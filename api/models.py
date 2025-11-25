"""
Database models for DNS tunneling detection system.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

Base = declarative_base()


# SQLAlchemy ORM Models

class DNSQuery(Base):
    """DNS query record with extracted features."""
    __tablename__ = "dns_queries"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    query = Column(String, nullable=False, index=True)
    client_ip = Column(String, nullable=False, index=True)
    qtype = Column(String)
    
    # Features
    len_q = Column(Integer)
    entropy = Column(Float)
    num_labels = Column(Integer)
    max_label_len = Column(Integer)
    digits_ratio = Column(Float)
    non_alnum_ratio = Column(Float)
    qps = Column(Float)
    unique_subdomains = Column(Integer)
    avg_entropy = Column(Float)
    max_entropy = Column(Float)
    
    # ML Results
    anomaly_score = Column(Float, index=True)
    severity = Column(String, index=True)
    
    # Additional metadata
    features_json = Column(JSON)
    
    __table_args__ = (
        Index('idx_timestamp_severity', 'timestamp', 'severity'),
        Index('idx_client_severity', 'client_ip', 'severity'),
    )


class Alert(Base):
    """Security alert record."""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String, nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False)
    
    domain = Column(String, nullable=False, index=True)
    client_ip = Column(String, nullable=False, index=True)
    
    # Alert status
    acknowledged = Column(Boolean, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String, nullable=True)
    
    # Response actions
    action_taken = Column(String, nullable=True)
    action_status = Column(String, nullable=True)
    
    # Notification tracking
    slack_sent = Column(Boolean, default=False)
    email_sent = Column(Boolean, default=False)
    jira_ticket = Column(String, nullable=True)
    
    # Full alert data
    alert_data = Column(JSON)
    
    __table_args__ = (
        Index('idx_severity_timestamp', 'severity', 'timestamp'),
    )


class ResponseAction(Base):
    """Response action execution record."""
    __tablename__ = "response_actions"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_id = Column(Integer, nullable=False, index=True)
    
    action_type = Column(String, nullable=False)  # block_ip, quarantine, etc.
    target = Column(String, nullable=False)  # IP or domain
    status = Column(String, nullable=False)  # pending, success, failed
    
    # Approval workflow
    requires_approval = Column(Boolean, default=False)
    approved = Column(Boolean, default=False)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(String, nullable=True)
    
    # Execution details
    executed_at = Column(DateTime, nullable=True)
    duration_minutes = Column(Integer, nullable=True)
    error_message = Column(String, nullable=True)
    
    details = Column(JSON)


# Pydantic Models for API

class DNSQueryRequest(BaseModel):
    """Request model for DNS query analysis."""
    query: str = Field(..., description="DNS query domain name")
    client_ip: str = Field(..., description="Source IP address")
    timestamp: Optional[datetime] = Field(None, description="Query timestamp")
    qtype: Optional[str] = Field("A", description="Query type")
    
    class Config:
        json_schema_extra = {
            "example": {
                "query": "www.example.com",
                "client_ip": "192.168.1.100",
                "qtype": "A"
            }
        }


class DNSQueryResponse(BaseModel):
    """Response model for DNS query analysis."""
    query: str
    client_ip: str
    timestamp: datetime
    anomaly_score: float
    severity: str
    features: dict
    
    class Config:
        json_schema_extra = {
            "example": {
                "query": "suspicious-subdomain.evil.com",
                "client_ip": "192.168.1.100",
                "timestamp": "2025-11-25T10:30:45Z",
                "anomaly_score": 0.87,
                "severity": "HIGH",
                "features": {
                    "entropy": 4.2,
                    "len_q": 67,
                    "qps": 15.3
                }
            }
        }


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis."""
    queries: list[DNSQueryRequest] = Field(..., description="List of DNS queries")
    
    class Config:
        json_schema_extra = {
            "example": {
                "queries": [
                    {"query": "www.google.com", "client_ip": "192.168.1.100"},
                    {"query": "suspicious.evil.com", "client_ip": "192.168.1.101"}
                ]
            }
        }


class AlertResponse(BaseModel):
    """Response model for alert."""
    id: int
    timestamp: datetime
    severity: str
    anomaly_score: float
    domain: str
    client_ip: str
    acknowledged: bool
    action_taken: Optional[str]
    action_status: Optional[str]
    
    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    """Response model for list of alerts."""
    total: int
    page: int
    page_size: int
    alerts: list[AlertResponse]


class StatsResponse(BaseModel):
    """System statistics response."""
    total_queries: int
    total_alerts: int
    alerts_by_severity: dict
    top_suspicious_domains: list[dict]
    top_clients: list[dict]
    detection_rate: float
    timestamp: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_queries": 15420,
                "total_alerts": 23,
                "alerts_by_severity": {
                    "HIGH": 5,
                    "SUSPICIOUS": 18
                },
                "top_suspicious_domains": [
                    {"domain": "evil.com", "count": 10}
                ],
                "top_clients": [
                    {"client_ip": "192.168.1.50", "count": 8}
                ],
                "detection_rate": 0.0015,
                "timestamp": "2025-11-25T10:30:45Z"
            }
        }


class ResponseActionRequest(BaseModel):
    """Request model for manual response action."""
    alert_id: int
    action_type: str = Field(..., description="block_ip, quarantine_host, or block_domain")
    duration_minutes: Optional[int] = Field(60, description="Action duration in minutes")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": 123,
                "action_type": "block_ip",
                "duration_minutes": 60
            }
        }


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    model_loaded: bool
    database_connected: bool
    timestamp: datetime

