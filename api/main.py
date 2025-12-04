"""
FastAPI Main Application
DNS Tunneling Detection Microservice
"""

import os
from datetime import datetime, timedelta
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from loguru import logger

from api.models import (
    DNSQuery, Alert, ResponseAction as ResponseActionModel, AlertFeedback,
    DNSQueryRequest, DNSQueryResponse, BatchAnalysisRequest,
    AlertResponse, AlertListResponse, StatsResponse,
    ResponseActionRequest, HealthResponse,
    AlertFeedbackRequest, AlertFeedbackResponse, AdaptiveThresholdStatus
)
from api.database import get_db, init_db, test_connection
from agents.feature_extractor import FeatureExtractor
from agents.scorer import AnomalyScorer, Severity
from agents.alerting import AlertingAgent
from agents.response import ResponseAgent, ResponseAction


# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    # Startup
    logger.info("Starting DNS Tunneling Detection Service")

    # Initialize database
    init_db()

    # Check if adaptive thresholds are enabled
    adaptive_enabled = os.getenv('ADAPTIVE_THRESHOLDS_ENABLED', 'true').lower() == 'true'

    if adaptive_enabled:
        from agents.adaptive_thresholds import AdaptiveThresholdManager

        # Initialize adaptive threshold manager
        app.state.adaptive_threshold_manager = AdaptiveThresholdManager(
            initial_suspicious=float(os.getenv('ANOMALY_THRESHOLD_SUSPICIOUS', '0.70')),
            initial_high=float(os.getenv('ANOMALY_THRESHOLD_HIGH', '0.85')),
            target_fp_rate=float(os.getenv('TARGET_FP_RATE', '0.03')),
            max_fp_rate=float(os.getenv('MAX_FP_RATE', '0.10')),
            adjustment_increment=float(os.getenv('THRESHOLD_ADJUSTMENT_INCREMENT', '0.02')),
            evaluation_window_hours=int(os.getenv('EVALUATION_WINDOW_HOURS', '24')),
            max_adjustment_frequency_hours=int(os.getenv('MAX_ADJUSTMENT_FREQUENCY_HOURS', '6'))
        )

        logger.info("✓ Adaptive threshold manager initialized")

        # Start continuous monitoring in background
        import asyncio
        app.state.threshold_monitoring_task = asyncio.create_task(
            app.state.adaptive_threshold_manager.run_continuous_monitoring(
                check_interval_minutes=int(os.getenv('THRESHOLD_CHECK_INTERVAL_MINUTES', '60'))
            )
        )
    else:
        app.state.adaptive_threshold_manager = None
        logger.info("Adaptive thresholds disabled - using static thresholds")

    # Load ML model
    model_path = os.getenv('MODEL_PATH', './models/isolation_forest.pkl')
    app.state.scorer = AnomalyScorer(
        model_path=model_path,
        threshold_suspicious=float(os.getenv('ANOMALY_THRESHOLD_SUSPICIOUS', '0.70')),
        threshold_high=float(os.getenv('ANOMALY_THRESHOLD_HIGH', '0.85'))
    )

    # Initialize agents
    app.state.feature_extractor = FeatureExtractor(
        window_size=int(os.getenv('FEATURE_WINDOW_SIZE', '60'))
    )

    app.state.alerting_agent = AlertingAgent(
        throttle_seconds=int(os.getenv('ALERT_THROTTLE_SECONDS', '300')),
        min_score_to_alert=float(os.getenv('ANOMALY_THRESHOLD_SUSPICIOUS', '0.70'))
    )

    app.state.response_agent = ResponseAgent(
        auto_response_enabled=os.getenv('ENABLE_AUTO_RESPONSE', 'false').lower() == 'true',
        auto_block_threshold=float(os.getenv('ANOMALY_THRESHOLD_HIGH', '0.85')),
        require_manual_approval=True
    )

    logger.info("Service initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down DNS Tunneling Detection Service")

    # Cancel threshold monitoring if running
    if adaptive_enabled and hasattr(app.state, 'threshold_monitoring_task'):
        app.state.threshold_monitoring_task.cancel()
        try:
            await app.state.threshold_monitoring_task
        except asyncio.CancelledError:
            pass


# Create FastAPI app
app = FastAPI(
    title="DNS Tunneling Detection Service",
    description="Production-grade microservice for detecting DNS tunneling attacks using ML",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Routes

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "service": "DNS Tunneling Detection",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    db_connected = test_connection()
    model_loaded = app.state.scorer.model is not None
    
    status = "healthy" if db_connected and model_loaded else "degraded"
    
    return HealthResponse(
        status=status,
        version="1.0.0",
        model_loaded=model_loaded,
        database_connected=db_connected,
        timestamp=datetime.utcnow()
    )


@app.post("/api/v1/dns/analyze", response_model=DNSQueryResponse, tags=["Analysis"])
async def analyze_query(
    request: DNSQueryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Analyze a single DNS query for tunneling behavior.
    
    This endpoint:
    1. Extracts features from the query
    2. Scores it using the ML model
    3. Stores the result in the database
    4. Triggers alerts if suspicious
    """
    try:
        # Extract features
        features = app.state.feature_extractor.extract_features(
            query=request.query,
            client_ip=request.client_ip,
            timestamp=request.timestamp or datetime.utcnow()
        )

        # Get current thresholds (adaptive or static)
        if app.state.adaptive_threshold_manager:
            threshold_suspicious, threshold_high = app.state.adaptive_threshold_manager.get_current_thresholds()
            # Update scorer thresholds dynamically
            app.state.scorer.threshold_suspicious = threshold_suspicious
            app.state.scorer.threshold_high = threshold_high

        # Score query
        anomaly_score, severity = app.state.scorer.score(features)

        # Record score in adaptive threshold manager
        if app.state.adaptive_threshold_manager:
            app.state.adaptive_threshold_manager.record_score(
                score=anomaly_score,
                severity=severity.value,
                timestamp=request.timestamp or datetime.utcnow()
            )
        
        # Store in database
        db_query = DNSQuery(
            timestamp=request.timestamp or datetime.utcnow(),
            query=request.query,
            client_ip=request.client_ip,
            qtype=request.qtype,
            **features,
            anomaly_score=anomaly_score,
            severity=severity.value,
            features_json=features
        )
        db.add(db_query)
        db.commit()
        db.refresh(db_query)
        
        # If suspicious, handle alert in background
        if severity in [Severity.SUSPICIOUS, Severity.HIGH]:
            background_tasks.add_task(
                handle_alert,
                query_id=db_query.id,
                severity=severity.value,
                anomaly_score=anomaly_score,
                domain=request.query,
                client_ip=request.client_ip,
                features=features,
                timestamp=db_query.timestamp
            )
        
        return DNSQueryResponse(
            query=request.query,
            client_ip=request.client_ip,
            timestamp=db_query.timestamp,
            anomaly_score=anomaly_score,
            severity=severity.value,
            features=features
        )
        
    except Exception as e:
        logger.error(f"Error analyzing query: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/dns/batch", tags=["Analysis"])
async def analyze_batch(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Analyze a batch of DNS queries."""
    results = []
    
    for query_req in request.queries:
        try:
            # Extract features
            features = app.state.feature_extractor.extract_features(
                query=query_req.query,
                client_ip=query_req.client_ip,
                timestamp=query_req.timestamp or datetime.utcnow()
            )
            
            # Score query
            anomaly_score, severity = app.state.scorer.score(features)
            
            # Store in database
            db_query = DNSQuery(
                timestamp=query_req.timestamp or datetime.utcnow(),
                query=query_req.query,
                client_ip=query_req.client_ip,
                qtype=query_req.qtype,
                **features,
                anomaly_score=anomaly_score,
                severity=severity.value,
                features_json=features
            )
            db.add(db_query)
            
            # Trigger alert if needed
            if severity in [Severity.SUSPICIOUS, Severity.HIGH]:
                background_tasks.add_task(
                    handle_alert,
                    query_id=db_query.id,
                    severity=severity.value,
                    anomaly_score=anomaly_score,
                    domain=query_req.query,
                    client_ip=query_req.client_ip,
                    features=features,
                    timestamp=db_query.timestamp
                )
            
            results.append({
                "query": query_req.query,
                "anomaly_score": anomaly_score,
                "severity": severity.value
            })
            
        except Exception as e:
            logger.error(f"Error processing query {query_req.query}: {e}")
            results.append({
                "query": query_req.query,
                "error": str(e)
            })
    
    db.commit()
    
    return {
        "total": len(request.queries),
        "processed": len(results),
        "results": results
    }


@app.get("/api/v1/alerts", response_model=AlertListResponse, tags=["Alerts"])
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """List alerts with pagination and filtering."""
    query = db.query(Alert)
    
    # Apply filters
    if severity:
        query = query.filter(Alert.severity == severity)
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    
    # Get total count
    total = query.count()
    
    # Paginate
    offset = (page - 1) * page_size
    alerts = query.order_by(desc(Alert.timestamp)).offset(offset).limit(page_size).all()
    
    return AlertListResponse(
        total=total,
        page=page,
        page_size=page_size,
        alerts=[AlertResponse.from_orm(alert) for alert in alerts]
    )


@app.get("/api/v1/alerts/{alert_id}", response_model=AlertResponse, tags=["Alerts"])
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get specific alert details."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse.from_orm(alert)


@app.post("/api/v1/alerts/{alert_id}/acknowledge", tags=["Alerts"])
async def acknowledge_alert(
    alert_id: int,
    acknowledged_by: str = "api_user",
    db: Session = Depends(get_db)
):
    """Acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.acknowledged = True
    alert.acknowledged_at = datetime.utcnow()
    alert.acknowledged_by = acknowledged_by
    
    db.commit()
    
    return {"status": "success", "alert_id": alert_id}


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Statistics"])
async def get_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get system statistics."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    # Total queries
    total_queries = db.query(func.count(DNSQuery.id)).filter(
        DNSQuery.timestamp >= cutoff
    ).scalar()
    
    # Total alerts
    total_alerts = db.query(func.count(Alert.id)).filter(
        Alert.timestamp >= cutoff
    ).scalar()
    
    # Alerts by severity
    severity_counts = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).filter(
        Alert.timestamp >= cutoff
    ).group_by(Alert.severity).all()
    
    alerts_by_severity = {sev: count for sev, count in severity_counts}
    
    # Top suspicious domains
    top_domains = db.query(
        Alert.domain,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.timestamp >= cutoff
    ).group_by(Alert.domain).order_by(desc('count')).limit(10).all()
    
    top_suspicious_domains = [
        {"domain": domain, "count": count}
        for domain, count in top_domains
    ]
    
    # Top clients
    top_clients_data = db.query(
        Alert.client_ip,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.timestamp >= cutoff
    ).group_by(Alert.client_ip).order_by(desc('count')).limit(10).all()
    
    top_clients = [
        {"client_ip": ip, "count": count}
        for ip, count in top_clients_data
    ]
    
    # Detection rate
    detection_rate = total_alerts / total_queries if total_queries > 0 else 0.0
    
    return StatsResponse(
        total_queries=total_queries or 0,
        total_alerts=total_alerts or 0,
        alerts_by_severity=alerts_by_severity,
        top_suspicious_domains=top_suspicious_domains,
        top_clients=top_clients,
        detection_rate=detection_rate,
        timestamp=datetime.utcnow()
    )


@app.post("/api/v1/response/block", tags=["Response"])
async def manual_block(
    request: ResponseActionRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Manually trigger a response action."""
    # Get alert
    alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Execute action in background
    background_tasks.add_task(
        execute_response_action,
        alert_id=request.alert_id,
        action_type=request.action_type,
        duration_minutes=request.duration_minutes,
        client_ip=alert.client_ip,
        domain=alert.domain
    )
    
    return {
        "status": "accepted",
        "alert_id": request.alert_id,
        "action": request.action_type
    }


@app.get("/api/v1/response/pending", tags=["Response"])
async def get_pending_approvals():
    """Get pending response actions requiring approval."""
    pending = app.state.response_agent.get_pending_approvals()
    return {"pending_approvals": pending}


@app.post("/api/v1/response/approve/{approval_id}", tags=["Response"])
async def approve_response(approval_id: int):
    """Approve a pending response action."""
    success = app.state.response_agent.approve_action(approval_id)

    if not success:
        raise HTTPException(status_code=404, detail="Approval not found")

    return {"status": "approved", "approval_id": approval_id}


# Adaptive Thresholds & Feedback Endpoints

@app.post("/api/v1/feedback", response_model=AlertFeedbackResponse, tags=["Adaptive Thresholds"])
async def submit_alert_feedback(
    feedback: AlertFeedbackRequest,
    db: Session = Depends(get_db)
):
    """
    Submit analyst feedback on an alert.

    This feedback is used to adjust detection thresholds adaptively:
    - False positives cause thresholds to increase (less sensitive)
    - True positives cause thresholds to decrease (more sensitive)
    """
    # Get the alert
    alert = db.query(Alert).filter(Alert.id == feedback.alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Store feedback in database
    db_feedback = AlertFeedback(
        alert_id=feedback.alert_id,
        is_false_positive=feedback.is_false_positive,
        analyst=feedback.analyst,
        notes=feedback.notes,
        anomaly_score=alert.anomaly_score,
        severity=alert.severity,
        domain=alert.domain,
        client_ip=alert.client_ip
    )
    db.add(db_feedback)
    db.commit()
    db.refresh(db_feedback)

    # Record in adaptive threshold manager
    if hasattr(app.state, 'adaptive_threshold_manager'):
        app.state.adaptive_threshold_manager.add_feedback(
            alert_id=feedback.alert_id,
            is_false_positive=feedback.is_false_positive,
            score=alert.anomaly_score,
            analyst=feedback.analyst,
            notes=feedback.notes
        )

        logger.info(
            f"Feedback recorded: Alert {feedback.alert_id} marked as "
            f"{'FALSE POSITIVE' if feedback.is_false_positive else 'TRUE POSITIVE'} "
            f"by {feedback.analyst}"
        )

    return AlertFeedbackResponse.from_orm(db_feedback)


@app.get("/api/v1/feedback", tags=["Adaptive Thresholds"])
async def list_feedback(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    is_false_positive: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """List analyst feedback with pagination and filtering."""
    query = db.query(AlertFeedback)

    # Apply filters
    if is_false_positive is not None:
        query = query.filter(AlertFeedback.is_false_positive == is_false_positive)

    # Get total count
    total = query.count()

    # Paginate
    offset = (page - 1) * page_size
    feedback_list = query.order_by(desc(AlertFeedback.timestamp)).offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "feedback": [AlertFeedbackResponse.from_orm(f) for f in feedback_list]
    }


@app.get("/api/v1/thresholds/status", response_model=AdaptiveThresholdStatus, tags=["Adaptive Thresholds"])
async def get_threshold_status():
    """
    Get current adaptive threshold status and performance metrics.

    Returns:
    - Current threshold values
    - Performance metrics (FP rate, alert volume, etc.)
    - Recent threshold adjustments
    - Feedback summary
    """
    if not hasattr(app.state, 'adaptive_threshold_manager'):
        raise HTTPException(
            status_code=503,
            detail="Adaptive thresholds not enabled"
        )

    stats = app.state.adaptive_threshold_manager.get_statistics()
    return AdaptiveThresholdStatus(**stats)


@app.post("/api/v1/thresholds/adjust", tags=["Adaptive Thresholds"])
async def trigger_threshold_adjustment():
    """
    Manually trigger threshold adjustment evaluation.

    Normally thresholds adjust automatically every few hours.
    This endpoint allows manual triggering for testing or immediate adjustment.
    """
    if not hasattr(app.state, 'adaptive_threshold_manager'):
        raise HTTPException(
            status_code=503,
            detail="Adaptive thresholds not enabled"
        )

    adjusted = await app.state.adaptive_threshold_manager.adjust_thresholds()

    if adjusted:
        thresholds = app.state.adaptive_threshold_manager.get_current_thresholds()
        return {
            "status": "adjusted",
            "new_thresholds": {
                "suspicious": thresholds[0],
                "high": thresholds[1]
            }
        }
    else:
        return {
            "status": "no_adjustment_needed",
            "message": "Current thresholds are optimal"
        }


@app.get("/api/v1/thresholds/history", tags=["Adaptive Thresholds"])
async def get_threshold_history():
    """Get history of threshold adjustments."""
    if not hasattr(app.state, 'adaptive_threshold_manager'):
        raise HTTPException(
            status_code=503,
            detail="Adaptive thresholds not enabled"
        )

    stats = app.state.adaptive_threshold_manager.get_statistics()
    return {
        "adjustment_history": stats['recent_changes'],
        "total_adjustments": stats['adjustment_stats']['total_adjustments'],
        "increases": stats['adjustment_stats']['increases'],
        "decreases": stats['adjustment_stats']['decreases']
    }


# Background tasks

async def handle_alert(
    query_id: int,
    severity: str,
    anomaly_score: float,
    domain: str,
    client_ip: str,
    features: dict,
    timestamp: datetime
):
    """Handle alert generation and notification."""
    from api.database import get_db_context
    
    # Prepare alert data
    alert_data = {
        'severity': severity,
        'anomaly_score': anomaly_score,
        'domain': domain,
        'client_ip': client_ip,
        'timestamp': timestamp,
        'features': features
    }
    
    # Send alerts
    alert_results = await app.state.alerting_agent.send_alert(alert_data)
    
    # Store alert in database
    with get_db_context() as db:
        db_alert = Alert(
            timestamp=timestamp,
            severity=severity,
            anomaly_score=anomaly_score,
            domain=domain,
            client_ip=client_ip,
            slack_sent=alert_results.get('slack', False),
            email_sent=alert_results.get('email', False),
            jira_ticket=alert_results.get('jira_ticket'),
            alert_data=alert_data
        )
        db.add(db_alert)
        db.commit()
        db.refresh(db_alert)
        
        # Trigger response agent
        response = await app.state.response_agent.handle_alert(alert_data)
        
        # Update alert with response info
        db_alert.action_taken = response.get('action')
        db_alert.action_status = response.get('status')
        db.commit()


async def execute_response_action(
    alert_id: int,
    action_type: str,
    duration_minutes: int,
    client_ip: str,
    domain: str
):
    """Execute a response action."""
    from api.database import get_db_context
    
    logger.info(f"Executing {action_type} for alert {alert_id}")
    
    success = False
    error_msg = None
    
    try:
        if action_type == "block_ip":
            success = await app.state.response_agent.block_ip(
                client_ip, domain, duration_minutes
            )
        elif action_type == "quarantine_host":
            success = await app.state.response_agent.quarantine_host(
                client_ip, duration_minutes
            )
        elif action_type == "block_domain":
            success = await app.state.response_agent.block_domain(domain)
    except Exception as e:
        logger.error(f"Failed to execute {action_type}: {e}")
        error_msg = str(e)
    
    # Record action
    with get_db_context() as db:
        action_record = ResponseActionModel(
            alert_id=alert_id,
            action_type=action_type,
            target=client_ip if "ip" in action_type else domain,
            status="success" if success else "failed",
            executed_at=datetime.utcnow(),
            duration_minutes=duration_minutes,
            error_message=error_msg
        )
        db.add(action_record)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

