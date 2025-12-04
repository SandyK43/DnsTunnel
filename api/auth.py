"""
API Authentication and Authorization
Supports API key-based authentication with role-based access control.
"""

import os
import secrets
from datetime import datetime
from typing import Optional
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from loguru import logger

from api.database import Base, get_db


# API Key security scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class APIKey(Base):
    """API key for authentication."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)  # Human-readable name
    role = Column(String, nullable=False, default="viewer")  # viewer, analyst, admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(String, nullable=True)
    notes = Column(String, nullable=True)


class Role:
    """Role-based access control."""
    VIEWER = "viewer"      # Read-only access (health, alerts, stats)
    ANALYST = "analyst"    # Analyst access (submit feedback, acknowledge alerts)
    ADMIN = "admin"        # Full access (all endpoints, manage API keys)


# Role permissions mapping
ROLE_PERMISSIONS = {
    Role.VIEWER: [
        "read:health",
        "read:alerts",
        "read:stats",
        "read:feedback",
        "read:thresholds"
    ],
    Role.ANALYST: [
        "read:health",
        "read:alerts",
        "read:stats",
        "read:feedback",
        "read:thresholds",
        "write:feedback",
        "write:acknowledge",
        "analyze:dns"
    ],
    Role.ADMIN: [
        "read:*",
        "write:*",
        "analyze:*",
        "manage:*"
    ]
}


def generate_api_key() -> str:
    """Generate a secure random API key."""
    return f"dns_{secrets.token_urlsafe(32)}"


def get_api_key(
    api_key: Optional[str] = Security(api_key_header),
    db: Session = None
) -> Optional[APIKey]:
    """
    Validate API key and return the APIKey object.

    Returns None if authentication is disabled or key is valid.
    Raises HTTPException if authentication is enabled and key is invalid.
    """
    # Check if authentication is enabled
    auth_enabled = os.getenv('API_AUTH_ENABLED', 'false').lower() == 'true'

    if not auth_enabled:
        # Authentication disabled - allow all requests
        return None

    # Authentication enabled - validate key
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide X-API-Key header."
        )

    # Query database for key
    if db is None:
        # Cannot validate without database - this shouldn't happen
        logger.error("Database session not provided to get_api_key")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable"
        )

    key_obj = db.query(APIKey).filter(
        APIKey.key == api_key,
        APIKey.is_active == True
    ).first()

    if not key_obj:
        logger.warning(f"Invalid API key attempt: {api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key"
        )

    # Update last used timestamp
    key_obj.last_used_at = datetime.utcnow()
    db.commit()

    return key_obj


def require_role(required_role: str):
    """
    Dependency to require specific role.

    Usage:
        @app.get("/admin")
        def admin_endpoint(api_key: APIKey = Depends(require_role(Role.ADMIN))):
            ...
    """
    def role_checker(
        api_key: Optional[str] = Security(api_key_header),
        db: Session = None
    ) -> Optional[APIKey]:
        # Get API key object
        key_obj = get_api_key(api_key, db)

        # If authentication disabled, allow
        if key_obj is None:
            return None

        # Check role hierarchy
        role_hierarchy = {
            Role.VIEWER: 0,
            Role.ANALYST: 1,
            Role.ADMIN: 2
        }

        user_role_level = role_hierarchy.get(key_obj.role, 0)
        required_role_level = role_hierarchy.get(required_role, 999)

        if user_role_level < required_role_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required role: {required_role}"
            )

        return key_obj

    return role_checker


def check_permission(api_key_obj: Optional[APIKey], permission: str) -> bool:
    """
    Check if API key has specific permission.

    Args:
        api_key_obj: APIKey object (None if auth disabled)
        permission: Permission string (e.g., "write:feedback")

    Returns:
        True if permission granted, False otherwise
    """
    # If authentication disabled, allow all
    if api_key_obj is None:
        return True

    # Get role permissions
    role_permissions = ROLE_PERMISSIONS.get(api_key_obj.role, [])

    # Check for exact match
    if permission in role_permissions:
        return True

    # Check for wildcard permissions
    permission_prefix = permission.split(':')[0]
    if f"{permission_prefix}:*" in role_permissions:
        return True

    # Check for admin wildcard
    if "*:*" in role_permissions or "read:*" in role_permissions or "write:*" in role_permissions:
        return True

    return False


def create_api_key(
    db: Session,
    name: str,
    role: str = Role.VIEWER,
    created_by: Optional[str] = None,
    notes: Optional[str] = None
) -> APIKey:
    """
    Create a new API key.

    Args:
        db: Database session
        name: Human-readable name for the key
        role: Role (viewer, analyst, admin)
        created_by: Username of creator
        notes: Optional notes

    Returns:
        APIKey object
    """
    # Validate role
    if role not in [Role.VIEWER, Role.ANALYST, Role.ADMIN]:
        raise ValueError(f"Invalid role: {role}")

    # Generate key
    key = generate_api_key()

    # Create database object
    api_key_obj = APIKey(
        key=key,
        name=name,
        role=role,
        created_by=created_by,
        notes=notes
    )

    db.add(api_key_obj)
    db.commit()
    db.refresh(api_key_obj)

    logger.info(f"Created API key: {name} ({role})")

    return api_key_obj


def revoke_api_key(db: Session, key_id: int) -> bool:
    """
    Revoke (deactivate) an API key.

    Args:
        db: Database session
        key_id: API key ID

    Returns:
        True if revoked, False if not found
    """
    key_obj = db.query(APIKey).filter(APIKey.id == key_id).first()

    if not key_obj:
        return False

    key_obj.is_active = False
    db.commit()

    logger.info(f"Revoked API key: {key_obj.name} (ID: {key_id})")

    return True


def list_api_keys(db: Session, include_inactive: bool = False):
    """
    List all API keys.

    Args:
        db: Database session
        include_inactive: Include inactive keys

    Returns:
        List of APIKey objects
    """
    query = db.query(APIKey)

    if not include_inactive:
        query = query.filter(APIKey.is_active == True)

    return query.order_by(APIKey.created_at.desc()).all()
