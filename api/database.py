"""
Database configuration and session management.
Supports both SQLite and PostgreSQL.
"""

import os
from pathlib import Path
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from loguru import logger

from api.models import Base


def get_database_url():
    """
    Get database URL from environment or config.
    Supports both SQLite and PostgreSQL.
    """
    # Check if DATABASE_URL is explicitly set
    if os.getenv('DATABASE_URL'):
        return os.getenv('DATABASE_URL')

    # Determine database type
    db_type = os.getenv('DATABASE_TYPE', 'sqlite').lower()

    if db_type == 'sqlite':
        # SQLite configuration
        db_path = os.getenv('SQLITE_PATH', 'data/dns_tunnel.db')

        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        return f'sqlite:///{db_path}'

    elif db_type == 'postgresql':
        # PostgreSQL configuration
        host = os.getenv('POSTGRES_HOST', 'localhost')
        port = os.getenv('POSTGRES_PORT', '5432')
        user = os.getenv('POSTGRES_USER', 'dnsadmin')
        password = os.getenv('POSTGRES_PASSWORD', 'changeme123')
        database = os.getenv('POSTGRES_DB', 'dns_tunnel_db')

        return f'postgresql://{user}:{password}@{host}:{port}/{database}'

    else:
        raise ValueError(f"Unsupported database type: {db_type}")


# Get database URL
DATABASE_URL = get_database_url()
logger.info(f"Database type: {DATABASE_URL.split(':')[0]}")

# Create engine with appropriate settings
if 'sqlite' in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
else:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        echo=False
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def get_db() -> Session:
    """
    Get database session for FastAPI dependency injection.
    
    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context():
    """
    Get database session as context manager.
    
    Usage:
        with get_db_context() as db:
            ...
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def test_connection() -> bool:
    """Test database connection."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("Database connection successful")
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False


def reset_database():
    """Drop all tables and recreate (DANGEROUS - use only for development/testing)."""
    logger.warning("Dropping all database tables...")
    Base.metadata.drop_all(bind=engine)
    logger.info("Recreating all database tables...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database reset complete")

