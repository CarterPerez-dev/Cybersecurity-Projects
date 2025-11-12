"""
Database configuration and session management using SQLAlchemy.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from config import settings

# Database engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping = True,
    echo = settings.DEBUG,
)

# Session factory
SessionLocal = sessionmaker(
    autocommit = False,
    autoflush = False,
    bind = engine
)

# Base class
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
