"""SQLAlchemy Database Engine and Session Factory (SQLite locally, Postgres/Neon in prod)."""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Base declarative class for all Atlas AI ORM models."""


_ENGINE: Engine | None = None
_SESSION_FACTORY: sessionmaker[Session] | None = None


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for SQLite or Postgres (Neon)."""
    url = database_url or os.getenv("DATABASE_URL", "sqlite:///./atlas_ai.db")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://") and "+psycopg2" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

    if url.startswith("sqlite"):
        is_memory = ":memory:" in url
        connect_args = {"check_same_thread": False}
        if is_memory:
            engine = create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
                future=True,
            )
        else:
            engine = create_engine(
                url,
                connect_args=connect_args,
                future=True,
            )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        future=True,
    )


def init_db(database_url: str | None = None) -> Engine:
    """Initialize global engine, session factory, and create tables."""
    global _ENGINE, _SESSION_FACTORY
    _ENGINE = create_db_engine(database_url)
    _SESSION_FACTORY = sessionmaker(bind=_ENGINE, autocommit=False, autoflush=False, expire_on_commit=False)

    # Import models so metadata is populated before create_all
    from db import models  # noqa: F401

    Base.metadata.create_all(bind=_ENGINE)
    return _ENGINE


def get_engine() -> Engine:
    global _ENGINE
    if _ENGINE is None:
        return init_db()
    return _ENGINE


def get_session_factory() -> sessionmaker[Session]:
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        init_db()
    assert _SESSION_FACTORY is not None
    return _SESSION_FACTORY


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a DB session."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Transactional context manager for internal services."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
