"""Database Migrations Package for Atlas AI."""

from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.engine import Engine

from db.database import Base
from db import models  # noqa: F401


MIGRATION_VERSION = "0001_phase0_foundation"


def run_migrations(engine: Engine) -> dict:
    """Apply idempotent schema creation and return verified table list."""
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    tables = sorted(inspector.get_table_names())
    return {
        "migration_version": MIGRATION_VERSION,
        "tables": tables,
    }
