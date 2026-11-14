"""The findings store (T2.3): the PostgreSQL tables of docs/database.md."""

from app.store.migrate import MigrationError, migrate

__all__ = ["MigrationError", "migrate"]
