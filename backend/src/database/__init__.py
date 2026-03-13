"""
Package database - Gestion de la persistance
"""

# === EXCEPTIONS (réexport depuis exceptions pour compatibilité) ===
from .exceptions import (
    DatabaseError,
    ConnectionError,
    MigrationError,
    ValidationError,
    IntegrityError,
    DatabaseErrorCodes,
    ERROR_MESSAGES,
    DEFAULT_DATABASE_CONFIG,
    DATABASE_SCHEMA_VERSION,
)

# === IMPORTS ===
from .database import Database, DatabaseConnection, create_database_manager
from .backup_restore import backup_database, restore_database, get_database_stats

# Alias pour les tests
create_database = create_database_manager

__version__ = "1.0.0"

__all__ = [
    "Database",
    "DatabaseConnection",
    "DatabaseError",
    "ConnectionError",
    "MigrationError",
    "ValidationError",
    "IntegrityError",
    "DatabaseErrorCodes",
    "ERROR_MESSAGES",
    "DEFAULT_DATABASE_CONFIG",
    "DATABASE_SCHEMA_VERSION",
    "create_database",
    "create_database_manager",
    "backup_database",
    "restore_database",
    "get_database_stats",
]
