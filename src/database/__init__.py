"""
Package database pour l'Agent IA de Cybersécurité
"""

# Importer TOUT depuis exceptions.py d'abord
from .exceptions import (
    DatabaseError,
    ConnectionError,
    MigrationError,
    ValidationError,
    IntegrityError,
    DatabaseErrorCodes,
    DEFAULT_DATABASE_CONFIG,
    ERROR_MESSAGES,
)

# Maintenant Database peut importer sans problème
from .database import Database

# Version du package
__version__ = "1.0.0"

# Exports complets
__all__ = [
    "Database",
    "DatabaseError",
    "ConnectionError",
    "MigrationError",
    "ValidationError",
    "IntegrityError",
    "DatabaseErrorCodes",
    "DEFAULT_DATABASE_CONFIG",
    "ERROR_MESSAGES",
]
