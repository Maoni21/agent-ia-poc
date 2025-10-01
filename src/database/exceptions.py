"""
Exceptions et constantes pour le module database
Ce fichier contient TOUTES les exceptions, codes d'erreur et constantes
pour éviter les imports circulaires.
"""

import datetime
from pathlib import Path

# === CHEMINS ET CONSTANTES GLOBALES ===

PROJECT_ROOT = Path(__file__).parent.parent.parent
LOG_PATH = PROJECT_ROOT / "logs"
DATA_PATH = PROJECT_ROOT / "data"

# Version du schéma de base de données
DATABASE_SCHEMA_VERSION = "1.0.0"


# === EXCEPTIONS ===

class DatabaseError(Exception):
    """Exception de base pour les erreurs de base de données"""
    def __init__(self, message: str, error_code: int = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.datetime.utcnow()


class ConnectionError(DatabaseError):
    """Erreur de connexion à la base de données"""
    pass


class MigrationError(DatabaseError):
    """Erreur lors des migrations de schéma"""
    pass


class ValidationError(DatabaseError):
    """Erreur de validation des données"""
    pass


class IntegrityError(DatabaseError):
    """Erreur d'intégrité des données"""
    pass


# === CODES D'ERREUR ===

class DatabaseErrorCodes:
    """Codes d'erreur pour les opérations de base de données"""

    # Erreurs de connexion (20000-20999)
    CONNECTION_FAILED = 20000
    CONNECTION_TIMEOUT = 20001
    DATABASE_LOCKED = 20002
    DATABASE_CORRUPT = 20003

    # Erreurs de schéma (21000-21999)
    SCHEMA_VERSION_MISMATCH = 21000
    MIGRATION_FAILED = 21001
    TABLE_NOT_EXISTS = 21002
    COLUMN_NOT_EXISTS = 21003

    # Erreurs de données (22000-22999)
    VALIDATION_FAILED = 22000
    CONSTRAINT_VIOLATION = 22001
    FOREIGN_KEY_VIOLATION = 22002
    UNIQUE_CONSTRAINT_VIOLATION = 22003

    # Erreurs d'opération (23000-23999)
    INSERT_FAILED = 23000
    UPDATE_FAILED = 23001
    DELETE_FAILED = 23002
    SELECT_FAILED = 23003


# === MESSAGES D'ERREUR ===

ERROR_MESSAGES = {
    DatabaseErrorCodes.CONNECTION_FAILED: "Impossible de se connecter à la base de données",
    DatabaseErrorCodes.CONNECTION_TIMEOUT: "Timeout de connexion à la base de données",
    DatabaseErrorCodes.DATABASE_LOCKED: "Base de données verrouillée",
    DatabaseErrorCodes.DATABASE_CORRUPT: "Base de données corrompue",

    DatabaseErrorCodes.SCHEMA_VERSION_MISMATCH: "Version du schéma incompatible",
    DatabaseErrorCodes.MIGRATION_FAILED: "Échec de la migration du schéma",
    DatabaseErrorCodes.TABLE_NOT_EXISTS: "Table inexistante",
    DatabaseErrorCodes.COLUMN_NOT_EXISTS: "Colonne inexistante",

    DatabaseErrorCodes.VALIDATION_FAILED: "Validation des données échouée",
    DatabaseErrorCodes.CONSTRAINT_VIOLATION: "Violation de contrainte",
    DatabaseErrorCodes.FOREIGN_KEY_VIOLATION: "Violation de clé étrangère",
    DatabaseErrorCodes.UNIQUE_CONSTRAINT_VIOLATION: "Violation de contrainte d'unicité",

    DatabaseErrorCodes.INSERT_FAILED: "Échec de l'insertion",
    DatabaseErrorCodes.UPDATE_FAILED: "Échec de la mise à jour",
    DatabaseErrorCodes.DELETE_FAILED: "Échec de la suppression",
    DatabaseErrorCodes.SELECT_FAILED: "Échec de la sélection",
}


# === CONFIGURATION PAR DÉFAUT ===

DEFAULT_DATABASE_CONFIG = {
    "database_path": "data/database/vulnerability_agent.db",
    "backup_enabled": True,
    "backup_retention_days": 30,
    "auto_vacuum": True,
    "foreign_keys": True,
    "journal_mode": "WAL",
    "synchronous": "NORMAL",
    "temp_store": "MEMORY",
    "cache_size": 10000,
    "connection_timeout": 30,
    "busy_timeout": 30000,
}
