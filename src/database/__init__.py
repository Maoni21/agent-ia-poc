"""
Package database pour l'Agent IA de Cybersécurité

Ce package gère toute la persistance des données de l'application :
- Modèles de données SQLite
- Gestionnaire de base de données
- Migrations et schémas
- Opérations CRUD pour tous les objets métier

Architecture de données :
    Database (gestionnaire principal)
    ├── Models (définitions des tables)
    ├── Migrations (évolution du schéma)
    └── Operations (CRUD spécialisées)

Tables principales :
- scans : Historique des scans de vulnérabilités
- vulnerabilities : Détails des vulnérabilités détectées
- analyses : Résultats d'analyse IA
- scripts : Scripts de correction générés
- workflows : Historique des workflows
- users : Gestion des utilisateurs (optionnel)
"""

from .database import Database, DatabaseConnection
from .models import (
    # Tables principales
    ScanModel,
    VulnerabilityModel,
    AnalysisModel,
    ScriptModel,
    WorkflowModel,

    # Tables de liaison
    ScanVulnerabilityModel,
    AnalysisVulnerabilityModel,

    # Métadonnées
    BaseModel,
    DatabaseSchema
)

# Version du package database
__version__ = "1.0.0"

# Export des éléments principaux
__all__ = [
    # Gestionnaire principal
    "Database",
    "DatabaseConnection",

    # Modèles de données
    "ScanModel",
    "VulnerabilityModel",
    "AnalysisModel",
    "ScriptModel",
    "WorkflowModel",
    "ScanVulnerabilityModel",
    "AnalysisVulnerabilityModel",

    # Classes de base
    "BaseModel",
    "DatabaseSchema",

    # Exceptions
    "DatabaseError",
    "ConnectionError",
    "MigrationError",
    "ValidationError",

    # Fonctions utilitaires
    "create_database",
    "get_database_info",
    "validate_database_config",
    "backup_database",
    "restore_database",
]


# === EXCEPTIONS PERSONNALISÉES ===

class DatabaseError(Exception):
    """Exception de base pour les erreurs de base de données"""

    def __init__(self, message: str, error_code: int = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = __import__('datetime').datetime.utcnow()


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


# === CONSTANTES ET CONFIGURATION ===

# Version du schéma de base de données
DATABASE_SCHEMA_VERSION = "1.0.0"

# Configuration par défaut
DEFAULT_DATABASE_CONFIG = {
    "database_path": "data/database/vulnerability_agent.db",
    "backup_enabled": True,
    "backup_retention_days": 30,
    "auto_vacuum": True,
    "foreign_keys": True,
    "journal_mode": "WAL",  # Write-Ahead Logging pour de meilleures performances
    "synchronous": "NORMAL",
    "temp_store": "MEMORY",
    "cache_size": 10000,  # 10MB de cache
    "connection_timeout": 30,
    "busy_timeout": 30000,  # 30 secondes
}


# Codes d'erreur spécifiques à la base de données
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


# Messages d'erreur correspondants
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


# === FONCTIONS UTILITAIRES ===

def get_database_info() -> dict:
    """
    Retourne les informations sur le package database

    Returns:
        dict: Informations complètes du package
    """
    return {
        "package": "database",
        "version": __version__,
        "schema_version": DATABASE_SCHEMA_VERSION,
        "supported_engines": ["SQLite"],
        "features": [
            "CRUD operations",
            "Schema migrations",
            "Data validation",
            "Backup/Restore",
            "Connection pooling",
            "Foreign key constraints"
        ],
        "models": [
            "ScanModel",
            "VulnerabilityModel",
            "AnalysisModel",
            "ScriptModel",
            "WorkflowModel"
        ]
    }


def validate_database_config(config: dict) -> bool:
    """
    Valide la configuration de la base de données

    Args:
        config: Configuration à valider

    Returns:
        bool: True si la configuration est valide

    Raises:
        ValidationError: Si la configuration est invalide
    """
    required_fields = ["database_path"]

    for field in required_fields:
        if field not in config:
            raise ValidationError(f"Champ obligatoire manquant: {field}")

    # Valider le chemin de la base de données
    db_path = config["database_path"]
    if not isinstance(db_path, str) or not db_path:
        raise ValidationError("Chemin de base de données invalide")

    # Valider les paramètres numériques
    numeric_fields = {
        "backup_retention_days": (1, 365),
        "cache_size": (1000, 100000),
        "connection_timeout": (5, 300),
        "busy_timeout": (1000, 60000)
    }

    for field, (min_val, max_val) in numeric_fields.items():
        if field in config:
            value = config[field]
            if not isinstance(value, int) or value < min_val or value > max_val:
                raise ValidationError(
                    f"Valeur invalide pour {field}: {value} "
                    f"(doit être entre {min_val} et {max_val})"
                )

    # Valider les paramètres booléens
    boolean_fields = ["backup_enabled", "auto_vacuum", "foreign_keys"]
    for field in boolean_fields:
        if field in config and not isinstance(config[field], bool):
            raise ValidationError(f"Valeur booléenne attendue pour {field}")

    # Valider les énumérations
    valid_journal_modes = ["DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"]
    if "journal_mode" in config:
        if config["journal_mode"] not in valid_journal_modes:
            raise ValidationError(f"Mode journal invalide. Valides: {valid_journal_modes}")

    valid_synchronous = ["OFF", "NORMAL", "FULL", "EXTRA"]
    if "synchronous" in config:
        if config["synchronous"] not in valid_synchronous:
            raise ValidationError(f"Mode synchronous invalide. Valides: {valid_synchronous}")

    return True


def create_database(config: dict = None) -> Database:
    """
    Factory pour créer une instance de base de données

    Args:
        config: Configuration personnalisée (optionnel)

    Returns:
        Database: Instance configurée de la base de données

    Raises:
        DatabaseError: Si la création échoue
    """
    try:
        # Utiliser la configuration par défaut si non fournie
        if config is None:
            config = DEFAULT_DATABASE_CONFIG.copy()
        else:
            # Merger avec la configuration par défaut
            merged_config = DEFAULT_DATABASE_CONFIG.copy()
            merged_config.update(config)
            config = merged_config

        # Valider la configuration
        validate_database_config(config)

        # Créer l'instance
        database = Database(config)

        return database

    except Exception as e:
        raise DatabaseError(
            f"Erreur lors de la création de la base de données: {str(e)}",
            DatabaseErrorCodes.CONNECTION_FAILED
        )


def backup_database(
        database_path: str,
        backup_path: str = None,
        compress: bool = True
) -> str:
    """
    Sauvegarde une base de données

    Args:
        database_path: Chemin vers la base de données
        backup_path: Chemin de sauvegarde (optionnel)
        compress: Compresser la sauvegarde

    Returns:
        str: Chemin du fichier de sauvegarde créé

    Raises:
        DatabaseError: Si la sauvegarde échoue
    """
    import shutil
    import gzip
    from pathlib import Path
    from datetime import datetime

    try:
        db_path = Path(database_path)
        if not db_path.exists():
            raise DatabaseError(f"Base de données non trouvée: {database_path}")

        # Générer le nom de sauvegarde si non fourni
        if backup_path is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_dir = db_path.parent / "backups"
            backup_dir.mkdir(exist_ok=True)
            backup_path = backup_dir / f"{db_path.stem}_backup_{timestamp}.db"

        backup_path = Path(backup_path)

        # Copier la base de données
        if compress:
            # Compression avec gzip
            with open(db_path, 'rb') as f_in:
                with gzip.open(f"{backup_path}.gz", 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            final_path = f"{backup_path}.gz"
        else:
            # Copie simple
            shutil.copy2(db_path, backup_path)
            final_path = str(backup_path)

        return final_path

    except Exception as e:
        raise DatabaseError(f"Erreur lors de la sauvegarde: {str(e)}")


def restore_database(
        backup_path: str,
        target_path: str,
        verify_integrity: bool = True
) -> bool:
    """
    Restaure une base de données depuis une sauvegarde

    Args:
        backup_path: Chemin vers la sauvegarde
        target_path: Chemin de destination
        verify_integrity: Vérifier l'intégrité après restauration

    Returns:
        bool: True si la restauration a réussi

    Raises:
        DatabaseError: Si la restauration échoue
    """
    import shutil
    import gzip
    import sqlite3
    from pathlib import Path

    try:
        backup_path = Path(backup_path)
        target_path = Path(target_path)

        if not backup_path.exists():
            raise DatabaseError(f"Sauvegarde non trouvée: {backup_path}")

        # Créer le répertoire de destination
        target_path.parent.mkdir(parents=True, exist_ok=True)

        # Restaurer selon le type de fichier
        if backup_path.suffix == '.gz':
            # Décompression
            with gzip.open(backup_path, 'rb') as f_in:
                with open(target_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        else:
            # Copie simple
            shutil.copy2(backup_path, target_path)

        # Vérifier l'intégrité si demandé
        if verify_integrity:
            try:
                conn = sqlite3.connect(str(target_path))
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                conn.close()

                if result[0] != "ok":
                    raise DatabaseError("Vérification d'intégrité échouée")

            except sqlite3.Error as e:
                raise DatabaseError(f"Erreur de vérification: {str(e)}")

        return True

    except Exception as e:
        raise DatabaseError(f"Erreur lors de la restauration: {str(e)}")


def get_database_stats(database_path: str) -> dict:
    """
    Retourne les statistiques d'une base de données

    Args:
        database_path: Chemin vers la base de données

    Returns:
        dict: Statistiques de la base de données
    """
    import sqlite3
    import os
    from pathlib import Path

    try:
        db_path = Path(database_path)
        if not db_path.exists():
            return {"error": "Base de données non trouvée"}

        # Informations sur le fichier
        file_stats = db_path.stat()
        file_size = file_stats.st_size

        # Connexion à la base
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Informations sur le schéma
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        # Comptage des enregistrements par table
        table_counts = {}
        for table in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                table_counts[table] = cursor.fetchone()[0]
            except sqlite3.Error:
                table_counts[table] = "Error"

        # Informations sur la base
        cursor.execute("PRAGMA user_version")
        user_version = cursor.fetchone()[0]

        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0]

        cursor.execute("PRAGMA synchronous")
        synchronous = cursor.fetchone()[0]

        conn.close()

        return {
            "file_size_bytes": file_size,
            "file_size_human": _format_file_size(file_size),
            "tables_count": len(tables),
            "tables": table_counts,
            "user_version": user_version,
            "journal_mode": journal_mode,
            "synchronous": synchronous,
            "last_modified": file_stats.st_mtime,
            "tables_list": tables
        }

    except Exception as e:
        return {"error": str(e)}


def _format_file_size(size_bytes: int) -> str:
    """Formate une taille de fichier en format lisible"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def check_database_health(database_path: str) -> dict:
    """
    Vérifie la santé d'une base de données

    Args:
        database_path: Chemin vers la base de données

    Returns:
        dict: Résultat de la vérification de santé
    """
    import sqlite3
    from pathlib import Path

    health_report = {
        "healthy": True,
        "issues": [],
        "warnings": [],
        "recommendations": []
    }

    try:
        db_path = Path(database_path)

        # Vérifier l'existence
        if not db_path.exists():
            health_report["healthy"] = False
            health_report["issues"].append("Base de données non trouvée")
            return health_report

        # Vérifier la connectivité
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            cursor = conn.cursor()
        except sqlite3.Error as e:
            health_report["healthy"] = False
            health_report["issues"].append(f"Impossible de se connecter: {str(e)}")
            return health_report

        # Vérification d'intégrité
        try:
            cursor.execute("PRAGMA integrity_check")
            integrity_result = cursor.fetchone()
            if integrity_result[0] != "ok":
                health_report["healthy"] = False
                health_report["issues"].append(f"Intégrité compromise: {integrity_result[0]}")
        except sqlite3.Error as e:
            health_report["issues"].append(f"Erreur vérification intégrité: {str(e)}")

        # Vérifier la version du schéma
        try:
            cursor.execute("PRAGMA user_version")
            db_version = cursor.fetchone()[0]

            # Comparer avec la version attendue (simplification)
            expected_version = 1  # À ajuster selon votre système de versioning
            if db_version != expected_version:
                health_report["warnings"].append(
                    f"Version schéma différente: {db_version} (attendue: {expected_version})"
                )
        except sqlite3.Error:
            health_report["warnings"].append("Impossible de vérifier la version du schéma")

        # Vérifier les performances
        file_size = db_path.stat().st_size
        if file_size > 100 * 1024 * 1024:  # 100MB
            health_report["recommendations"].append("Base de données volumineuse - envisager une optimisation")

        # Vérifier le mode journal
        try:
            cursor.execute("PRAGMA journal_mode")
            journal_mode = cursor.fetchone()[0]
            if journal_mode not in ["WAL", "MEMORY"]:
                health_report["recommendations"].append("Considérer le mode WAL pour de meilleures performances")
        except sqlite3.Error:
            pass

        conn.close()

    except Exception as e:
        health_report["healthy"] = False
        health_report["issues"].append(f"Erreur lors de la vérification: {str(e)}")

    return health_report


# === INITIALISATION DU PACKAGE ===

def _initialize_database_package():
    """Initialisation du package database au chargement"""
    try:
        # Vérifier la disponibilité de SQLite
        import sqlite3
        sqlite_version = sqlite3.sqlite_version

        # Log de démarrage
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Package database initialisé - SQLite {sqlite_version}")

    except ImportError:
        import warnings
        warnings.warn("SQLite non disponible - fonctionnalités de base de données limitées")
    except Exception as e:
        import warnings
        warnings.warn(f"Erreur lors de l'initialisation du package database: {e}")


# Exécuter l'initialisation au chargement
_initialize_database_package()

# === INFORMATIONS DE DEBUG ===

if __name__ == "__main__":
    print(f"Package Database v{__version__}")
    print(f"Schéma version: {DATABASE_SCHEMA_VERSION}")

    print("\nModèles disponibles:")
    models = ["ScanModel", "VulnerabilityModel", "AnalysisModel", "ScriptModel", "WorkflowModel"]
    for model in models:
        print(f"  - {model}")

    print("\nConfiguration par défaut:")
    for key, value in DEFAULT_DATABASE_CONFIG.items():
        print(f"  {key}: {value}")

    print(f"\nCodes d'erreur: {len(ERROR_MESSAGES)} définis")
    print("Fonctionnalités: CRUD, Migrations, Backup/Restore, Validation")