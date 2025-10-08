#!/usr/bin/env python3
"""
Script de correction des imports circulaires
Corrige les problèmes d'imports après le nettoyage
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

# === CORRECTION 1: src/core/__init__.py ===
# On doit rajouter les exceptions et constantes

CORE_INIT_FIXED = '''"""
Package core - Modules principaux de traitement
"""

# === EXCEPTIONS ===

class CoreException(Exception):
    """Exception de base pour les modules core"""
    pass


class CollectorException(CoreException):
    """Exception pour le module Collector"""
    pass


class AnalyzerException(CoreException):
    """Exception pour le module Analyzer"""
    pass


class GeneratorException(CoreException):
    """Exception pour le module Generator"""
    pass


class SupervisorException(CoreException):
    """Exception pour le module Supervisor"""
    pass


# === CODES D'ERREUR ===

class CoreErrorCodes:
    """Codes d'erreur pour les modules core"""

    # Erreurs génériques
    CORE_INIT_ERROR = 10000
    MODULE_NOT_READY = 10001
    INVALID_CONFIGURATION = 10002

    # Erreurs Collector
    SCAN_TARGET_INVALID = 11000
    SCAN_TIMEOUT = 11001
    SCAN_PERMISSION_DENIED = 11002
    NMAP_NOT_FOUND = 11003

    # Erreurs Analyzer
    AI_SERVICE_ERROR = 12000
    ANALYSIS_TIMEOUT = 12001
    INVALID_VULNERABILITY_DATA = 12002

    # Erreurs Generator
    SCRIPT_GENERATION_FAILED = 13000
    UNSAFE_SCRIPT_DETECTED = 13001
    VALIDATION_FAILED = 13002


# === MESSAGES D'ERREUR ===

ERROR_MESSAGES = {
    CoreErrorCodes.CORE_INIT_ERROR: "Erreur d'initialisation du module core",
    CoreErrorCodes.MODULE_NOT_READY: "Module non prêt",
    CoreErrorCodes.INVALID_CONFIGURATION: "Configuration invalide",
    CoreErrorCodes.SCAN_TARGET_INVALID: "Cible de scan invalide",
    CoreErrorCodes.SCAN_TIMEOUT: "Timeout du scan",
    CoreErrorCodes.SCAN_PERMISSION_DENIED: "Permission refusée",
    CoreErrorCodes.NMAP_NOT_FOUND: "Nmap non trouvé",
    CoreErrorCodes.AI_SERVICE_ERROR: "Erreur service IA",
    CoreErrorCodes.ANALYSIS_TIMEOUT: "Timeout de l'analyse",
    CoreErrorCodes.INVALID_VULNERABILITY_DATA: "Données de vulnérabilité invalides",
    CoreErrorCodes.SCRIPT_GENERATION_FAILED: "Échec de génération du script",
    CoreErrorCodes.UNSAFE_SCRIPT_DETECTED: "Script dangereux détecté",
    CoreErrorCodes.VALIDATION_FAILED: "Échec de validation",
}


# === IMPORTS DES MODULES ===

from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from .supervisor import Supervisor

__version__ = "1.0.0"

__all__ = [
    # Classes principales
    "Collector",
    "Analyzer",
    "Generator", 
    "Supervisor",

    # Modèles de données
    "ScanResult",
    "AnalysisResult",
    "ScriptResult",

    # Exceptions
    "CoreException",
    "CollectorException",
    "AnalyzerException",
    "GeneratorException",
    "SupervisorException",

    # Codes d'erreur
    "CoreErrorCodes",
    "ERROR_MESSAGES",
]
'''

# === CORRECTION 2: src/utils/__init__.py ===
# Ajouter les exceptions manquantes

UTILS_INIT_FIXED = '''"""
Package utils - Utilitaires transversaux
"""

# === EXCEPTIONS ===

class ValidationError(Exception):
    """Exception levée lors d'une erreur de validation"""
    pass


class ParserError(Exception):
    """Exception levée lors d'une erreur de parsing"""
    pass


class SecurityError(Exception):
    """Exception levée lors d'une erreur de sécurité"""
    pass


# === IMPORTS ===

from .logger import setup_logger
from .validators import validate_ip_address, validate_domain, validate_port
from .decorators import handle_errors, retry, timeout

__version__ = "1.0.0"

__all__ = [
    # Fonctions principales
    "setup_logger",
    "validate_ip_address",
    "validate_domain",
    "validate_port",
    "handle_errors",
    "retry",
    "timeout",

    # Exceptions
    "ValidationError",
    "ParserError",
    "SecurityError",
]
'''

# === CORRECTION 3: src/database/__init__.py ===

DATABASE_INIT_FIXED = '''"""
Package database - Gestion de la persistance
"""

# === EXCEPTIONS ===

class DatabaseError(Exception):
    """Exception de base pour les erreurs de base de données"""
    pass


class ConnectionError(DatabaseError):
    """Erreur de connexion à la base de données"""
    pass


# === IMPORTS ===

from .database import Database

__version__ = "1.0.0"

__all__ = [
    "Database",
    "DatabaseError",
    "ConnectionError",
]
'''


def fix_imports():
    """Corriger les imports circulaires"""

    print("🔧 CORRECTION DES IMPORTS CIRCULAIRES")
    print("=" * 60)

    fixes = [
        ("src/core/__init__.py", CORE_INIT_FIXED),
        ("src/utils/__init__.py", UTILS_INIT_FIXED),
        ("src/database/__init__.py", DATABASE_INIT_FIXED),
    ]

    for file_path, content in fixes:
        full_path = PROJECT_ROOT / file_path

        if full_path.exists():
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"  ✓ Corrigé: {file_path}")
        else:
            print(f"  ⚠️  Non trouvé: {file_path}")

    print("\n✅ Corrections appliquées !")
    print("\n🧪 Testez maintenant avec: python test_full_workflow.py")


if __name__ == "__main__":
    fix_imports()