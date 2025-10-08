"""
Package core pour l'Agent IA de Cybersécurité
"""


# === CODES D'ERREUR ===

class CoreErrorCodes:
    """Codes d'erreur pour les modules core"""

    # Erreurs génériques (10000-10999)
    CORE_INIT_ERROR = 10000
    MODULE_NOT_READY = 10001
    INVALID_CONFIGURATION = 10002
    RESOURCE_UNAVAILABLE = 10003

    # Erreurs de collecte (11000-11999)
    SCAN_TARGET_INVALID = 11000
    SCAN_TIMEOUT = 11001
    SCAN_PERMISSION_DENIED = 11002
    NMAP_NOT_FOUND = 11003
    SCAN_FAILED = 11004

    # Erreurs d'analyse (12000-12999)
    AI_SERVICE_ERROR = 12000
    ANALYSIS_TIMEOUT = 12001
    INVALID_VULNERABILITY_DATA = 12002
    AI_QUOTA_EXCEEDED = 12003
    ANALYSIS_FAILED = 12004  # ← AJOUTÉ

    # Erreurs de génération (13000-13999)
    SCRIPT_GENERATION_FAILED = 13000
    UNSAFE_SCRIPT_DETECTED = 13001
    VALIDATION_FAILED = 13002
    TEMPLATE_NOT_FOUND = 13003

    # Erreurs de supervisor (14000-14999)
    ORCHESTRATION_FAILED = 14000
    WORKFLOW_INTERRUPTED = 14001
    DEPENDENCY_MISSING = 14002


# Messages d'erreur correspondants
ERROR_MESSAGES = {
    CoreErrorCodes.CORE_INIT_ERROR: "Erreur d'initialisation du module core",
    CoreErrorCodes.MODULE_NOT_READY: "Module non prêt ou non initialisé",
    CoreErrorCodes.INVALID_CONFIGURATION: "Configuration invalide",
    CoreErrorCodes.RESOURCE_UNAVAILABLE: "Ressource indisponible",

    CoreErrorCodes.SCAN_TARGET_INVALID: "Cible de scan invalide",
    CoreErrorCodes.SCAN_TIMEOUT: "Timeout du scan",
    CoreErrorCodes.SCAN_PERMISSION_DENIED: "Permissions insuffisantes pour le scan",
    CoreErrorCodes.NMAP_NOT_FOUND: "Nmap non trouvé ou non installé",
    CoreErrorCodes.SCAN_FAILED: "Échec du scan",

    CoreErrorCodes.AI_SERVICE_ERROR: "Erreur du service IA",
    CoreErrorCodes.ANALYSIS_TIMEOUT: "Timeout de l'analyse IA",
    CoreErrorCodes.INVALID_VULNERABILITY_DATA: "Données de vulnérabilité invalides",
    CoreErrorCodes.AI_QUOTA_EXCEEDED: "Quota API IA dépassé",
    CoreErrorCodes.ANALYSIS_FAILED: "Échec de l'analyse IA",  # ← AJOUTÉ

    CoreErrorCodes.SCRIPT_GENERATION_FAILED: "Échec de génération de script",
    CoreErrorCodes.UNSAFE_SCRIPT_DETECTED: "Script potentiellement dangereux détecté",
    CoreErrorCodes.VALIDATION_FAILED: "Validation du script échouée",
    CoreErrorCodes.TEMPLATE_NOT_FOUND: "Template de script non trouvé",

    CoreErrorCodes.ORCHESTRATION_FAILED: "Échec de l'orchestration",
    CoreErrorCodes.WORKFLOW_INTERRUPTED: "Workflow interrompu",
    CoreErrorCodes.DEPENDENCY_MISSING: "Dépendance manquante",
}


# === EXCEPTIONS PERSONNALISÉES ===

class CoreException(Exception):
    """Exception de base pour les modules core"""

    def __init__(self, message: str, error_code: int = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = __import__('datetime').datetime.utcnow()


class CollectorException(CoreException):
    """Exception spécifique au module Collector"""
    pass


class AnalyzerException(CoreException):
    """Exception spécifique au module Analyzer"""
    pass


class GeneratorException(CoreException):
    """Exception spécifique au module Generator"""
    pass


class SupervisorException(CoreException):
    """Exception spécifique au module Supervisor"""
    pass


# === CONSTANTES ===

TASK_STATUS = {
    "PENDING": "pending",
    "RUNNING": "running",
    "COMPLETED": "completed",
    "FAILED": "failed",
    "CANCELLED": "cancelled"
}

OPERATION_TYPES = {
    "SCAN": "scan",
    "ANALYZE": "analyze",
    "GENERATE": "generate",
    "REPORT": "report"
}

DEFAULT_CONFIG = {
    "max_concurrent_tasks": 3,
    "timeout": 3600,
    "retry_attempts": 3,
    "orchestration_mode": "sequential"
}

# === IMPORTS DES MODULES ===

from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from .supervisor import Supervisor

# Version
__version__ = "1.0.0"

# Exports
__all__ = [
    # Modules
    "Collector",
    "Analyzer",
    "Generator",
    "Supervisor",

    # Modèles
    "ScanResult",
    "AnalysisResult",
    "ScriptResult",

    # Exceptions
    "CoreException",
    "CollectorException",
    "AnalyzerException",
    "GeneratorException",
    "SupervisorException",

    # Constantes
    "CoreErrorCodes",
    "ERROR_MESSAGES",
    "TASK_STATUS",
    "OPERATION_TYPES",
    "DEFAULT_CONFIG",
]


# === FONCTIONS UTILITAIRES ===

def get_core_version() -> str:
    """Retourne la version du package core"""
    return __version__


def create_supervisor(config: dict = None):
    """Factory pour créer un Supervisor"""
    return Supervisor(config=config)