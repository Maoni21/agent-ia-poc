"""
Exceptions et constantes pour le module core
"""

import datetime


# === EXCEPTIONS ===

class CoreException(Exception):
    """Exception de base pour les modules core"""
    def __init__(self, message: str, error_code: int = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = datetime.datetime.utcnow()


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


# === CODES D'ERREUR ===

class CoreErrorCodes:
    """Codes d'erreur pour les modules core"""

    # Erreurs génériques (10000-10999)
    CORE_INIT_ERROR = 10000
    MODULE_NOT_READY = 10001
    INVALID_CONFIGURATION = 10002
    RESOURCE_UNAVAILABLE = 10003
    SCAN_FAILED = 10004

    # Erreurs de collector (11000-11999)
    SCAN_TARGET_INVALID = 11000
    SCAN_TIMEOUT = 11001
    SCAN_PERMISSION_DENIED = 11002
    NMAP_NOT_FOUND = 11003

    # Erreurs d'analyzer (12000-12999)
    AI_SERVICE_ERROR = 12000
    ANALYSIS_TIMEOUT = 12001
    INVALID_VULNERABILITY_DATA = 12002
    AI_QUOTA_EXCEEDED = 12003

    # Erreurs de generator (13000-13999)
    SCRIPT_GENERATION_FAILED = 13000
    UNSAFE_SCRIPT_DETECTED = 13001
    VALIDATION_FAILED = 13002
    TEMPLATE_NOT_FOUND = 13003

    # Erreurs de supervisor (14000-14999)
    ORCHESTRATION_FAILED = 14000
    WORKFLOW_INTERRUPTED = 14001
    DEPENDENCY_MISSING = 14002


# === MESSAGES D'ERREUR ===

ERROR_MESSAGES = {
    CoreErrorCodes.CORE_INIT_ERROR: "Erreur d'initialisation du module core",
    CoreErrorCodes.MODULE_NOT_READY: "Module non prêt ou non initialisé",
    CoreErrorCodes.INVALID_CONFIGURATION: "Configuration invalide",
    CoreErrorCodes.RESOURCE_UNAVAILABLE: "Ressource indisponible",
    CoreErrorCodes.SCAN_FAILED: "Échec du scan",

    CoreErrorCodes.SCAN_TARGET_INVALID: "Cible de scan invalide",
    CoreErrorCodes.SCAN_TIMEOUT: "Timeout du scan",
    CoreErrorCodes.SCAN_PERMISSION_DENIED: "Permissions insuffisantes pour le scan",
    CoreErrorCodes.NMAP_NOT_FOUND: "Nmap non trouvé ou non installé",

    CoreErrorCodes.AI_SERVICE_ERROR: "Erreur du service IA",
    CoreErrorCodes.ANALYSIS_TIMEOUT: "Timeout de l'analyse IA",
    CoreErrorCodes.INVALID_VULNERABILITY_DATA: "Données de vulnérabilité invalides",
    CoreErrorCodes.AI_QUOTA_EXCEEDED: "Quota API IA dépassé",

    CoreErrorCodes.SCRIPT_GENERATION_FAILED: "Échec de génération de script",
    CoreErrorCodes.UNSAFE_SCRIPT_DETECTED: "Script potentiellement dangereux détecté",
    CoreErrorCodes.VALIDATION_FAILED: "Validation du script échouée",
    CoreErrorCodes.TEMPLATE_NOT_FOUND: "Template de script non trouvé",

    CoreErrorCodes.ORCHESTRATION_FAILED: "Échec de l'orchestration",
    CoreErrorCodes.WORKFLOW_INTERRUPTED: "Workflow interrompu",
    CoreErrorCodes.DEPENDENCY_MISSING: "Dépendance manquante",
}


# === CONSTANTES ===

# États possibles des tâches core
TASK_STATUS = {
    "PENDING": "pending",
    "RUNNING": "running",
    "COMPLETED": "completed",
    "FAILED": "failed",
    "CANCELLED": "cancelled"
}

# Types d'opération supportés
OPERATION_TYPES = {
    "SCAN": "scan",
    "ANALYZE": "analyze",
    "GENERATE": "generate",
    "VALIDATE": "validate"
}

# Configuration par défaut des modules
DEFAULT_CONFIG = {
    "collector": {
        "max_concurrent_scans": 3,
        "default_timeout": 300,
        "retry_count": 3,
        "output_format": "json"
    },
    "analyzer": {
        "model_provider": "openai",
        "model_name": "gpt-4",
        "max_tokens": 2000,
        "temperature": 0.3,
        "timeout": 60
    },
    "generator": {
        "safety_checks": True,
        "validation_mode": "strict",
        "backup_scripts": True,
        "rollback_generation": True
    },
    "supervisor": {
        "orchestration_mode": "sequential",
        "error_handling": "strict",
        "logging_level": "INFO",
        "monitoring_enabled": True
    }
}
