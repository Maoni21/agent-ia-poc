"""
Package core pour l'Agent IA de Cybersécurité

Ce package contient les modules principaux de l'agent IA :
- Collecteur de vulnérabilités (scanner)
- Analyseur IA
- Générateur de scripts de correction
- Superviseur orchestrateur

Architecture :
    Supervisor
    ├── Collector (scan des vulnérabilités)
    ├── Analyzer (analyse IA)
    └── Generator (génération de scripts)

Chaque module peut fonctionner de manière autonome ou être orchestré
par le Supervisor pour un workflow complet.
"""

from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from .supervisor import Supervisor

# Version du package core
__version__ = "1.0.0"

# Export des classes principales
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

    # Fonctions utilitaires
    "create_supervisor",
    "get_core_version",
    "validate_core_config",
]

# === CONSTANTES DU PACKAGE ===

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


# Codes d'erreur spécifiques au core
class CoreErrorCodes:
    """Codes d'erreur pour les modules core"""

    # Erreurs génériques (10000-10999)
    CORE_INIT_ERROR = 10000
    MODULE_NOT_READY = 10001
    INVALID_CONFIGURATION = 10002
    RESOURCE_UNAVAILABLE = 10003

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


# === FONCTIONS UTILITAIRES ===

def get_core_version() -> str:
    """
    Retourne la version du package core

    Returns:
        str: Version du package
    """
    return __version__


def validate_core_config(config: dict) -> bool:
    """
    Valide la configuration des modules core

    Args:
        config: Configuration à valider

    Returns:
        bool: True si la configuration est valide

    Raises:
        CoreException: Si la configuration est invalide
    """
    required_modules = ["collector", "analyzer", "generator", "supervisor"]

    for module in required_modules:
        if module not in config:
            raise CoreException(
                f"Configuration manquante pour le module: {module}",
                CoreErrorCodes.INVALID_CONFIGURATION
            )

    # Validation spécifique par module
    _validate_collector_config(config["collector"])
    _validate_analyzer_config(config["analyzer"])
    _validate_generator_config(config["generator"])
    _validate_supervisor_config(config["supervisor"])

    return True


def _validate_collector_config(config: dict) -> bool:
    """Valide la configuration du collector"""
    if config.get("max_concurrent_scans", 0) <= 0:
        raise CoreException("max_concurrent_scans doit être > 0")

    if config.get("default_timeout", 0) <= 0:
        raise CoreException("default_timeout doit être > 0")

    return True


def _validate_analyzer_config(config: dict) -> bool:
    """Valide la configuration de l'analyzer"""
    allowed_providers = ["openai", "anthropic", "ollama"]
    provider = config.get("model_provider")

    if provider not in allowed_providers:
        raise CoreException(f"Fournisseur IA non supporté: {provider}")

    if config.get("max_tokens", 0) <= 0:
        raise CoreException("max_tokens doit être > 0")

    return True


def _validate_generator_config(config: dict) -> bool:
    """Valide la configuration du generator"""
    if not isinstance(config.get("safety_checks"), bool):
        raise CoreException("safety_checks doit être un booléen")

    allowed_modes = ["strict", "moderate", "permissive"]
    validation_mode = config.get("validation_mode")

    if validation_mode not in allowed_modes:
        raise CoreException(f"Mode de validation invalide: {validation_mode}")

    return True


def _validate_supervisor_config(config: dict) -> bool:
    """Valide la configuration du supervisor"""
    allowed_modes = ["sequential", "parallel", "hybrid"]
    orchestration_mode = config.get("orchestration_mode")

    if orchestration_mode not in allowed_modes:
        raise CoreException(f"Mode d'orchestration invalide: {orchestration_mode}")

    return True


def create_supervisor(config: dict = None) -> Supervisor:
    """
    Factory pour créer une instance de Supervisor configurée

    Args:
        config: Configuration personnalisée (optionnel)

    Returns:
        Supervisor: Instance configurée du superviseur

    Raises:
        CoreException: Si la création échoue
    """
    try:
        # Utiliser la configuration par défaut si non fournie
        if config is None:
            config = DEFAULT_CONFIG.copy()
        else:
            # Merger avec la configuration par défaut
            merged_config = DEFAULT_CONFIG.copy()
            merged_config.update(config)
            config = merged_config

        # Valider la configuration
        validate_core_config(config)

        # Créer le superviseur
        supervisor = Supervisor(config=config)

        return supervisor

    except Exception as e:
        raise CoreException(
            f"Erreur lors de la création du superviseur: {str(e)}",
            CoreErrorCodes.CORE_INIT_ERROR
        )


def get_error_message(error_code: int) -> str:
    """
    Retourne le message d'erreur pour un code donné

    Args:
        error_code: Code d'erreur

    Returns:
        str: Message d'erreur correspondant
    """
    return ERROR_MESSAGES.get(error_code, "Erreur inconnue")


def check_dependencies() -> dict:
    """
    Vérifie les dépendances des modules core

    Returns:
        dict: Statut des dépendances
    """
    dependencies = {
        "nmap": False,
        "openai": False,
        "requests": False,
        "sqlite3": False
    }

    # Vérifier Nmap
    import shutil
    dependencies["nmap"] = shutil.which("nmap") is not None

    # Vérifier les packages Python
    try:
        import openai
        dependencies["openai"] = True
    except ImportError:
        pass

    try:
        import requests
        dependencies["requests"] = True
    except ImportError:
        pass

    try:
        import sqlite3
        dependencies["sqlite3"] = True
    except ImportError:
        pass

    return dependencies


def get_module_status() -> dict:
    """
    Retourne le statut des modules core

    Returns:
        dict: Statut de chaque module
    """
    status = {
        "collector": "unknown",
        "analyzer": "unknown",
        "generator": "unknown",
        "supervisor": "unknown",
        "dependencies": check_dependencies()
    }

    # TODO: Implémenter la vérification réelle du statut des modules
    # Pour l'instant, on assume qu'ils sont disponibles si les dépendances le sont
    deps = status["dependencies"]

    status["collector"] = "ready" if deps["nmap"] else "not_ready"
    status["analyzer"] = "ready" if deps["openai"] else "not_ready"
    status["generator"] = "ready"  # Pas de dépendance externe critique
    status["supervisor"] = "ready" if all([
        status["collector"] == "ready",
        status["analyzer"] == "ready",
        status["generator"] == "ready"
    ]) else "not_ready"

    return status


# === INITIALISATION DU PACKAGE ===

def _initialize_package():
    """Initialisation du package core au chargement"""
    try:
        # Vérifier les dépendances critiques
        dependencies = check_dependencies()

        missing_deps = [dep for dep, available in dependencies.items() if not available]
        if missing_deps:
            import warnings
            warnings.warn(
                f"Dépendances manquantes pour le package core: {', '.join(missing_deps)}"
            )

        # Log de démarrage
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Package core initialisé - version {__version__}")

    except Exception as e:
        import warnings
        warnings.warn(f"Erreur lors de l'initialisation du package core: {e}")


# Exécuter l'initialisation au chargement
_initialize_package()

# === INFORMATIONS DE DEBUG ===

if __name__ == "__main__":
    print(f"Agent IA Cybersécurité - Package Core v{__version__}")
    print("\nModules disponibles:")
    for module in ["collector", "analyzer", "generator", "supervisor"]:
        print(f"  - {module}")

    print("\nStatut des modules:")
    status = get_module_status()
    for module, state in status.items():
        if module != "dependencies":
            print(f"  {module}: {state}")

    print("\nDépendances:")
    for dep, available in status["dependencies"].items():
        status_str = "✅" if available else "❌"
        print(f"  {dep}: {status_str}")