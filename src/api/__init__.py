"""
Package API REST pour l'Agent IA de Cybersécurité

Ce package contient l'API REST basée sur FastAPI qui permet d'interagir
avec l'agent IA de manière programmatique via HTTP.

L'API expose les fonctionnalités suivantes :
- Lancement de scans de vulnérabilités
- Consultation des résultats d'analyse
- Génération de scripts de correction
- Gestion des rapports
- Monitoring et healthcheck

Structure du package :
- main.py : Application FastAPI principale
- routes.py : Définition des endpoints API
- schemas.py : Modèles Pydantic pour validation des données
"""

from .main import create_app, app
from .routes import router
from .schemas import (
    # Modèles de requête
    ScanRequest,
    AnalysisRequest,
    ScriptGenerationRequest,

    # Modèles de réponse
    ScanResponse,
    AnalysisResponse,
    ScriptResponse,
    VulnerabilityResponse,
    HealthResponse,

    # Modèles de données
    VulnerabilityModel,
    ScanResultModel,
    ScriptModel,
)

# Version de l'API
__version__ = "1.0.0"

# Configuration de l'API
API_CONFIG = {
    "title": "Agent IA Cybersécurité API",
    "description": "API REST pour la détection et correction automatisée de vulnérabilités",
    "version": __version__,
    "contact": {
        "name": "Équipe Cybersécurité",
        "email": "security@company.com",
    },
    "license_info": {
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
}

# Endpoints disponibles
ENDPOINTS = {
    # Healthcheck
    "health": "/health",
    "metrics": "/metrics",

    # Scans
    "scan_start": "/api/v1/scan",
    "scan_status": "/api/v1/scan/{scan_id}/status",
    "scan_results": "/api/v1/scan/{scan_id}/results",
    "scan_list": "/api/v1/scans",

    # Analyse
    "analyze": "/api/v1/analyze",
    "vulnerability_details": "/api/v1/vulnerability/{vuln_id}",

    # Scripts
    "generate_script": "/api/v1/script/generate",
    "validate_script": "/api/v1/script/validate",
    "script_details": "/api/v1/script/{script_id}",

    # Rapports
    "reports_list": "/api/v1/reports",
    "report_details": "/api/v1/report/{report_id}",
    "report_generate": "/api/v1/report/generate",

    # Administration
    "config": "/api/v1/config",
    "stats": "/api/v1/stats",
}


# Codes d'erreur personnalisés
class APIErrorCodes:
    """Codes d'erreur standardisés pour l'API"""

    # Erreurs génériques (1000-1999)
    INTERNAL_ERROR = 1000
    VALIDATION_ERROR = 1001
    AUTHENTICATION_ERROR = 1002
    AUTHORIZATION_ERROR = 1003
    RATE_LIMIT_ERROR = 1004

    # Erreurs de scan (2000-2999)
    SCAN_NOT_FOUND = 2000
    SCAN_ALREADY_RUNNING = 2001
    SCAN_FAILED = 2002
    INVALID_TARGET = 2003
    SCAN_TIMEOUT = 2004

    # Erreurs d'analyse (3000-3999)
    ANALYSIS_FAILED = 3000
    NO_VULNERABILITIES_FOUND = 3001
    AI_SERVICE_UNAVAILABLE = 3002

    # Erreurs de script (4000-4999)
    SCRIPT_GENERATION_FAILED = 4000
    SCRIPT_VALIDATION_FAILED = 4001
    UNSAFE_SCRIPT = 4002

    # Erreurs de rapport (5000-5999)
    REPORT_NOT_FOUND = 5000
    REPORT_GENERATION_FAILED = 5001


# Messages d'erreur correspondants
ERROR_MESSAGES = {
    APIErrorCodes.INTERNAL_ERROR: "Erreur interne du serveur",
    APIErrorCodes.VALIDATION_ERROR: "Données de requête invalides",
    APIErrorCodes.AUTHENTICATION_ERROR: "Authentification requise",
    APIErrorCodes.AUTHORIZATION_ERROR: "Permissions insuffisantes",
    APIErrorCodes.RATE_LIMIT_ERROR: "Limite de taux dépassée",

    APIErrorCodes.SCAN_NOT_FOUND: "Scan non trouvé",
    APIErrorCodes.SCAN_ALREADY_RUNNING: "Un scan est déjà en cours sur cette cible",
    APIErrorCodes.SCAN_FAILED: "Échec du scan",
    APIErrorCodes.INVALID_TARGET: "Cible invalide ou inaccessible",
    APIErrorCodes.SCAN_TIMEOUT: "Timeout du scan",

    APIErrorCodes.ANALYSIS_FAILED: "Échec de l'analyse IA",
    APIErrorCodes.NO_VULNERABILITIES_FOUND: "Aucune vulnérabilité détectée",
    APIErrorCodes.AI_SERVICE_UNAVAILABLE: "Service IA indisponible",

    APIErrorCodes.SCRIPT_GENERATION_FAILED: "Échec de la génération de script",
    APIErrorCodes.SCRIPT_VALIDATION_FAILED: "Validation du script échouée",
    APIErrorCodes.UNSAFE_SCRIPT: "Script considéré comme non sécurisé",

    APIErrorCodes.REPORT_NOT_FOUND: "Rapport non trouvé",
    APIErrorCodes.REPORT_GENERATION_FAILED: "Échec de la génération de rapport",
}

# Configuration des middlewares
MIDDLEWARE_CONFIG = {
    "cors": {
        "allow_origins": ["*"],  # À configurer selon l'environnement
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    },
    "rate_limiting": {
        "calls": 100,
        "period": 60,  # secondes
    },
    "compression": {
        "minimum_size": 1000,
    }
}

# Configuration de logging pour l'API
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        },
        "access": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
        "access": {
            "formatter": "access",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "logs/api_access.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
        },
    },
    "loggers": {
        "": {
            "level": "INFO",
            "handlers": ["default"],
        },
        "api.access": {
            "level": "INFO",
            "handlers": ["access"],
            "propagate": False,
        },
    },
}

# Tags pour l'organisation de la documentation OpenAPI
API_TAGS = [
    {
        "name": "health",
        "description": "Endpoints de santé et monitoring",
    },
    {
        "name": "scans",
        "description": "Gestion des scans de vulnérabilités",
    },
    {
        "name": "analysis",
        "description": "Analyse IA des vulnérabilités",
    },
    {
        "name": "scripts",
        "description": "Génération et validation de scripts de correction",
    },
    {
        "name": "reports",
        "description": "Génération et consultation de rapports",
    },
    {
        "name": "admin",
        "description": "Administration et configuration",
    },
]

# Export des éléments principaux
__all__ = [
    # Application
    "create_app",
    "app",
    "router",

    # Configuration
    "API_CONFIG",
    "ENDPOINTS",
    "MIDDLEWARE_CONFIG",
    "LOGGING_CONFIG",
    "API_TAGS",

    # Modèles de données
    "ScanRequest",
    "AnalysisRequest",
    "ScriptGenerationRequest",
    "ScanResponse",
    "AnalysisResponse",
    "ScriptResponse",
    "VulnerabilityResponse",
    "HealthResponse",
    "VulnerabilityModel",
    "ScanResultModel",
    "ScriptModel",

    # Gestion d'erreurs
    "APIErrorCodes",
    "ERROR_MESSAGES",
]


# Fonctions utilitaires pour l'initialisation de l'API
def get_api_version() -> str:
    """Retourne la version de l'API"""
    return __version__


def get_available_endpoints() -> dict:
    """Retourne la liste des endpoints disponibles"""
    return ENDPOINTS


def get_error_message(error_code: int) -> str:
    """
    Retourne le message d'erreur pour un code donné

    Args:
        error_code: Code d'erreur

    Returns:
        str: Message d'erreur correspondant
    """
    return ERROR_MESSAGES.get(error_code, "Erreur inconnue")


def validate_api_config() -> bool:
    """
    Valide la configuration de l'API

    Returns:
        bool: True si la configuration est valide

    Raises:
        ValueError: Si la configuration est invalide
    """
    required_fields = ["title", "description", "version"]

    for field in required_fields:
        if field not in API_CONFIG:
            raise ValueError(f"Champ manquant dans API_CONFIG: {field}")

    # Vérifier que les endpoints sont bien définis
    if not ENDPOINTS:
        raise ValueError("Aucun endpoint défini")

    return True


# Auto-validation au chargement du module
try:
    validate_api_config()
except Exception as e:
    import warnings

    warnings.warn(f"Configuration API invalide: {e}")

# Information de debug
if __name__ == "__main__":
    print(f"API Agent IA Cybersécurité v{__version__}")
    print(f"Endpoints disponibles: {len(ENDPOINTS)}")
    print("Configuration validée ✅")