"""
Configuration complète pour l'API REST
Contient TOUTES les constantes nécessaires
"""

# Version
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
    "docs_url": "/docs",
    "redoc_url": "/redoc",
}
# Configuration des middlewares
MIDDLEWARE_CONFIG = {
    "cors": {
        "enabled": True,
        "allow_origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    },
    "compression": {"enabled": True, "minimum_size": 1000},
}

# Configuration de sécurité
SECURITY_CONFIG = {
    "api_key_enabled": False,
    "cors_enabled": True,
    "https_only": False,
}

# Endpoints
ENDPOINTS = {
    "health": "/health",
    "scan_start": "/api/v1/scan",
}

# Codes d'erreur API
class APIErrorCodes:
    """Codes d'erreur pour l'API"""
    # Erreurs générales (40000-40999)
    BAD_REQUEST = 40000
    UNAUTHORIZED = 40001
    FORBIDDEN = 40002
    NOT_FOUND = 40003
    INTERNAL_ERROR = 40999  # AJOUTEZ CETTE LIGNE

    # Erreurs métier (41000-41999)
    SCAN_NOT_FOUND = 41000
    INVALID_TARGET = 41001
    SCAN_IN_PROGRESS = 41002
    ANALYSIS_FAILED = 41003
    SCAN_FAILED = 41004  # AJOUTEZ CETTE LIGNE

API_ERROR_MESSAGES = {
    APIErrorCodes.BAD_REQUEST: "Requête invalide",
    APIErrorCodes.NOT_FOUND: "Ressource non trouvée",
    APIErrorCodes.SCAN_NOT_FOUND: "Scan non trouvé",
    APIErrorCodes.INVALID_TARGET: "Cible invalide",
    APIErrorCodes.INTERNAL_ERROR: "Erreur interne du serveur",  # AJOUTEZ
    APIErrorCodes.SCAN_FAILED: "Échec du scan",  # AJOUTEZ
}

# Statuts HTTP
HTTP_STATUS = {
    "OK": 200,
    "CREATED": 201,
    "BAD_REQUEST": 400,
    "NOT_FOUND": 404,
    "INTERNAL_ERROR": 500,
}

# Configuration des routes
ROUTE_CONFIG = {
    "prefix": "/api/v1",
    "tags": ["scans", "analysis", "scripts"],
}

# Limites de requêtes
REQUEST_LIMITS = {
    "max_scan_targets": 100,
    "max_request_size": 10485760,  # 10MB
    "timeout_seconds": 300,
}

# Configuration de logging pour l'API
LOGGING_CONFIG = {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
}

# Alias pour compatibilité
ERROR_MESSAGES = API_ERROR_MESSAGES

# Tags pour la documentation API
API_TAGS = [
    {"name": "scans", "description": "Opérations de scan"},
    {"name": "analysis", "description": "Analyse de vulnérabilités"},
    {"name": "scripts", "description": "Génération de scripts"},
]
