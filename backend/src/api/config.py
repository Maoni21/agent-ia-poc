"""
Configuration complète pour l'Agent IA de Cybersécurité
Supporte OpenAI et Anthropic/Claude
"""

import os
from pathlib import Path

# Version
__version__ = "1.0.0"

# ============================================================
# CONFIGURATION IA - OPENAI
# ============================================================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
OPENAI_MAX_TOKENS = int(os.getenv("OPENAI_MAX_TOKENS", "1000"))
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.7"))
OPENAI_TIMEOUT = int(os.getenv("OPENAI_TIMEOUT", "120"))

# ============================================================
# CONFIGURATION IA - ANTHROPIC/CLAUDE
# ============================================================
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
ANTHROPIC_MAX_TOKENS = int(os.getenv("ANTHROPIC_MAX_TOKENS", "4096"))
ANTHROPIC_TEMPERATURE = float(os.getenv("ANTHROPIC_TEMPERATURE", "0.7"))
ANTHROPIC_TIMEOUT = int(os.getenv("ANTHROPIC_TIMEOUT", "120"))

# ============================================================
# CHOIX DU PROVIDER IA
# ============================================================
AI_PROVIDER = os.getenv("AI_PROVIDER", "anthropic")  # "openai" ou "anthropic"

# ============================================================
# LIMITES POUR ÉCONOMISER LES TOKENS
# ============================================================
MAX_VULNERABILITIES_TO_ANALYZE = int(os.getenv("MAX_VULNERABILITIES_TO_ANALYZE", "10"))
MAX_SCRIPTS_TO_GENERATE = int(os.getenv("MAX_SCRIPTS_TO_GENERATE", "5"))

# ============================================================
# CONFIGURATION NMAP
# ============================================================
NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "3600"))

# Types de scan disponibles
SCAN_TYPES = {
    "ultra-quick": {
        "args": "-T5 -F --top-ports 100",
        "description": "Scan ultra-rapide pour tests et démos (30-60 secondes)",
        "timeout": 90,
    },
    "quick": {
        "args": "-T4 -F --top-ports 1000",
        "description": "Scan rapide optimisé (2-3 minutes)",
        "timeout": 300,
    },
    "full": {
        "args": "-sV -sC -O -A -T4",
        "description": "Scan complet avec détection de versions (5-10 minutes)",
        "timeout": 900,
    },
    "stealth": {
        "args": "-sS -T2 -f",
        "description": "Scan furtif lent pour éviter la détection",
        "timeout": 1800,
    },
    "aggressive": {
        "args": "-sV -sC --script vuln -A -T4",
        "description": "Scan agressif avec scripts de vulnérabilités",
        "timeout": 1200,
    },
}

# ============================================================
# CONFIGURATION BASE DE DONNÉES
# ============================================================
DATABASE_PATH = os.getenv("DATABASE_PATH", "data/database/vulnerability_agent.db")
DATABASE_BACKUP_ENABLED = os.getenv("DATABASE_BACKUP_ENABLED", "true").lower() == "true"
DATABASE_BACKUP_INTERVAL_HOURS = int(os.getenv("DATABASE_BACKUP_INTERVAL_HOURS", "24"))

# ============================================================
# CONFIGURATION API REST
# ============================================================
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
        "allow_origins": [
            "http://localhost:3000",  # Frontend React en développement
            "http://localhost:3001",  # Alternative
            "http://127.0.0.1:3000",
            "http://127.0.0.1:3001",
            # En production, remplacer par le vrai domaine :
            # "https://votre-domaine.com"
        ],
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
    VALIDATION_ERROR = 40004
    INTERNAL_ERROR = 40999

    # Erreurs métier (41000-41999)
    SCAN_NOT_FOUND = 41000
    INVALID_TARGET = 41001
    SCAN_IN_PROGRESS = 41002
    SCAN_ALREADY_RUNNING = 41003
    ANALYSIS_FAILED = 41004
    SCAN_FAILED = 41005
    SCRIPT_GENERATION_FAILED = 41006
    SCRIPT_VALIDATION_FAILED = 41007
    REPORT_GENERATION_FAILED = 41008


API_ERROR_MESSAGES = {
    APIErrorCodes.BAD_REQUEST: "Requête invalide",
    APIErrorCodes.UNAUTHORIZED: "Non autorisé",
    APIErrorCodes.FORBIDDEN: "Accès interdit",
    APIErrorCodes.NOT_FOUND: "Ressource non trouvée",
    APIErrorCodes.VALIDATION_ERROR: "Erreur de validation",
    APIErrorCodes.INTERNAL_ERROR: "Erreur interne du serveur",
    APIErrorCodes.SCAN_NOT_FOUND: "Scan non trouvé",
    APIErrorCodes.INVALID_TARGET: "Cible invalide",
    APIErrorCodes.SCAN_IN_PROGRESS: "Scan déjà en cours",
    APIErrorCodes.SCAN_ALREADY_RUNNING: "Un scan est déjà en cours pour cette cible",
    APIErrorCodes.ANALYSIS_FAILED: "Échec de l'analyse",
    APIErrorCodes.SCAN_FAILED: "Échec du scan",
    APIErrorCodes.SCRIPT_GENERATION_FAILED: "Échec de la génération de script",
    APIErrorCodes.SCRIPT_VALIDATION_FAILED: "Échec de la validation du script",
    APIErrorCodes.REPORT_GENERATION_FAILED: "Échec de la génération du rapport",
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


# ============================================================
# FONCTION GET_CONFIG
# ============================================================
def get_config():
    """Retourne la configuration complète de l'application"""
    return {
        # IA Provider
        "ai_provider": AI_PROVIDER,

        # OpenAI
        "openai_api_key": OPENAI_API_KEY,
        "openai_model": OPENAI_MODEL,
        "openai_max_tokens": OPENAI_MAX_TOKENS,
        "openai_temperature": OPENAI_TEMPERATURE,
        "openai_timeout": OPENAI_TIMEOUT,

        # Anthropic
        "anthropic_api_key": ANTHROPIC_API_KEY,
        "anthropic_model": ANTHROPIC_MODEL,
        "anthropic_max_tokens": ANTHROPIC_MAX_TOKENS,
        "anthropic_temperature": ANTHROPIC_TEMPERATURE,
        "anthropic_timeout": ANTHROPIC_TIMEOUT,

        # Limites
        "max_vulnerabilities_to_analyze": MAX_VULNERABILITIES_TO_ANALYZE,
        "max_scripts_to_generate": MAX_SCRIPTS_TO_GENERATE,

        # Nmap
        "nmap_path": NMAP_PATH,
        "nmap_timeout": NMAP_TIMEOUT,
        "scan_types": SCAN_TYPES,

        # Database
        "database_path": DATABASE_PATH,
        "database_backup_enabled": DATABASE_BACKUP_ENABLED,

        # Concurrence
        "max_concurrent_workflows": 3,
        "max_concurrent_tasks": 5,
    }


def print_config_summary():
    """Affiche un résumé de la configuration"""
    provider = AI_PROVIDER.upper()

    if AI_PROVIDER == "openai":
        api_key = OPENAI_API_KEY[:10] + "..." if OPENAI_API_KEY else "NON DÉFINIE"
        model = OPENAI_MODEL
        timeout = OPENAI_TIMEOUT
        max_tokens = OPENAI_MAX_TOKENS
    else:  # anthropic
        api_key = ANTHROPIC_API_KEY[:15] + "..." if ANTHROPIC_API_KEY else "NON DÉFINIE"
        model = ANTHROPIC_MODEL
        timeout = ANTHROPIC_TIMEOUT
        max_tokens = ANTHROPIC_MAX_TOKENS

    print(f"✅ Configuration {provider} chargée:")
    print(f"   - Clé API: {api_key}")
    print(f"   - Modèle: {model}")
    print(f"   - Timeout: {timeout}s")
    print(f"   - Max tokens: {max_tokens}")
    print()
    print("💰 Limites pour économiser les tokens:")
    print(f"   - Vulnérabilités analysées max: {MAX_VULNERABILITIES_TO_ANALYZE}")
    print(f"   - Scripts générés max: {MAX_SCRIPTS_TO_GENERATE}")
    print()
    print("⚡ Types de scans disponibles:")
    for scan_type, config in SCAN_TYPES.items():
        print(f"   - {scan_type}: {config['description']}")