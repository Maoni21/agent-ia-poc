"""
Configuration générale de l'Agent IA de Cybersécurité

Ce module contient toutes les configurations de l'application :
- Paramètres de connexion aux APIs
- Configuration des outils de scan
- Chemins des fichiers et répertoires
- Paramètres de logging
- Configuration de la base de données
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Chemin racine du projet
PROJECT_ROOT = Path(__file__).parent.parent
DATA_PATH = PROJECT_ROOT / "data"
LOG_PATH = PROJECT_ROOT / "logs"
CONFIG_PATH = PROJECT_ROOT / "config"


@dataclass
class Config:
    """Classe de configuration principale"""

    # === CONFIGURATION API ===
    openai_api_key: str
    openai_model: str = "gpt-3.5-turbo"  # Changé de gpt-4 à gpt-3.5-turbo (plus rapide)
    openai_max_tokens: int = 3000  # ← MODIFIÉ : Réduit de 2000 à 1000
    openai_temperature: float = 0.3

    # === CONFIGURATION SCAN ===
    nmap_default_args: str = "-sV -sC --script vuln"
    scan_timeout: int = 300  # 5 minutes
    max_concurrent_scans: int = 3

    # === LIMITES POUR ÉCONOMISER LES TOKENS ===
    max_vulnerabilities_to_analyze: int = 10  # ← NOUVEAU : Analyser 10 vulns max
    max_scripts_to_generate: int = 5  # ← NOUVEAU : Générer 5 scripts max

    # === CONFIGURATION BASE DE DONNÉES ===
    database_path: str = str(DATA_PATH / "database" / "vulnerability_agent.db")
    database_backup: bool = True
    max_scan_history: int = 100

    # === CONFIGURATION LOGGING ===
    log_level: str = "INFO"
    log_file: str = str(LOG_PATH / "app.log")
    log_max_size: int = 10485760  # 10MB
    log_backup_count: int = 5

    # === CONFIGURATION SÉCURITÉ ===
    enable_script_validation: bool = True
    allowed_script_commands: list = None
    sandbox_mode: bool = True

    # === CONFIGURATION RAPPORTS ===
    report_format: str = "json"  # json, html, txt
    max_report_size: int = 5242880  # 5MB

    def __post_init__(self):
        """Initialisation après création de l'objet"""
        if self.allowed_script_commands is None:
            self.allowed_script_commands = [
                "apt", "yum", "systemctl", "service",
                "chmod", "chown", "cp", "mv", "rm",
                "wget", "curl", "git", "pip", "npm"
            ]

    def get(self, key: str, default: Any = None) -> Any:
        """Permet d'accéder aux attributs via une interface de type dictionnaire."""
        return getattr(self, key, default)


# === CONSTANTES GLOBALES ===

# Paramètres de scan par défaut
NMAP_DEFAULT_ARGS = os.getenv("NMAP_DEFAULT_ARGS", "-sV -sC --script vuln")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "300"))

# Configuration AI Provider
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai").lower()  # openai ou anthropic

# Configuration OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")  # Changé de gpt-4

# Configuration Anthropic
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

MAX_TOKENS = int(os.getenv("MAX_TOKENS", "1000"))  # ← MODIFIÉ : Réduit de 2000 à 1000
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.3"))

# Limites pour économiser les tokens
MAX_VULNERABILITIES_TO_ANALYZE = int(os.getenv("MAX_VULNERABILITIES_TO_ANALYZE", "10"))  # ← NOUVEAU
MAX_SCRIPTS_TO_GENERATE = int(os.getenv("MAX_SCRIPTS_TO_GENERATE", "5"))  # ← NOUVEAU

# Chemins des fichiers
DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_PATH / "database" / "vulnerability_agent.db"))
VULNERABILITY_DB_PATH = CONFIG_PATH / "vulnerability_db.json"

# Configuration de logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", str(LOG_PATH / "app.log"))

# === CONFIGURATION DES TYPES DE SCAN ===
# ⭐ NOUVEAU : Configuration optimisée des scans Nmap
SCAN_TYPES = {
    'ultra-quick': {
        'nmap_args': '-T5 -F --max-retries 0 --host-timeout 10s',
        'description': 'Scan ultra-rapide pour tests et démos (30-60 secondes)',
        'timeout': 120,
        'ports': 'top-100'
    },
    'quick': {
        'nmap_args': '-T5 -F --host-timeout 30s --max-retries 1',
        'description': 'Scan rapide optimisé (2-3 minutes)',
        'timeout': 300,
        'ports': 'top-1000'
    },
    'full': {
        'nmap_args': '-T4 -sV --version-intensity 3 --host-timeout 60s --max-retries 2',
        'description': 'Scan complet avec détection de versions (5-10 minutes)',
        'timeout': 600,
        'ports': 'all'
    },
    'stealth': {
        'nmap_args': '-T2 -sS -f --scan-delay 1s',
        'description': 'Scan furtif lent pour éviter la détection',
        'timeout': 1800,
        'ports': 'top-1000'
    },
    'aggressive': {
        'nmap_args': '-T4 -A -sV --script vuln',
        'description': 'Scan agressif avec scripts de vulnérabilités',
        'timeout': 900,
        'ports': 'all'
    }
}

# === CONFIGURATION DES OUTILS ===

# Configuration Nmap
NMAP_CONFIG = {
    "timing": "T4",  # Timing template (T0-T5)
    "max_retries": 3,
    "host_timeout": "5m",
    "script_timeout": "2m",
    "ports": {
        "top_ports": 1000,
        "custom_ports": "22,23,25,53,80,110,139,143,443,993,995,1723,3389,5900,8080"
    },
    "scripts": {
        "default": ["vuln", "safe"],
        "aggressive": ["vuln", "malware", "exploit"],
        "stealth": ["vuln"]
    }
}

# Configuration des CVE et vulnérabilités
CVE_CONFIG = {
    "nvd_api_key": os.getenv("NVD_API_KEY"),  # Optionnel
    "cve_database_url": "https://cve.mitre.org/data/downloads/allitems.csv",
    "update_frequency": 24,  # heures
    "severity_threshold": 5.0  # CVSS score minimum
}

# Configuration IA/LLM - OPTIMISÉE
LLM_CONFIG = {
    "openai": {
        "provider": "openai",
        "api_key": OPENAI_API_KEY,
        "model": OPENAI_MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "timeout": 120  # Augmenté de 30 à 120 secondes
    },
    "openai_fast": {  # Configuration alternative pour tests rapides
        "provider": "openai",
        "api_key": OPENAI_API_KEY,
        "model": "gpt-3.5-turbo",  # Plus rapide
        "max_tokens": 1500,
        "temperature": 0.3,
        "timeout": 60
    },
    "openai_premium": {  # Configuration pour analyses approfondies
        "provider": "openai",
        "api_key": OPENAI_API_KEY,
        "model": "gpt-4",  # Plus précis mais plus lent
        "max_tokens": 2500,
        "temperature": 0.3,
        "timeout": 180  # 3 minutes
    },
    "ollama": {  # Configuration pour modèles locaux
        "provider": "ollama",
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": os.getenv("OLLAMA_MODEL", "llama3"),
        "max_tokens": 2000,
        "temperature": 0.3,
        "timeout": 90
    }
}


# === FONCTIONS DE CONFIGURATION ===

def get_config() -> Config:
    """
    Retourne la configuration complète de l'application

    Returns:
        Config: Instance de configuration avec tous les paramètres

    Raises:
        ValueError: Si la clé API n'est pas définie selon le provider
    """
    # Vérifier la clé API selon le provider
    if AI_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY n'est pas définie. "
                "Veuillez configurer votre fichier .env avec AI_PROVIDER=anthropic et ANTHROPIC_API_KEY"
            )
        api_key = ANTHROPIC_API_KEY
        model = ANTHROPIC_MODEL
    else:
        if not OPENAI_API_KEY:
            raise ValueError(
                "OPENAI_API_KEY n'est pas définie. "
                "Veuillez configurer votre fichier .env"
            )
        api_key = OPENAI_API_KEY
        model = OPENAI_MODEL

    return Config(
        openai_api_key=api_key,  # Utiliser la bonne clé selon le provider
        openai_model=model,  # Utiliser le bon modèle selon le provider
        openai_max_tokens=MAX_TOKENS,
        openai_temperature=TEMPERATURE,
        nmap_default_args=NMAP_DEFAULT_ARGS,
        scan_timeout=SCAN_TIMEOUT,
        database_path=DATABASE_PATH,
        log_level=LOG_LEVEL,
        log_file=LOG_FILE,
        max_vulnerabilities_to_analyze=MAX_VULNERABILITIES_TO_ANALYZE,  # ← NOUVEAU
        max_scripts_to_generate=MAX_SCRIPTS_TO_GENERATE  # ← NOUVEAU
    )


def get_scan_config(scan_type: str = 'quick') -> Dict[str, Any]:
    """
    Retourne la configuration pour un type de scan donné

    Args:
        scan_type: Type de scan (ultra-quick, quick, full, stealth, aggressive)

    Returns:
        Dict contenant la configuration du scan

    Raises:
        ValueError: Si le type de scan est invalide
    """
    if scan_type not in SCAN_TYPES:
        raise ValueError(
            f"Type de scan invalide: '{scan_type}'. "
            f"Types disponibles: {', '.join(SCAN_TYPES.keys())}"
        )

    return SCAN_TYPES[scan_type].copy()


def validate_config(config: Config) -> Dict[str, Any]:
    """
    Valide la configuration fournie

    Args:
        config: Instance de configuration à valider

    Returns:
        Dict: Dictionnaire avec le statut de validation et les détails

    Raises:
        ValueError: Si un paramètre obligatoire est manquant ou invalide
    """
    issues = []
    warnings = []

    # Vérifier la clé API
    if not config.openai_api_key or config.openai_api_key == "your_openai_api_key_here":
        issues.append("Clé API OpenAI invalide ou manquante")

    # Vérifier les chemins
    try:
        if not os.path.exists(Path(config.database_path).parent):
            os.makedirs(Path(config.database_path).parent, exist_ok=True)
    except Exception as e:
        warnings.append(f"Impossible de créer le répertoire de base de données: {e}")

    try:
        if not os.path.exists(Path(config.log_file).parent):
            os.makedirs(Path(config.log_file).parent, exist_ok=True)
    except Exception as e:
        warnings.append(f"Impossible de créer le répertoire de logs: {e}")

    # Vérifier les paramètres numériques
    if config.scan_timeout <= 0:
        issues.append("Timeout de scan doit être positif")

    if config.openai_max_tokens <= 0 or config.openai_max_tokens > 4000:
        issues.append("Max tokens doit être entre 1 et 4000")

    # Retourner le résultat de validation
    if issues:
        return {
            "valid": False,
            "status": "invalid",
            "issues": issues,
            "warnings": warnings
        }

    return {
        "valid": True,
        "status": "valid",
        "issues": [],
        "warnings": warnings
    }


def get_nmap_config(profile: str = "default") -> Dict[str, Any]:
    """
    Retourne la configuration Nmap pour un profil donné

    Args:
        profile: Profil de scan (default, aggressive, stealth)

    Returns:
        Dict contenant la configuration Nmap
    """
    if profile not in NMAP_CONFIG["scripts"]:
        profile = "default"

    return {
        "args": NMAP_DEFAULT_ARGS,
        "timing": NMAP_CONFIG["timing"],
        "timeout": SCAN_TIMEOUT,
        "scripts": NMAP_CONFIG["scripts"][profile],
        "ports": NMAP_CONFIG["ports"]["custom_ports"]
    }


def get_llm_config(provider: str = "openai") -> Dict[str, Any]:
    """
    Retourne la configuration pour un fournisseur LLM

    Args:
        provider: Fournisseur LLM (openai, openai_fast, openai_premium, ollama)

    Returns:
        Dict contenant la configuration du LLM

    Note:
        - "openai" : Configuration par défaut (gpt-3.5-turbo, 120s timeout)
        - "openai_fast" : Pour tests rapides (gpt-3.5-turbo, 60s timeout)
        - "openai_premium" : Pour analyses approfondies (gpt-4, 180s timeout)
        - "ollama" : Pour modèles locaux
    """
    if provider not in LLM_CONFIG:
        print(f"⚠️  Provider '{provider}' inconnu, utilisation de 'openai' par défaut")
        provider = "openai"

    config = LLM_CONFIG[provider].copy()

    # Ajouter le provider si pas présent
    if "provider" not in config:
        config["provider"] = provider.split("_")[0]  # openai_fast -> openai

    return config


# === VALIDATION AU CHARGEMENT ===

def _validate_environment():
    """Valide l'environnement au chargement du module"""

    # Créer les répertoires nécessaires
    os.makedirs(DATA_PATH, exist_ok=True)
    os.makedirs(DATA_PATH / "scans", exist_ok=True)
    os.makedirs(DATA_PATH / "reports", exist_ok=True)
    os.makedirs(DATA_PATH / "scripts", exist_ok=True)
    os.makedirs(DATA_PATH / "database", exist_ok=True)
    os.makedirs(DATA_PATH / "workflow_results", exist_ok=True)
    os.makedirs(LOG_PATH, exist_ok=True)

    # Avertir si la clé API n'est pas configurée
    if not OPENAI_API_KEY:
        print("⚠️  AVERTISSEMENT: OPENAI_API_KEY n'est pas définie dans les variables d'environnement")
        print("   Veuillez configurer votre fichier .env avant d'utiliser l'agent IA")
    else:
        # Afficher la configuration actuelle
        print(f"✅ Configuration OpenAI chargée:")
        print(f"   - Modèle: {OPENAI_MODEL}")
        print(f"   - Timeout: {LLM_CONFIG['openai']['timeout']}s")
        print(f"   - Max tokens: {MAX_TOKENS}")
        print(f"\n💰 Limites pour économiser les tokens:")
        print(f"   - Vulnérabilités analysées max: {MAX_VULNERABILITIES_TO_ANALYZE}")
        print(f"   - Scripts générés max: {MAX_SCRIPTS_TO_GENERATE}")
        print(f"\n⚡ Types de scans disponibles:")
        for scan_type, config in SCAN_TYPES.items():
            print(f"   - {scan_type}: {config['description']}")


# Exécuter la validation au chargement
_validate_environment()