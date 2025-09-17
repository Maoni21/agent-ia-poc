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
    openai_model: str = "gpt-4"
    openai_max_tokens: int = 2000
    openai_temperature: float = 0.3

    # === CONFIGURATION SCAN ===
    nmap_default_args: str = "-sV -sC --script vuln"
    scan_timeout: int = 300  # 5 minutes
    max_concurrent_scans: int = 3

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

# Configuration OpenAI
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "2000"))
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.3"))

# Chemins des fichiers
DATABASE_PATH = os.getenv("DATABASE_PATH", str(DATA_PATH / "database" / "vulnerability_agent.db"))
VULNERABILITY_DB_PATH = CONFIG_PATH / "vulnerability_db.json"

# Configuration de logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", str(LOG_PATH / "app.log"))

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

# Configuration IA/LLM
LLM_CONFIG = {
    "openai": {
        "api_key": OPENAI_API_KEY,
        "model": OPENAI_MODEL,
        "max_tokens": MAX_TOKENS,
        "temperature": TEMPERATURE,
        "timeout": 30
    },
    "ollama": {  # Configuration pour modèles locaux
        "base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": os.getenv("OLLAMA_MODEL", "llama3"),
        "timeout": 60
    }
}


# === FONCTIONS DE CONFIGURATION ===

def get_config() -> Config:
    """
    Retourne la configuration complète de l'application

    Returns:
        Config: Instance de configuration avec tous les paramètres

    Raises:
        ValueError: Si la clé API OpenAI n'est pas définie
    """
    if not OPENAI_API_KEY:
        raise ValueError(
            "OPENAI_API_KEY n'est pas définie. "
            "Veuillez configurer votre fichier .env"
        )

    return Config(
        openai_api_key=OPENAI_API_KEY,
        openai_model=OPENAI_MODEL,
        openai_max_tokens=MAX_TOKENS,
        openai_temperature=TEMPERATURE,
        nmap_default_args=NMAP_DEFAULT_ARGS,
        scan_timeout=SCAN_TIMEOUT,
        database_path=DATABASE_PATH,
        log_level=LOG_LEVEL,
        log_file=LOG_FILE
    )


def validate_config(config: Config) -> bool:
    """
    Valide la configuration fournie

    Args:
        config: Instance de configuration à valider

    Returns:
        bool: True si la configuration est valide

    Raises:
        ValueError: Si un paramètre obligatoire est manquant ou invalide
    """
    # Vérifier la clé API
    if not config.openai_api_key or config.openai_api_key == "your_openai_api_key_here":
        raise ValueError("Clé API OpenAI invalide ou manquante")

    # Vérifier les chemins
    if not os.path.exists(Path(config.database_path).parent):
        os.makedirs(Path(config.database_path).parent, exist_ok=True)

    if not os.path.exists(Path(config.log_file).parent):
        os.makedirs(Path(config.log_file).parent, exist_ok=True)

    # Vérifier les paramètres numériques
    if config.scan_timeout <= 0:
        raise ValueError("Timeout de scan doit être positif")

    if config.openai_max_tokens <= 0 or config.openai_max_tokens > 4000:
        raise ValueError("Max tokens doit être entre 1 et 4000")

    return True


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
        provider: Fournisseur LLM (openai, ollama)

    Returns:
        Dict contenant la configuration du LLM
    """
    if provider not in LLM_CONFIG:
        provider = "openai"

    return LLM_CONFIG[provider]


# === VALIDATION AU CHARGEMENT ===

def _validate_environment():
    """Valide l'environnement au chargement du module"""

    # Créer les répertoires nécessaires
    os.makedirs(DATA_PATH, exist_ok=True)
    os.makedirs(DATA_PATH / "scans", exist_ok=True)
    os.makedirs(DATA_PATH / "reports", exist_ok=True)
    os.makedirs(DATA_PATH / "scripts", exist_ok=True)
    os.makedirs(DATA_PATH / "database", exist_ok=True)
    os.makedirs(LOG_PATH, exist_ok=True)

    # Avertir si la clé API n'est pas configurée
    if not OPENAI_API_KEY:
        print("⚠️  AVERTISSEMENT: OPENAI_API_KEY n'est pas définie dans les variables d'environnement")
        print("   Veuillez configurer votre fichier .env avant d'utiliser l'agent IA")


# Exécuter la validation au chargement
_validate_environment()
