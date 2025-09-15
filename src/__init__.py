"""
Package principal src pour l'Agent IA de Cybersécurité

Ce package contient tous les modules de l'application :
- core : Modules principaux (Collector, Analyzer, Generator, Supervisor)
- api : Interface REST avec FastAPI
- database : Gestion de la base de données
- utils : Utilitaires transversaux

Architecture globale :
    Application (main.py)
    ├── API REST (src.api)
    ├── Core Modules (src.core)
    │   ├── Supervisor (orchestrateur)
    │   ├── Collector (scan vulnérabilités)
    │   ├── Analyzer (analyse IA)
    │   └── Generator (génération scripts)
    ├── Database (src.database)
    └── Utils (src.utils)
"""

from .core import (
    # Classes principales
    Collector,
    Analyzer,
    Generator,
    Supervisor,

    # Modèles de données
    ScanResult,
    AnalysisResult,
    ScriptResult,

    # Fonctions utilitaires
    create_supervisor,
    get_core_version,
)

from .database import (
    Database,
    DatabaseError,
)

from .utils import (
    setup_logger,
    validate_ip_address,
    validate_domain,
)

# Version du package src
__version__ = "1.0.0"

# Export des éléments principaux
__all__ = [
    # Version
    "__version__",

    # Modules core
    "Collector",
    "Analyzer",
    "Generator",
    "Supervisor",

    # Modèles de données
    "ScanResult",
    "AnalysisResult",
    "ScriptResult",

    # Database
    "Database",
    "DatabaseError",

    # Utils
    "setup_logger",
    "validate_ip_address",
    "validate_domain",

    # Fonctions utilitaires
    "create_supervisor",
    "get_core_version",
    "create_agent",
    "get_application_info",
    "validate_application_config",
]

# Configuration globale de l'application
APPLICATION_INFO = {
    "name": "Agent IA de Cybersécurité",
    "version": __version__,
    "description": "Agent intelligent pour la détection et correction automatisée de vulnérabilités",
    "author": "Équipe Cybersécurité",
    "license": "MIT",
    "python_requires": ">=3.10",
    "components": {
        "core": "Modules de traitement principal",
        "api": "Interface REST",
        "database": "Persistance des données",
        "utils": "Utilitaires transversaux"
    }
}


# États de l'application
class ApplicationStatus:
    """États possibles de l'application"""
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    ERROR = "error"
    SHUTDOWN = "shutdown"


# Configuration par défaut de l'application
DEFAULT_APPLICATION_CONFIG = {
    "core": {
        "enable_collector": True,
        "enable_analyzer": True,
        "enable_generator": True,
        "enable_supervisor": True,
    },
    "api": {
        "enable_api": True,
        "host": "0.0.0.0",
        "port": 8000,
        "debug": False,
    },
    "database": {
        "auto_create_tables": True,
        "backup_enabled": True,
    },
    "logging": {
        "level": "INFO",
        "enable_file_logging": True,
        "enable_console_logging": True,
    },
    "security": {
        "enable_authentication": False,  # Pour le PoC
        "enable_rate_limiting": True,
        "max_concurrent_scans": 3,
    }
}


# === FONCTIONS PRINCIPALES ===

def get_application_info() -> dict:
    """
    Retourne les informations de l'application

    Returns:
        dict: Informations complètes de l'application
    """
    return APPLICATION_INFO.copy()


def get_version() -> str:
    """
    Retourne la version de l'application

    Returns:
        str: Version de l'application
    """
    return __version__


def validate_application_config(config: dict) -> bool:
    """
    Valide la configuration de l'application

    Args:
        config: Configuration à valider

    Returns:
        bool: True si la configuration est valide

    Raises:
        ValueError: Si la configuration est invalide
    """
    required_sections = ["core", "api", "database", "logging"]

    for section in required_sections:
        if section not in config:
            raise ValueError(f"Section de configuration manquante: {section}")

    # Validation spécifique par section
    _validate_core_config(config["core"])
    _validate_api_config(config["api"])
    _validate_database_config(config["database"])
    _validate_logging_config(config["logging"])

    return True


def _validate_core_config(config: dict) -> bool:
    """Valide la configuration des modules core"""
    required_modules = ["enable_collector", "enable_analyzer", "enable_generator", "enable_supervisor"]

    for module in required_modules:
        if module not in config:
            raise ValueError(f"Configuration core manquante: {module}")

        if not isinstance(config[module], bool):
            raise ValueError(f"Configuration {module} doit être un booléen")

    return True


def _validate_api_config(config: dict) -> bool:
    """Valide la configuration de l'API"""
    if "port" in config:
        port = config["port"]
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError("Port API invalide (doit être entre 1 et 65535)")

    if "host" in config:
        host = config["host"]
        if not isinstance(host, str) or not host:
            raise ValueError("Host API invalide")

    return True


def _validate_database_config(config: dict) -> bool:
    """Valide la configuration de la base de données"""
    if "auto_create_tables" in config:
        if not isinstance(config["auto_create_tables"], bool):
            raise ValueError("auto_create_tables doit être un booléen")

    return True


def _validate_logging_config(config: dict) -> bool:
    """Valide la configuration du logging"""
    if "level" in config:
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if config["level"] not in valid_levels:
            raise ValueError(f"Niveau de log invalide. Valides: {valid_levels}")

    return True


def create_agent(config: dict = None) -> Supervisor:
    """
    Factory principal pour créer un agent complet

    Args:
        config: Configuration personnalisée (optionnel)

    Returns:
        Supervisor: Instance de l'agent configuré

    Raises:
        ValueError: Si la configuration est invalide
        Exception: Si la création échoue
    """
    # Utiliser la configuration par défaut si non fournie
    if config is None:
        config = DEFAULT_APPLICATION_CONFIG.copy()
    else:
        # Merger avec la configuration par défaut
        merged_config = DEFAULT_APPLICATION_CONFIG.copy()
        for section, section_config in config.items():
            if section in merged_config:
                merged_config[section].update(section_config)
            else:
                merged_config[section] = section_config
        config = merged_config

    # Valider la configuration
    validate_application_config(config)

    # Créer le superviseur (agent principal)
    supervisor = create_supervisor(config.get("core", {}))

    return supervisor


def check_dependencies() -> dict:
    """
    Vérifie toutes les dépendances de l'application

    Returns:
        dict: Statut des dépendances par catégorie
    """
    dependencies = {
        "system": {},
        "python_packages": {},
        "external_tools": {},
        "services": {}
    }

    # Vérifier les dépendances système
    import platform
    dependencies["system"] = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.architecture()[0]
    }

    # Vérifier les packages Python
    python_deps = [
        "nmap", "openai", "requests", "fastapi", "uvicorn",
        "pydantic", "sqlite3", "asyncio", "pathlib"
    ]

    for dep in python_deps:
        try:
            __import__(dep)
            dependencies["python_packages"][dep] = "available"
        except ImportError:
            dependencies["python_packages"][dep] = "missing"

    # Vérifier les outils externes
    import shutil
    external_tools = ["nmap", "curl", "wget"]

    for tool in external_tools:
        dependencies["external_tools"][tool] = "available" if shutil.which(tool) else "missing"

    # Vérifier les services (optionnels)
    dependencies["services"] = {
        "openai_api": "unknown",  # Nécessite une clé API pour tester
        "database": "available"  # SQLite est intégré
    }

    return dependencies


def get_application_status() -> dict:
    """
    Retourne le statut global de l'application

    Returns:
        dict: Statut complet de l'application
    """
    dependencies = check_dependencies()

    # Calculer le statut global
    missing_critical = []

    # Vérifier les dépendances critiques
    critical_packages = ["nmap", "openai", "requests", "fastapi"]
    for package in critical_packages:
        if dependencies["python_packages"].get(package) == "missing":
            missing_critical.append(f"python:{package}")

    critical_tools = ["nmap"]
    for tool in critical_tools:
        if dependencies["external_tools"].get(tool) == "missing":
            missing_critical.append(f"tool:{tool}")

    # Déterminer le statut
    if missing_critical:
        status = ApplicationStatus.ERROR
        message = f"Dépendances critiques manquantes: {', '.join(missing_critical)}"
    else:
        status = ApplicationStatus.READY
        message = "Application prête"

    return {
        "status": status,
        "message": message,
        "version": __version__,
        "dependencies": dependencies,
        "missing_critical": missing_critical,
        "components_available": {
            "core": True,
            "api": dependencies["python_packages"].get("fastapi") == "available",
            "database": dependencies["python_packages"].get("sqlite3") == "available",
            "utils": True
        }
    }


def print_application_banner():
    """Affiche la bannière de l'application"""
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        🛡️  Agent IA de Cybersécurité v{__version__}                ║
║                                                              ║
║  🔍 Détection automatique de vulnérabilités                 ║
║  🧠 Analyse intelligente par IA                             ║
║  🔧 Génération de scripts de correction                     ║
║  🚀 Interface API REST intégrée                             ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_quick_start():
    """Affiche le guide de démarrage rapide"""
    print("""
🚀 Démarrage rapide :

1. Configuration :
   cp .env.example .env
   # Configurer votre clé OpenAI dans .env

2. Lancement :
   python main.py --target 192.168.1.100 --scan

3. Interface API :
   python main.py --api
   # Documentation : http://localhost:8000/docs

4. Exemples d'usage :
   # Scan simple
   python main.py --target example.com --scan-type quick

   # Workflow complet
   python main.py --target 192.168.1.1 --full-workflow

   # API uniquement
   python main.py --api --port 8080

📚 Documentation complète : README.md
🆘 Aide : python main.py --help
""")


# === INITIALISATION DU PACKAGE ===

def _initialize_package():
    """Initialisation du package src au chargement"""
    try:
        # Vérifier les dépendances critiques
        status = get_application_status()

        if status["status"] == ApplicationStatus.ERROR:
            import warnings
            warnings.warn(
                f"Application non prête: {status['message']}\n"
                f"Dépendances manquantes: {', '.join(status['missing_critical'])}"
            )

        # Configuration du logging de base
        import logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        logger = logging.getLogger(__name__)
        logger.info(f"Package src initialisé - version {__version__}")

    except Exception as e:
        import warnings
        warnings.warn(f"Erreur lors de l'initialisation du package src: {e}")


# Exécuter l'initialisation au chargement
_initialize_package()

# === INFORMATIONS DE DEBUG ===

if __name__ == "__main__":
    # Affichage des informations de debug
    print_application_banner()

    print("📊 Informations de l'application:")
    app_info = get_application_info()
    for key, value in app_info.items():
        if key != "components":
            print(f"  {key}: {value}")

    print("\n🧩 Composants:")
    for component, description in app_info["components"].items():
        print(f"  {component}: {description}")

    print("\n🔍 Statut de l'application:")
    status = get_application_status()
    print(f"  Statut: {status['status']}")
    print(f"  Message: {status['message']}")

    print("\n📦 Dépendances:")
    deps = status["dependencies"]

    print("  Packages Python:")
    for package, status_pkg in deps["python_packages"].items():
        status_icon = "✅" if status_pkg == "available" else "❌"
        print(f"    {status_icon} {package}")

    print("  Outils externes:")
    for tool, status_tool in deps["external_tools"].items():
        status_icon = "✅" if status_tool == "available" else "❌"
        print(f"    {status_icon} {tool}")

    if status["missing_critical"]:
        print(f"\n⚠️  Dépendances critiques manquantes: {', '.join(status['missing_critical'])}")
        print("   Exécutez: ./scripts/install.sh")
    else:
        print("\n✅ Toutes les dépendances critiques sont disponibles!")
        print_quick_start()