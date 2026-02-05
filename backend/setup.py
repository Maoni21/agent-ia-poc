#!/usr/bin/env python3
"""
Setup.py pour l'Agent IA de Cybersécurité

Configuration d'installation et de distribution du package pour
l'agent intelligent de détection et correction automatisée de vulnérabilités.

Fonctionnalités :
- Installation des dépendances système et Python
- Configuration des entry points pour CLI
- Définition des extras pour développement et production
- Scripts post-installation pour configuration initiale
- Support multi-plateforme (Linux, macOS, Windows)

Usage:
    # Installation standard
    pip install .

    # Installation avec dépendances développement
    pip install .[dev]

    # Installation avec toutes les fonctionnalités
    pip install .[full]

    # Installation en mode éditable pour développement
    pip install -e .[dev]
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
from setuptools import setup, find_packages, Command
from setuptools.command.develop import develop
from setuptools.command.install import install

# === INFORMATIONS DU PACKAGE ===

PACKAGE_NAME = "vulnerability-agent-ia"
VERSION = "1.0.0"
DESCRIPTION = "Agent IA pour la détection et correction automatisée de vulnérabilités de cybersécurité"
LONG_DESCRIPTION = """
# Agent IA de Cybersécurité

Un agent intelligent basé sur l'IA pour automatiser la détection, l'analyse et la correction 
de vulnérabilités de sécurité dans les systèmes d'information.

## Fonctionnalités Principales

### 🔍 **Détection Automatisée**
- Scan de vulnérabilités avec Nmap et scripts NSE
- Import de rapports existants (OpenVAS, Tenable, Nessus)
- Détection de services et versions
- Identification des CVE et scoring CVSS

### 🧠 **Analyse IA Avancée**
- Analyse contextuelle avec GPT-4 ou modèles locaux
- Priorisation intelligente basée sur risque business
- Corrélation automatique des vulnérabilités
- Génération de plans de remédiation

### 🔧 **Correction Automatisée**
- Génération de scripts bash sécurisés
- Validation automatique de sécurité
- Scripts de rollback automatiques
- Templates prédéfinis pour vulnérabilités courantes

### 🚀 **Interface Unifiée**
- CLI puissant avec workflows prédéfinis
- API REST avec documentation OpenAPI
- Interface web intuitive (optionnel)
- Intégration Docker et Kubernetes

## Installation Rapide

```bash
# Installation avec pip
pip install vulnerability-agent-ia

# Configuration initiale
vulnerability-agent setup --api-key YOUR_OPENAI_KEY

# Premier scan
vulnerability-agent scan --target 192.168.1.1 --type full
```

## Architecture

Le projet suit une architecture modulaire :
- **Collector** : Scan et collecte de vulnérabilités
- **Analyzer** : Analyse IA et priorisation
- **Generator** : Génération de scripts de correction
- **Supervisor** : Orchestration des workflows

## Prérequis Système

- Python 3.10+
- Nmap 7.80+
- 4GB RAM minimum
- 1GB espace disque

## Licence

MIT License - Voir LICENSE pour les détails.
"""

AUTHOR = "Équipe Cybersécurité"
AUTHOR_EMAIL = "security@company.com"
URL = "https://github.com/company/vulnerability-agent-ia"
LICENSE = "MIT"

KEYWORDS = [
    "cybersecurity", "vulnerability", "security", "nmap", "ai", "gpt",
    "penetration-testing", "security-scanner", "automation", "devops"
]

CLASSIFIERS = [
    # Statut de développement
    "Development Status :: 4 - Beta",

    # Audience
    "Intended Audience :: System Administrators",
    "Intended Audience :: Information Technology",
    "Intended Audience :: Developers",

    # Sujet
    "Topic :: System :: Systems Administration",
    "Topic :: Security",
    "Topic :: System :: Networking :: Monitoring",
    "Topic :: Software Development :: Libraries :: Python Modules",

    # Licence
    "License :: OSI Approved :: MIT License",

    # Versions Python supportées
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",

    # OS supportés
    "Operating System :: POSIX :: Linux",
    "Operating System :: MacOS",
    "Operating System :: Microsoft :: Windows",

    # Type d'application
    "Environment :: Console",
    "Environment :: Web Environment",
]

# === DÉPENDANCES ===

# Dépendances de base requises
INSTALL_REQUIRES = [
    # Core dependencies
    "python-nmap>=0.7.1",
    "openai>=1.0.0",
    "requests>=2.28.0",
    "asyncio>=3.4.3",

    # Configuration et validation
    "pydantic>=2.0.0",
    "python-dotenv>=1.0.0",
    "click>=8.0.0",

    # Base de données
    "sqlite-utils>=3.30",

    # Parsing et data
    "lxml>=4.9.0",
    "xmltodict>=0.13.0",
    "beautifulsoup4>=4.11.0",

    # Crypto et sécurité
    "cryptography>=40.0.0",
    "hashlib",

    # Logging et monitoring
    "colorlog>=6.7.0",

    # Date et temps
    "python-dateutil>=2.8.0",

    # Réseau
    "ipaddress",
    "validators>=0.20.0",

    # Utilitaires
    "pathlib",
    "uuid",
    "json5>=0.9.0",
]

# Dépendances optionnelles pour l'API REST
API_REQUIRES = [
    "fastapi>=0.100.0",
    "uvicorn[standard]>=0.22.0",
    "jinja2>=3.1.0",
    "python-multipart>=0.0.6",
]

# Dépendances optionnelles pour l'interface web
WEB_REQUIRES = [
    "streamlit>=1.25.0",
    "plotly>=5.15.0",
    "pandas>=2.0.0",
    "numpy>=1.24.0",
]

# Dépendances pour le développement
DEV_REQUIRES = [
    # Tests
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-asyncio>=0.21.0",
    "pytest-mock>=3.11.0",
    "pytest-html>=3.2.0",

    # Linting et formatage
    "black>=23.0.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.5.0",
    "pylint>=2.17.0",

    # Sécurité
    "bandit>=1.7.0",
    "safety>=2.3.0",
    "pip-audit>=2.6.0",

    # Documentation
    "sphinx>=7.1.0",
    "sphinx-rtd-theme>=1.3.0",
    "myst-parser>=2.0.0",

    # Développement
    "pre-commit>=3.3.0",
    "tox>=4.6.0",
    "coverage>=7.2.0",
]

# Dépendances pour modèles IA locaux (Ollama)
LOCAL_AI_REQUIRES = [
    "ollama>=0.1.0",
    "transformers>=4.30.0",
    "torch>=2.0.0",
    "accelerate>=0.20.0",
]

# Dépendances pour production
PROD_REQUIRES = [
    "gunicorn>=21.0.0",
    "redis>=4.6.0",
    "psycopg2-binary>=2.9.0",
    "celery>=5.3.0",
]

# === ENTRY POINTS ===

CONSOLE_SCRIPTS = [
    "vulnerability-agent=src.main:main",
    "vuln-agent=src.main:main",
    "va=src.main:main",
]

GUI_SCRIPTS = [
    "vulnerability-agent-gui=src.api.main:main",
]


# === COMMANDES PERSONNALISÉES ===

class PostInstallCommand(install):
    """Commande post-installation personnalisée"""

    def run(self):
        install.run(self)
        self.execute(self._post_install, [], msg="Exécution des tâches post-installation")

    def _post_install(self):
        """Tâches à exécuter après installation"""
        print("\n" + "=" * 60)
        print("🛡️  Installation de l'Agent IA de Cybersécurité terminée!")
        print("=" * 60)

        # Créer les répertoires nécessaires
        self._create_directories()

        # Vérifier les dépendances système
        self._check_system_dependencies()

        # Configurer les permissions
        self._setup_permissions()

        # Afficher les instructions de configuration
        self._display_setup_instructions()

    def _create_directories(self):
        """Crée les répertoires nécessaires"""
        print("📁 Création des répertoires...")

        directories = [
            Path.home() / ".vulnerability_agent",
            Path.home() / ".vulnerability_agent" / "data",
            Path.home() / ".vulnerability_agent" / "logs",
            Path.home() / ".vulnerability_agent" / "config",
            Path.home() / ".vulnerability_agent" / "scripts",
        ]

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            print(f"  ✓ {directory}")

    def _check_system_dependencies(self):
        """Vérifie les dépendances système"""
        print("🔍 Vérification des dépendances système...")

        dependencies = {
            "nmap": "nmap --version",
            "curl": "curl --version",
            "git": "git --version",
        }

        missing = []
        for dep, command in dependencies.items():
            try:
                subprocess.run(
                    command.split(),
                    capture_output=True,
                    check=True
                )
                print(f"  ✓ {dep}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"  ❌ {dep} (non trouvé)")
                missing.append(dep)

        if missing:
            print(f"\n⚠️  Dépendances manquantes: {', '.join(missing)}")
            self._show_install_instructions(missing)

    def _show_install_instructions(self, missing_deps):
        """Affiche les instructions d'installation des dépendances"""
        system = platform.system().lower()

        if "nmap" in missing_deps:
            if system == "linux":
                print("   sudo apt-get install nmap  # Ubuntu/Debian")
                print("   sudo yum install nmap      # CentOS/RHEL")
            elif system == "darwin":
                print("   brew install nmap")
            elif system == "windows":
                print("   Téléchargez depuis https://nmap.org/download.html")

        if "curl" in missing_deps:
            if system == "linux":
                print("   sudo apt-get install curl")
            elif system == "darwin":
                print("   brew install curl")

    def _setup_permissions(self):
        """Configure les permissions nécessaires"""
        print("🔐 Configuration des permissions...")

        if platform.system().lower() == "linux":
            # Vérifier si l'utilisateur peut exécuter nmap
            try:
                subprocess.run(
                    ["nmap", "-sn", "127.0.0.1"],
                    capture_output=True,
                    check=True,
                    timeout=10
                )
                print("  ✓ Permissions Nmap OK")
            except subprocess.CalledProcessError:
                print("  ⚠️  Permissions Nmap limitées (certaines fonctions nécessitent sudo)")
            except subprocess.TimeoutExpired:
                print("  ⚠️  Timeout test Nmap")

    def _display_setup_instructions(self):
        """Affiche les instructions de configuration"""
        print("\n🚀 Configuration initiale :")
        print("1. Copiez votre clé API OpenAI :")
        print("   vulnerability-agent config --openai-key YOUR_API_KEY")
        print("\n2. Premier test :")
        print("   vulnerability-agent scan --target 127.0.0.1 --type quick")
        print("\n3. Aide complète :")
        print("   vulnerability-agent --help")
        print("\n📖 Documentation : https://github.com/company/vulnerability-agent-ia")
        print("=" * 60 + "\n")


class PostDevelopCommand(develop):
    """Commande post-développement personnalisée"""

    def run(self):
        develop.run(self)
        self.execute(self._post_develop, [], msg="Configuration environnement de développement")

    def _post_develop(self):
        """Configuration pour l'environnement de développement"""
        print("🔧 Configuration environnement de développement...")

        # Créer les hooks pre-commit
        try:
            subprocess.run(["pre-commit", "install"], check=True)
            print("  ✓ Hooks pre-commit installés")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("  ⚠️  pre-commit non trouvé, hooks non installés")

        # Créer le fichier .env de développement
        env_file = Path(".env.dev")
        if not env_file.exists():
            env_content = """# Configuration développement
DEBUG=true
LOG_LEVEL=DEBUG
OPENAI_API_KEY=your_openai_api_key_here
DATABASE_PATH=./data/database/dev_vulnerability_agent.db
ENABLE_API=true
API_HOST=127.0.0.1
API_PORT=8000
"""
            env_file.write_text(env_content)
            print(f"  ✓ Fichier {env_file} créé")


class CleanCommand(Command):
    """Commande de nettoyage personnalisée"""
    description = "Nettoie les fichiers de build et cache"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Nettoie les fichiers temporaires"""
        import shutil
        import glob

        print("🧹 Nettoyage en cours...")

        # Répertoires à nettoyer
        dirs_to_clean = [
            "build/",
            "dist/",
            "*.egg-info/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
            "htmlcov/",
        ]

        # Fichiers à nettoyer
        files_to_clean = [
            "*.pyc",
            "*.pyo",
            "*.pyd",
            ".coverage",
            "coverage.xml",
            "pytest.xml",
        ]

        cleaned_items = []

        # Nettoyer les répertoires
        for pattern in dirs_to_clean:
            for path in glob.glob(pattern, recursive=True):
                if os.path.exists(path):
                    shutil.rmtree(path)
                    cleaned_items.append(path)

        # Nettoyer les fichiers
        for pattern in files_to_clean:
            for path in glob.glob(pattern, recursive=True):
                if os.path.exists(path):
                    os.remove(path)
                    cleaned_items.append(path)

        if cleaned_items:
            print(f"  ✓ {len(cleaned_items)} éléments nettoyés")
        else:
            print("  ✓ Aucun fichier à nettoyer")


class TestCommand(Command):
    """Commande de test personnalisée"""
    description = "Lance les tests avec options avancées"
    user_options = [
        ('coverage', None, 'Génère un rapport de couverture'),
        ('html', None, 'Génère un rapport HTML'),
        ('benchmark', None, 'Inclut les tests de performance'),
    ]

    def initialize_options(self):
        self.coverage = False
        self.html = False
        self.benchmark = False

    def finalize_options(self):
        pass

    def run(self):
        """Lance les tests avec les options spécifiées"""
        import pytest

        args = ["-v"]

        if self.coverage:
            args.extend(["--cov=src", "--cov-report=term-missing"])

        if self.html:
            args.extend(["--cov-report=html", "--html=test_reports/report.html", "--self-contained-html"])

        if self.benchmark:
            args.append("--benchmark")

        # Ajouter le répertoire de tests
        args.append("tests/")

        print(f"🧪 Lancement des tests: pytest {' '.join(args)}")
        exit_code = pytest.main(args)
        sys.exit(exit_code)


# === DÉTECTION DES FICHIERS ===

def get_package_data():
    """Récupère les fichiers de données du package"""
    package_data = {
        'src': [
            'config/*.json',
            'config/*.yaml',
            'database/*.sql',
            'templates/*.html',
            'templates/*.css',
            'templates/*.js',
        ]
    }
    return package_data


def get_data_files():
    """Récupère les fichiers de données à installer"""
    data_files = []

    # Fichiers de configuration système
    if platform.system().lower() == "linux":
        data_files.extend([
            ('/etc/vulnerability-agent/', ['config/agent.conf']),
            ('/usr/share/vulnerability-agent/templates/', ['templates/*.html']),
        ])

    return data_files


# === VÉRIFICATIONS PRÉALABLES ===

def check_python_version():
    """Vérifie la version Python"""
    if sys.version_info < (3, 10):
        print("❌ Python 3.10 ou supérieur requis")
        print(f"   Version actuelle: {sys.version}")
        sys.exit(1)


def check_platform_support():
    """Vérifie que la plateforme est supportée"""
    supported_platforms = ["linux", "darwin", "win32"]
    if sys.platform not in supported_platforms:
        print(f"⚠️  Plateforme non officiellement supportée: {sys.platform}")
        print("   L'installation peut ne pas fonctionner correctement")


def pre_install_checks():
    """Vérifications avant installation"""
    print("🔍 Vérifications préalables...")
    check_python_version()
    check_platform_support()
    print("✓ Vérifications réussies\n")


# === CONFIGURATION PRINCIPALE ===

def main_setup():
    """Configuration principale du setup"""

    # Vérifications préalables
    pre_install_checks()

    # Définir les extras
    extras_require = {
        "api": API_REQUIRES,
        "web": WEB_REQUIRES,
        "dev": DEV_REQUIRES,
        "local-ai": LOCAL_AI_REQUIRES,
        "prod": PROD_REQUIRES,
        "full": API_REQUIRES + WEB_REQUIRES + LOCAL_AI_REQUIRES,
        "all": API_REQUIRES + WEB_REQUIRES + DEV_REQUIRES + LOCAL_AI_REQUIRES + PROD_REQUIRES,
    }

    setup(
        # === INFORMATIONS DE BASE ===
        name=PACKAGE_NAME,
        version=VERSION,
        description=DESCRIPTION,
        long_description=LONG_DESCRIPTION,
        long_description_content_type="text/markdown",

        # === AUTEUR ET LICENCE ===
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        maintainer=AUTHOR,
        maintainer_email=AUTHOR_EMAIL,
        url=URL,
        license=LICENSE,

        # === CLASSIFICATION ===
        keywords=KEYWORDS,
        classifiers=CLASSIFIERS,

        # === STRUCTURE DU PROJET ===
        packages=find_packages(exclude=["tests", "tests.*", "docs", "docs.*"]),
        package_data=get_package_data(),
        data_files=get_data_files(),
        include_package_data=True,
        zip_safe=False,

        # === DÉPENDANCES ===
        python_requires=">=3.10",
        install_requires=INSTALL_REQUIRES,
        extras_require=extras_require,

        # === ENTRY POINTS ===
        entry_points={
            "console_scripts": CONSOLE_SCRIPTS,
            "gui_scripts": GUI_SCRIPTS,
        },

        # === COMMANDES PERSONNALISÉES ===
        cmdclass={
            "install": PostInstallCommand,
            "develop": PostDevelopCommand,
            "clean": CleanCommand,
            "test": TestCommand,
        },

        # === MÉTADONNÉES SUPPLÉMENTAIRES ===
        project_urls={
            "Documentation": f"{URL}/wiki",
            "Source Code": URL,
            "Bug Tracker": f"{URL}/issues",
            "Changelog": f"{URL}/blob/main/CHANGELOG.md",
            "Funding": f"{URL}/sponsors",
        },

        # === OPTIONS DE BUILD ===
        options={
            "build_py": {
                "compile": True,
                "optimize": 2,
            },
            "bdist_wheel": {
                "universal": False,
            },
        },
    )


if __name__ == "__main__":
    main_setup()