#!/bin/bash

# Script d'installation pour Agent IA de Cybersécurité
# Version: 1.0.0
# Usage: chmod +x scripts/install.sh && ./scripts/install.sh

set -euo pipefail  # Arrêt immédiat en cas d'erreur

# === CONFIGURATION ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PYTHON_MIN_VERSION="3.10"
VENV_NAME=".venv"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# === FONCTIONS UTILITAIRES ===

print_header() {
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}" >&2
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Vérifier si une commande existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Comparer les versions Python
version_greater_equal() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# === VÉRIFICATIONS PRÉALABLES ===

check_system() {
    print_header "Vérification du système"

    # Détecter l'OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
        if command_exists apt-get; then
            PACKAGE_MANAGER="apt"
        elif command_exists yum; then
            PACKAGE_MANAGER="yum"
        elif command_exists dnf; then
            PACKAGE_MANAGER="dnf"
        elif command_exists pacman; then
            PACKAGE_MANAGER="pacman"
        else
            print_error "Gestionnaire de paquets non supporté"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        print_error "OS non supporté: $OSTYPE"
        exit 1
    fi

    print_success "OS détecté: $OS ($PACKAGE_MANAGER)"

    # Vérifier les privilèges si nécessaire
    if [[ "$OS" == "linux" ]] && [[ $EUID -eq 0 ]]; then
        print_warning "Script lancé en root. Recommandé de lancer en utilisateur normal."
    fi
}

check_python() {
    print_header "Vérification de Python"

    # Vérifier Python 3
    if ! command_exists python3; then
        print_error "Python 3 n'est pas installé"
        print_info "Installation de Python 3..."
        install_python
    fi

    # Vérifier la version
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    if ! version_greater_equal "$PYTHON_VERSION" "$PYTHON_MIN_VERSION"; then
        print_error "Python $PYTHON_MIN_VERSION+ requis, version actuelle: $PYTHON_VERSION"
        exit 1
    fi

    print_success "Python $PYTHON_VERSION OK"

    # Vérifier pip
    if ! python3 -m pip --version >/dev/null 2>&1; then
        print_error "pip n'est pas installé"
        print_info "Installation de pip..."
        install_pip
    fi

    print_success "pip OK"
}

# === INSTALLATION DES DÉPENDANCES SYSTÈME ===

install_system_packages() {
    print_header "Installation des dépendances système"

    case $PACKAGE_MANAGER in
        apt)
            print_info "Mise à jour des paquets..."
            sudo apt-get update -qq

            print_info "Installation des paquets système..."
            sudo apt-get install -y \
                nmap \
                git \
                curl \
                wget \
                build-essential \
                python3-dev \
                python3-pip \
                python3-venv \
                libffi-dev \
                libssl-dev
            ;;
        yum|dnf)
            print_info "Installation des paquets système..."
            sudo $PACKAGE_MANAGER install -y \
                nmap \
                git \
                curl \
                wget \
                gcc \
                python3-devel \
                python3-pip \
                openssl-devel \
                libffi-devel
            ;;
        brew)
            print_info "Installation via Homebrew..."
            brew install nmap python@3.11 git curl wget
            ;;
        pacman)
            print_info "Installation via pacman..."
            sudo pacman -S --noconfirm \
                nmap \
                git \
                curl \
                wget \
                python \
                python-pip \
                base-devel
            ;;
    esac

    print_success "Dépendances système installées"
}

install_python() {
    case $PACKAGE_MANAGER in
        apt)
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        yum|dnf)
            sudo $PACKAGE_MANAGER install -y python3 python3-pip
            ;;
        brew)
            brew install python@3.11
            ;;
        pacman)
            sudo pacman -S --noconfirm python python-pip
            ;;
    esac
}

install_pip() {
    if command_exists curl; then
        curl https://bootstrap.pypa.io/get-pip.py | python3
    elif command_exists wget; then
        wget -O - https://bootstrap.pypa.io/get-pip.py | python3
    else
        print_error "curl ou wget requis pour installer pip"
        exit 1
    fi
}

# === CONFIGURATION DE L'ENVIRONNEMENT VIRTUEL ===

setup_virtual_environment() {
    print_header "Configuration de l'environnement virtuel"

    cd "$PROJECT_ROOT"

    # Supprimer l'ancien venv s'il existe
    if [[ -d "$VENV_NAME" ]]; then
        print_warning "Suppression de l'ancien environnement virtuel..."
        rm -rf "$VENV_NAME"
    fi

    # Créer le nouvel environnement virtuel
    print_info "Création de l'environnement virtuel..."
    python3 -m venv "$VENV_NAME"

    # Activer l'environnement virtuel
    print_info "Activation de l'environnement virtuel..."
    source "$VENV_NAME/bin/activate"

    # Mise à jour de pip
    print_info "Mise à jour de pip..."
    pip install --upgrade pip setuptools wheel

    print_success "Environnement virtuel configuré"
}

# === INSTALLATION DES DÉPENDANCES PYTHON ===

install_python_dependencies() {
    print_header "Installation des dépendances Python"

    cd "$PROJECT_ROOT"
    source "$VENV_NAME/bin/activate"

    # Vérifier que requirements.txt existe
    if [[ ! -f "requirements.txt" ]]; then
        print_error "Fichier requirements.txt non trouvé"
        exit 1
    fi

    print_info "Installation des dépendances depuis requirements.txt..."
    pip install -r requirements.txt

    print_success "Dépendances Python installées"
}

# === CONFIGURATION DE L'APPLICATION ===

setup_application() {
    print_header "Configuration de l'application"

    cd "$PROJECT_ROOT"

    # Créer les répertoires nécessaires
    print_info "Création des répertoires..."
    mkdir -p data/{scans,reports,scripts,database}
    mkdir -p logs

    # Copier le fichier de configuration exemple
    if [[ -f ".env.example" ]] && [[ ! -f ".env" ]]; then
        print_info "Copie du fichier de configuration..."
        cp .env.example .env
        print_warning "Fichier .env créé. Veuillez le configurer avec vos clés API."
    fi

    # Initialiser la base de données
    print_info "Initialisation de la base de données..."
    source "$VENV_NAME/bin/activate"
    python -c "
from src.database.database import Database
db = Database()
db.create_tables()
print('Base de données initialisée')
" 2>/dev/null || print_warning "Impossible d'initialiser la base de données automatiquement"

    # Définir les permissions
    print_info "Configuration des permissions..."
    chmod +x main.py
    chmod -R 755 scripts/

    print_success "Application configurée"
}

# === TESTS DE FONCTIONNEMENT ===

run_tests() {
    print_header "Tests de fonctionnement"

    cd "$PROJECT_ROOT"
    source "$VENV_NAME/bin/activate"

    # Test d'import des modules principaux
    print_info "Test des imports Python..."
    python -c "
import sys
sys.path.append('.')
try:
    from config import get_config
    from src.core.collector import Collector
    from src.core.analyzer import Analyzer
    from src.core.generator import Generator
    print('✅ Tous les modules s\'importent correctement')
except ImportError as e:
    print(f'❌ Erreur d\\'import: {e}')
    sys.exit(1)
"

    # Test de Nmap
    print_info "Test de Nmap..."
    if command_exists nmap; then
        nmap --version | head -n1
        print_success "Nmap fonctionnel"
    else
        print_error "Nmap non trouvé"
    fi

    # Test de l'API (optionnel)
    if [[ "${RUN_API_TEST:-false}" == "true" ]]; then
        print_info "Test de l'API..."
        python main.py --test &
        PID=$!
        sleep 5
        if curl -f http://localhost:8000/health >/dev/null 2>&1; then
            print_success "API fonctionnelle"
        else
            print_warning "API non accessible (normal en mode test)"
        fi
        kill $PID 2>/dev/null || true
    fi
}

# === FINALISATION ===

finalize_installation() {
    print_header "Finalisation"

    # Créer un script d'activation rapide
    cat > "$PROJECT_ROOT/activate.sh" << 'EOF'
#!/bin/bash
# Script d'activation de l'environnement virtuel
source .venv/bin/activate
echo "Environnement virtuel activé"
echo "Usage: python main.py --help"
EOF
    chmod +x "$PROJECT_ROOT/activate.sh"

    print_success "Installation terminée avec succès !"

    # Afficher les instructions finales
    echo -e "\n${BOLD}${GREEN}🎉 Installation réussie !${NC}\n"
    echo -e "${BOLD}Prochaines étapes :${NC}"
    echo "1. Configurer votre fichier .env avec vos clés API"
    echo "2. Activer l'environnement virtuel : source .venv/bin/activate"
    echo "3. Ou utiliser le script : ./activate.sh"
    echo "4. Lancer l'agent : python main.py --help"
    echo ""
    echo -e "${BOLD}Exemples d'usage :${NC}"
    echo "• Scan : python main.py --target 192.168.1.1 --scan"
    echo "• API : python main.py --api"
    echo "• Tests : ./scripts/run_tests.sh"
    echo ""
    if [[ ! -f ".env" ]] || grep -q "your_openai_api_key_here" .env 2>/dev/null; then
        echo -e "${YELLOW}⚠️  N'oubliez pas de configurer votre clé OpenAI dans le fichier .env${NC}"
    fi
}

# === FONCTION PRINCIPALE ===

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║        Agent IA de Cybersécurité - Install      ║"
    echo "║                   Version 1.0.0                 ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    # Vérifications préalables
    check_system
    check_python

    # Installation
    install_system_packages
    setup_virtual_environment
    install_python_dependencies
    setup_application

    # Tests
    run_tests

    # Finalisation
    finalize_installation
}

# === GESTION DES ERREURS ===

cleanup() {
    print_error "Installation interrompue"
    exit 1
}

trap cleanup SIGINT SIGTERM

# === LANCEMENT ===

# Vérifier si le script est dans le bon répertoire
if [[ ! -f "$PROJECT_ROOT/main.py" ]]; then
    print_error "Script lancé depuis le mauvais répertoire"
    print_info "Lancez depuis la racine du projet : ./scripts/install.sh"
    exit 1
fi

# Options de ligne de commande
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            export INSTALL_DEV_DEPS=true
            shift
            ;;
        --test-api)
            export RUN_API_TEST=true
            shift
            ;;
        --force)
            export FORCE_INSTALL=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  --dev        Installer les dépendances de développement"
            echo "  --test-api   Tester l'API après installation"
            echo "  --force      Forcer la réinstallation"
            echo "  --help       Afficher cette aide"
            exit 0
            ;;
        *)
            print_error "Option inconnue: $1"
            exit 1
            ;;
    esac
done

# Lancer l'installation
main "$@"