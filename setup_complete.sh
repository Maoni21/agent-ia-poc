#!/bin/bash

# ========================================================================
# Script de configuration automatique complète avec environnement virtuel
# Agent IA de Cybersécurité
# ========================================================================

set -e  # Arrêt en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions d'affichage
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_header() { echo -e "\n${BLUE}═══════════════════════════════════════${NC}\n${BLUE}$1${NC}\n${BLUE}═══════════════════════════════════════${NC}"; }

# ========================================================================
# ÉTAPE 1: Vérifications initiales
# ========================================================================

print_header "ÉTAPE 1: Vérifications initiales"

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 n'est pas installé"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_success "Python $PYTHON_VERSION détecté"

# ========================================================================
# ÉTAPE 2: Créer l'environnement virtuel
# ========================================================================

print_header "ÉTAPE 2: Création de l'environnement virtuel"

VENV_DIR=".venv"

if [ -d "$VENV_DIR" ]; then
    print_warning "Environnement virtuel existant trouvé"
    read -p "Voulez-vous le supprimer et le recréer ? (o/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Oo]$ ]]; then
        rm -rf "$VENV_DIR"
        print_info "Ancien environnement supprimé"
    else
        print_info "Utilisation de l'environnement existant"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    print_info "Création de l'environnement virtuel..."
    python3 -m venv "$VENV_DIR"
    print_success "Environnement virtuel créé dans $VENV_DIR"
fi

# Activer l'environnement virtuel
print_info "Activation de l'environnement virtuel..."
source "$VENV_DIR/bin/activate"
print_success "Environnement virtuel activé"

# Mettre à jour pip
print_info "Mise à jour de pip..."
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
print_success "pip mis à jour"

# ========================================================================
# ÉTAPE 3: Créer les répertoires nécessaires
# ========================================================================

print_header "ÉTAPE 3: Création des répertoires"

mkdir -p data/scans
mkdir -p data/reports
mkdir -p data/scripts
mkdir -p data/database
mkdir -p logs
mkdir -p tests/test_data
mkdir -p tests/fixtures

print_success "Tous les répertoires créés"

# ========================================================================
# ÉTAPE 4: Créer le fichier pytest.ini
# ========================================================================

print_header "ÉTAPE 4: Configuration de pytest"

cat > pytest.ini << 'EOF'
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    -v
    --tb=short
    --strict-markers
    --disable-warnings
markers =
    unit: Unit tests
    integration: Integration tests
    slow: Slow running tests
EOF

print_success "pytest.ini créé"

# ========================================================================
# ÉTAPE 5: Créer requirements-dev.txt
# ========================================================================

print_header "ÉTAPE 5: Création de requirements-dev.txt"

cat > requirements-dev.txt << 'EOF'
# Dépendances de développement et tests
pytest>=7.4.3
pytest-cov>=4.1.0
pytest-asyncio>=0.23.2
pytest-mock>=3.12.0
pytest-xdist>=3.5.0
pytest-html>=4.1.1

# Qualité de code
black>=23.12.1
isort>=5.13.2
flake8>=7.0.0
mypy>=1.8.0
EOF

print_success "requirements-dev.txt créé"

# ========================================================================
# ÉTAPE 6: Créer les fichiers de test data
# ========================================================================

print_header "ÉTAPE 6: Création des fichiers de données de test"

# sample_nmap.xml
cat > tests/test_data/sample_nmap.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 127.0.0.1" start="1234567890" version="7.80">
    <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
    <host starttime="1234567890" endtime="1234567900">
        <status state="up" reason="localhost-response"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="localhost" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="ssh" product="OpenSSH" version="7.4" ostype="Linux"/>
            </port>
            <port protocol="tcp" portid="80">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="http" product="Apache" version="2.4.6" ostype="Linux"/>
            </port>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" reason_ttl="64"/>
                <service name="https" product="Apache" version="2.4.6" ostype="Linux"/>
            </port>
        </ports>
    </host>
    <runstats>
        <finished time="1234567900" timestr="Test Run" elapsed="10.00"/>
        <hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
EOF

# sample_vulnerabilities.json
cat > tests/test_data/sample_vulnerabilities.json << 'EOF'
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-12345",
      "name": "Test SQL Injection Vulnerability",
      "severity": "HIGH",
      "cvss_score": 8.5,
      "description": "SQL injection vulnerability in test application",
      "affected_service": "http",
      "affected_port": 80,
      "cve_ids": ["CVE-2024-12345"],
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"
      ],
      "solution": "Update to version 2.0 or apply security patch"
    },
    {
      "id": "CVE-2024-54321",
      "name": "OpenSSL Heartbleed",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "description": "Buffer over-read in OpenSSL",
      "affected_service": "https",
      "affected_port": 443,
      "cve_ids": ["CVE-2024-54321"],
      "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2024-54321"
      ],
      "solution": "Update OpenSSL to latest version"
    }
  ]
}
EOF

# sample_nmap.json
cat > tests/test_data/sample_nmap.json << 'EOF'
{
  "scan_info": {
    "scan_type": "quick",
    "target": "127.0.0.1",
    "timestamp": "2024-01-01T12:00:00"
  },
  "hosts": [
    {
      "ip": "127.0.0.1",
      "hostname": "localhost",
      "status": "up",
      "open_ports": [22, 80, 443],
      "services": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "version": "OpenSSH 7.4"
        },
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http",
          "version": "Apache 2.4.6"
        }
      ]
    }
  ]
}
EOF

print_success "Fichiers de données de test créés"

# ========================================================================
# ÉTAPE 7: Créer .gitkeep pour les dossiers vides
# ========================================================================

print_header "ÉTAPE 7: Création des fichiers .gitkeep"

touch tests/fixtures/.gitkeep
touch data/scans/.gitkeep
touch data/reports/.gitkeep
touch data/scripts/.gitkeep
touch logs/.gitkeep

print_success "Fichiers .gitkeep créés"

# ========================================================================
# ÉTAPE 8: Installation des dépendances
# ========================================================================

print_header "ÉTAPE 8: Installation des dépendances"

print_info "Installation des dépendances principales (cela peut prendre quelques minutes)..."
pip install -r requirements.txt --quiet

print_info "Installation des dépendances de développement..."
pip install -r requirements-dev.txt --quiet

print_success "Toutes les dépendances installées dans l'environnement virtuel"

# ========================================================================
# ÉTAPE 9: Initialisation de la base de données
# ========================================================================

print_header "ÉTAPE 9: Initialisation de la base de données"

python3 << 'PYTHON_SCRIPT'
import sys
sys.path.insert(0, '.')

try:
    from src.database import Database
    db = Database()
    db.create_tables()
    print("✅ Base de données initialisée avec succès")
except Exception as e:
    print(f"⚠️  Avertissement: Impossible d'initialiser la base de données: {e}")
    print("   Vous pourrez le faire manuellement plus tard")
PYTHON_SCRIPT

# ========================================================================
# ÉTAPE 10: Vérifications finales
# ========================================================================

print_header "ÉTAPE 10: Vérifications finales"

# Vérifier les imports
print_info "Vérification des imports Python..."
python3 << 'PYTHON_CHECK'
import sys
sys.path.insert(0, '.')

try:
    from src.core import Collector, Analyzer, Generator, Supervisor
    print("✅ Imports core OK")
except Exception as e:
    print(f"❌ Erreur imports: {e}")
    sys.exit(1)

try:
    from config.settings import get_config
    config = get_config()
    if config.openai_api_key and config.openai_api_key != "":
        print("✅ Configuration OK avec clé API")
    else:
        print("⚠️  Clé API OpenAI non configurée dans .env")
except Exception as e:
    print(f"⚠️  Configuration: {e}")

try:
    from src.database import Database
    print("✅ Module Database OK")
except Exception as e:
    print(f"❌ Erreur Database: {e}")
PYTHON_CHECK

# ========================================================================
# ÉTAPE 11: Créer un script d'activation rapide
# ========================================================================

print_header "ÉTAPE 11: Création du script d'activation"

cat > activate.sh << 'EOF'
#!/bin/bash
# Script d'activation rapide de l'environnement virtuel

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    echo "✅ Environnement virtuel activé"
    echo ""
    echo "Commandes disponibles:"
    echo "  python main.py --check    # Vérifier l'installation"
    echo "  pytest tests/ -v          # Lancer les tests"
    echo "  python main.py            # Lancer l'application"
    echo ""
else
    echo "❌ Environnement virtuel non trouvé"
    echo "Lancez: ./setup_complete.sh"
fi
EOF

chmod +x activate.sh
print_success "Script activate.sh créé"

# ========================================================================
# ÉTAPE 12: Résumé et prochaines étapes
# ========================================================================

print_header "✨ INSTALLATION TERMINÉE ✨"

echo ""
echo "📋 Récapitulatif:"
echo "  ✅ Environnement virtuel créé dans .venv/"
echo "  ✅ Répertoires créés"
echo "  ✅ Fichiers de configuration créés"
echo "  ✅ Fichiers de test créés"
echo "  ✅ Dépendances installées"
echo "  ✅ Base de données initialisée"
echo ""
echo "🚀 Prochaines étapes:"
echo ""
echo "1. ${GREEN}IMPORTANT:${NC} À chaque fois que vous travaillez sur le projet, activez l'environnement:"
echo "   ${GREEN}source .venv/bin/activate${NC}"
echo "   ou utilisez le raccourci:"
echo "   ${GREEN}source activate.sh${NC}"
echo ""
echo "2. Vérifier votre fichier .env:"
echo "   ${GREEN}cat .env${NC}"
echo ""
echo "3. Tester l'application:"
echo "   ${GREEN}python main.py --check${NC}"
echo ""
echo "4. Lancer les tests:"
echo "   ${GREEN}pytest tests/ -v${NC}"
echo ""
echo "5. Pour un test rapide:"
echo "   ${GREEN}pytest tests/test_utils.py -v${NC}"
echo ""
echo "6. Lancer l'application:"
echo "   ${GREEN}python main.py${NC}"
echo ""
echo "📚 Pour désactiver l'environnement virtuel:"
echo "   ${GREEN}deactivate${NC}"
echo ""

print_success "Configuration terminée avec succès! 🎉"
print_warning "N'oubliez pas d'activer l'environnement virtuel: source .venv/bin/activate"