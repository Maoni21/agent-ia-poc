#!/bin/bash

# Script de lancement des tests pour Agent IA de Cybersécurité
# Version: 1.0.0
# Usage: ./scripts/run_tests.sh [OPTIONS]

set -euo pipefail

# === CONFIGURATION ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PATH="$PROJECT_ROOT/.venv"
TESTS_DIR="$PROJECT_ROOT/tests"
COVERAGE_DIR="$PROJECT_ROOT/htmlcov"
REPORTS_DIR="$PROJECT_ROOT/test_reports"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Variables par défaut
RUN_UNIT_TESTS=true
RUN_INTEGRATION_TESTS=true
RUN_COVERAGE=true
RUN_LINTING=true
RUN_SECURITY_CHECKS=true
GENERATE_REPORT=true
VERBOSE=false
TEST_PATTERN="test_*.py"

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

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --unit-only      Exécuter uniquement les tests unitaires"
    echo "  --integration-only  Exécuter uniquement les tests d'intégration"
    echo "  --no-coverage    Désactiver la couverture de code"
    echo "  --no-lint        Désactiver le linting"
    echo "  --no-security    Désactiver les tests de sécurité"
    echo "  --no-report      Désactiver la génération de rapport"
    echo "  --pattern PATTERN  Pattern pour les fichiers de test (défaut: test_*.py)"
    echo "  --verbose        Mode verbeux"
    echo "  --quick          Tests rapides (unit + lint uniquement)"
    echo "  --ci             Mode CI/CD (optimisé pour intégration continue)"
    echo "  --help           Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                    # Tous les tests"
    echo "  $0 --quick           # Tests rapides"
    echo "  $0 --unit-only       # Tests unitaires seulement"
    echo "  $0 --ci              # Mode CI/CD"
}

# === PRÉPARATION DE L'ENVIRONNEMENT ===

setup_environment() {
    print_header "Préparation de l'environnement de test"

    # Vérifier que nous sommes dans le bon répertoire
    if [[ ! -f "$PROJECT_ROOT/main.py" ]]; then
        print_error "Script lancé depuis le mauvais répertoire"
        print_info "Lancez depuis la racine : ./scripts/run_tests.sh"
        exit 1
    fi

    # Activer l'environnement virtuel
    if [[ -f "$VENV_PATH/bin/activate" ]]; then
        source "$VENV_PATH/bin/activate"
        print_success "Environnement virtuel activé"
    else
        print_error "Environnement virtuel non trouvé: $VENV_PATH"
        print_info "Lancez d'abord: ./scripts/install.sh"
        exit 1
    fi

    # Créer les répertoires de rapports
    mkdir -p "$REPORTS_DIR"
    mkdir -p "$COVERAGE_DIR"

    # Installer les dépendances de test si nécessaires
    print_info "Vérification des dépendances de test..."
    pip install -q pytest pytest-cov pytest-xdist pytest-html black flake8 mypy bandit safety || {
        print_warning "Installation des dépendances de test..."
        pip install pytest pytest-cov pytest-xdist pytest-html black flake8 mypy bandit safety
    }

    print_success "Environnement préparé"
}

# === TESTS UNITAIRES ===

run_unit_tests() {
    print_header "Tests unitaires"

    local pytest_args=(
        "--tb=short"
        "--strict-markers"
        "--disable-warnings"
    )

    if [[ "$RUN_COVERAGE" == true ]]; then
        pytest_args+=(
            "--cov=src"
            "--cov-report=html:$COVERAGE_DIR"
            "--cov-report=xml:$REPORTS_DIR/coverage.xml"
            "--cov-report=term-missing"
            "--cov-fail-under=80"
        )
    fi

    if [[ "$VERBOSE" == true ]]; then
        pytest_args+=("-v")
    fi

    if [[ "$GENERATE_REPORT" == true ]]; then
        pytest_args+=(
            "--html=$REPORTS_DIR/unit_tests.html"
            "--self-contained-html"
        )
    fi

    # Exécuter les tests unitaires
    pytest_args+=("$TESTS_DIR" -k "not integration" --pattern="$TEST_PATTERN")

    print_info "Commande: pytest ${pytest_args[*]}"

    if pytest "${pytest_args[@]}"; then
        print_success "Tests unitaires réussis"
        return 0
    else
        print_error "Tests unitaires échoués"
        return 1
    fi
}

# === TESTS D'INTÉGRATION ===

run_integration_tests() {
    print_header "Tests d'intégration"

    # Vérifier les prérequis pour les tests d'intégration
    check_integration_prerequisites

    local pytest_args=(
        "--tb=short"
        "--disable-warnings"
        "-m" "integration"
    )

    if [[ "$VERBOSE" == true ]]; then
        pytest_args+=("-v")
    fi

    if [[ "$GENERATE_REPORT" == true ]]; then
        pytest_args+=(
            "--html=$REPORTS_DIR/integration_tests.html"
            "--self-contained-html"
        )
    fi

    print_info "Commande: pytest ${pytest_args[*]}"

    if pytest "${pytest_args[@]}" "$TESTS_DIR"; then
        print_success "Tests d'intégration réussis"
        return 0
    else
        print_error "Tests d'intégration échoués"
        return 1
    fi
}

check_integration_prerequisites() {
    print_info "Vérification des prérequis d'intégration..."

    # Vérifier Nmap
    if ! command -v nmap >/dev/null 2>&1; then
        print_warning "Nmap non installé - certains tests d'intégration peuvent échouer"
    fi

    # Vérifier les variables d'environnement pour les tests
    if [[ ! -f "$PROJECT_ROOT/.env" ]]; then
        print_info "Création d'un fichier .env de test..."
        cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env.test"
        export ENV_FILE="$PROJECT_ROOT/.env.test"
    fi

    # Créer une base de données de test
    export DATABASE_PATH="$PROJECT_ROOT/test_database.db"

    print_success "Prérequis vérifiés"
}

# === LINTING ET QUALITÉ DU CODE ===

run_linting() {
    print_header "Linting et qualité du code"

    local exit_code=0

    # Black - formatage du code
    print_info "Vérification du formatage avec Black..."
    if black --check --diff src/ tests/ config/; then
        print_success "Formatage Black OK"
    else
        print_error "Formatage Black échoué"
        print_info "Correction automatique : black src/ tests/ config/"
        exit_code=1
    fi

    # Flake8 - style du code
    print_info "Vérification du style avec Flake8..."
    if flake8 src/ tests/ config/ --max-line-length=88 --extend-ignore=E203,W503; then
        print_success "Style Flake8 OK"
    else
        print_error "Style Flake8 échoué"
        exit_code=1
    fi

    # MyPy - vérification des types
    print_info "Vérification des types avec MyPy..."
    if mypy src/ --ignore-missing-imports --no-strict-optional; then
        print_success "Types MyPy OK"
    else
        print_warning "Vérification des types échouée (non bloquant)"
    fi

    return $exit_code
}

# === TESTS DE SÉCURITÉ ===

run_security_checks() {
    print_header "Tests de sécurité"

    local exit_code=0

    # Bandit - analyse de sécurité du code
    print_info "Analyse de sécurité avec Bandit..."
    if bandit -r src/ -f json -o "$REPORTS_DIR/bandit_security.json" >/dev/null 2>&1; then
        print_success "Analyse Bandit OK"
    else
        print_warning "Problèmes de sécurité détectés par Bandit"
        print_info "Rapport détaillé : $REPORTS_DIR/bandit_security.json"
    fi

    # Safety - vérification des vulnérabilités des dépendances
    print_info "Vérification des dépendances avec Safety..."
    if safety check --json --output "$REPORTS_DIR/safety_report.json" >/dev/null 2>&1; then
        print_success "Dépendances Safety OK"
    else
        print_warning "Vulnérabilités détectées dans les dépendances"
        print_info "Rapport détaillé : $REPORTS_DIR/safety_report.json"
    fi

    # Audit pip
    print_info "Audit des packages pip..."
    pip-audit --format=json --output="$REPORTS_DIR/pip_audit.json" >/dev/null 2>&1 || {
        print_info "pip-audit non installé, installation..."
        pip install pip-audit
        pip-audit --format=json --output="$REPORTS_DIR/pip_audit.json" >/dev/null 2>&1 || \
            print_warning "Audit pip échoué"
    }

    return $exit_code
}

# === GÉNÉRATION DE RAPPORTS ===

generate_test_report() {
    print_header "Génération du rapport de test"

    local report_file="$REPORTS_DIR/test_summary.html"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Tests - Agent IA Cybersécurité</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f8ff; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport de Tests - Agent IA Cybersécurité</h1>
        <p class="timestamp">Généré le : $(date)</p>
        <p>Environnement : $(uname -a)</p>
        <p>Python : $(python --version)</p>
    </div>
EOF

    # Ajouter les sections selon ce qui a été exécuté
    if [[ "$RUN_UNIT_TESTS" == true ]]; then
        echo '<div class="section info"><h2>Tests Unitaires</h2>' >> "$report_file"
        if [[ -f "$REPORTS_DIR/unit_tests.html" ]]; then
            echo '<p><a href="unit_tests.html">Rapport détaillé des tests unitaires</a></p>' >> "$report_file"
        fi
        echo '</div>' >> "$report_file"
    fi

    if [[ "$RUN_COVERAGE" == true && -f "$COVERAGE_DIR/index.html" ]]; then
        echo '<div class="section info"><h2>Couverture de Code</h2>' >> "$report_file"
        echo '<p><a href="../htmlcov/index.html">Rapport de couverture détaillé</a></p>' >> "$report_file"

        # Extraire le pourcentage de couverture
        if [[ -f "$REPORTS_DIR/coverage.xml" ]]; then
            local coverage=$(grep -oP 'line-rate="\K[^"]*' "$REPORTS_DIR/coverage.xml" | head -1)
            local coverage_percent=$(python -c "print(f'{float('$coverage') * 100:.1f}%')" 2>/dev/null || echo "N/A")
            echo "<p>Couverture totale : <strong>$coverage_percent</strong></p>" >> "$report_file"
        fi
        echo '</div>' >> "$report_file"
    fi

    if [[ "$RUN_SECURITY_CHECKS" == true ]]; then
        echo '<div class="section info"><h2>Tests de Sécurité</h2>' >> "$report_file"
        echo '<ul>' >> "$report_file"
        [[ -f "$REPORTS_DIR/bandit_security.json" ]] && echo '<li><a href="bandit_security.json">Rapport Bandit</a></li>' >> "$report_file"
        [[ -f "$REPORTS_DIR/safety_report.json" ]] && echo '<li><a href="safety_report.json">Rapport Safety</a></li>' >> "$report_file"
        [[ -f "$REPORTS_DIR/pip_audit.json" ]] && echo '<li><a href="pip_audit.json">Audit pip</a></li>' >> "$report_file"
        echo '</ul></div>' >> "$report_file"
    fi

    echo '</body></html>' >> "$report_file"

    print_success "Rapport généré : $report_file"
}

# === NETTOYAGE ===

cleanup() {
    print_info "Nettoyage des fichiers temporaires..."

    # Supprimer les fichiers de test temporaires
    [[ -f "$PROJECT_ROOT/test_database.db" ]] && rm "$PROJECT_ROOT/test_database.db"
    [[ -f "$PROJECT_ROOT/.env.test" ]] && rm "$PROJECT_ROOT/.env.test"

    # Nettoyer le cache Python
    find "$PROJECT_ROOT" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$PROJECT_ROOT" -type f -name "*.pyc" -delete 2>/dev/null || true

    print_success "Nettoyage terminé"
}

# === FONCTION PRINCIPALE ===

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           Tests Agent IA Cybersécurité          ║"
    echo "║                 Version 1.0.0                   ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    local start_time=$(date +%s)
    local exit_code=0

    # Préparation
    setup_environment

    # Exécution des tests selon la configuration
    if [[ "$RUN_UNIT_TESTS" == true ]]; then
        run_unit_tests || exit_code=1
    fi

    if [[ "$RUN_INTEGRATION_TESTS" == true ]]; then
        run_integration_tests || exit_code=1
    fi

    if [[ "$RUN_LINTING" == true ]]; then
        run_linting || exit_code=1
    fi

    if [[ "$RUN_SECURITY_CHECKS" == true ]]; then
        run_security_checks || exit_code=1
    fi

    # Génération du rapport final
    if [[ "$GENERATE_REPORT" == true ]]; then
        generate_test_report
    fi

    # Nettoyage
    cleanup

    # Résumé final
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    print_header "Résumé"
    echo "Durée totale : ${duration}s"
    echo "Rapports générés dans : $REPORTS_DIR"

    if [[ $exit_code -eq 0 ]]; then
        print_success "Tous les tests sont passés avec succès ! 🎉"
    else
        print_error "Certains tests ont échoué. Consultez les rapports pour plus de détails."
    fi

    return $exit_code
}

# === GESTION DES ARGUMENTS ===

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            RUN_INTEGRATION_TESTS=false
            RUN_SECURITY_CHECKS=false
            shift
            ;;
        --integration-only)
            RUN_UNIT_TESTS=false
            RUN_LINTING=false
            shift
            ;;
        --no-coverage)
            RUN_COVERAGE=false
            shift
            ;;
        --no-lint)
            RUN_LINTING=false
            shift
            ;;
        --no-security)
            RUN_SECURITY_CHECKS=false
            shift
            ;;
        --no-report)
            GENERATE_REPORT=false
            shift
            ;;
        --pattern)
            TEST_PATTERN="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --quick)
            RUN_INTEGRATION_TESTS=false
            RUN_SECURITY_CHECKS=false
            shift
            ;;
        --ci)
            # Mode optimisé pour CI/CD
            RUN_COVERAGE=true
            GENERATE_REPORT=true
            VERBOSE=false
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Option inconnue: $1"
            show_help
            exit 1
            ;;
    esac
done

# Trap pour nettoyage en cas d'interruption
trap cleanup EXIT

# Lancement des tests
cd "$PROJECT_ROOT"
main "$@"