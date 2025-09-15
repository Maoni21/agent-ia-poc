#!/bin/bash

# Script de nettoyage pour Agent IA de Cybersécurité
# Version: 1.0.0
# Usage: ./scripts/clean.sh [OPTIONS]

set -euo pipefail

# === CONFIGURATION ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Variables de configuration
CLEAN_CACHE=true
CLEAN_LOGS=false
CLEAN_DATA=false
CLEAN_REPORTS=false
CLEAN_TEMP=true
CLEAN_BUILD=true
CLEAN_TESTS=true
FORCE_MODE=false
DRY_RUN=false
VERBOSE=false

# Statistiques
TOTAL_FILES_DELETED=0
TOTAL_SIZE_FREED=0

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
    echo "Options de nettoyage:"
    echo "  --all               Nettoyer tout (équivalent à --cache --logs --data --reports --temp)"
    echo "  --cache             Nettoyer les caches Python et système"
    echo "  --logs              Nettoyer les fichiers de logs"
    echo "  --data              Nettoyer les données générées (ATTENTION)"
    echo "  --reports           Nettoyer les rapports de test et d'analyse"
    echo "  --temp              Nettoyer les fichiers temporaires"
    echo "  --build             Nettoyer les artefacts de build"
    echo "  --tests             Nettoyer les données de test"
    echo ""
    echo "Options de sécurité:"
    echo "  --force             Forcer le nettoyage sans confirmation"
    echo "  --dry-run           Simuler le nettoyage sans supprimer"
    echo "  --verbose           Mode verbeux"
    echo ""
    echo "Utilitaires:"
    echo "  --size              Afficher l'espace utilisé par catégorie"
    echo "  --old DAYS          Nettoyer uniquement les fichiers plus anciens que X jours"
    echo "  --help              Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                  # Nettoyage standard (cache + temp + build + tests)"
    echo "  $0 --all            # Nettoyage complet"
    echo "  $0 --logs --force   # Nettoyer les logs sans confirmation"
    echo "  $0 --dry-run --verbose  # Simuler le nettoyage avec détails"
    echo "  $0 --old 7          # Nettoyer les fichiers > 7 jours"
}

# Convertir les bytes en format lisible
bytes_to_human() {
    local bytes="$1"
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$bytes"
    else
        # Fallback manuel
        if [[ $bytes -lt 1024 ]]; then
            echo "${bytes}B"
        elif [[ $bytes -lt $((1024 * 1024)) ]]; then
            echo "$((bytes / 1024))KB"
        elif [[ $bytes -lt $((1024 * 1024 * 1024)) ]]; then
            echo "$((bytes / 1024 / 1024))MB"
        else
            echo "$((bytes / 1024 / 1024 / 1024))GB"
        fi
    fi
}

# Calculer la taille d'un répertoire
get_directory_size() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        du -sb "$dir" 2>/dev/null | cut -f1 || echo "0"
    else
        echo "0"
    fi
}

# Compter les fichiers dans un répertoire
count_files() {
    local pattern="$1"
    find $pattern -type f 2>/dev/null | wc -l || echo "0"
}

# Supprimer de manière sécurisée
safe_remove() {
    local target="$1"
    local description="$2"

    if [[ ! -e "$target" ]]; then
        if [[ "$VERBOSE" == true ]]; then
            print_info "Ignoré (inexistant): $target"
        fi
        return 0
    fi

    local size=0
    local count=0

    if [[ -d "$target" ]]; then
        size=$(get_directory_size "$target")
        count=$(find "$target" -type f 2>/dev/null | wc -l)
    elif [[ -f "$target" ]]; then
        size=$(stat -c%s "$target" 2>/dev/null || echo "0")
        count=1
    fi

    if [[ "$DRY_RUN" == true ]]; then
        print_info "[DRY RUN] Supprimerait: $description ($count fichiers, $(bytes_to_human $size))"
        return 0
    fi

    if [[ "$FORCE_MODE" != true ]] && [[ $size -gt $((100 * 1024 * 1024)) ]]; then
        print_warning "Répertoire volumineux détecté: $description ($(bytes_to_human $size))"
        read -p "Continuer? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Ignoré: $description"
            return 0
        fi
    fi

    print_info "Suppression: $description ($count fichiers, $(bytes_to_human $size))"

    if rm -rf "$target" 2>/dev/null; then
        TOTAL_FILES_DELETED=$((TOTAL_FILES_DELETED + count))
        TOTAL_SIZE_FREED=$((TOTAL_SIZE_FREED + size))
        if [[ "$VERBOSE" == true ]]; then
            print_success "Supprimé: $target"
        fi
    else
        print_error "Échec suppression: $target"
        return 1
    fi
}

# === FONCTIONS DE NETTOYAGE ===

clean_python_cache() {
    print_header "Nettoyage du cache Python"

    # Cache Python (__pycache__)
    while IFS= read -r -d '' pycache_dir; do
        safe_remove "$pycache_dir" "Cache Python $(basename "$(dirname "$pycache_dir")")"
    done < <(find "$PROJECT_ROOT" -type d -name "__pycache__" -print0 2>/dev/null)

    # Fichiers .pyc, .pyo, .pyd
    local pyc_files=0
    while IFS= read -r -d '' pyc_file; do
        safe_remove "$pyc_file" "Fichier Python compilé"
        ((pyc_files++))
    done < <(find "$PROJECT_ROOT" -type f \( -name "*.pyc" -o -name "*.pyo" -o -name "*.pyd" \) -print0 2>/dev/null)

    # Cache pip
    local pip_cache_dir="$HOME/.cache/pip"
    if [[ -d "$pip_cache_dir" ]]; then
        safe_remove "$pip_cache_dir" "Cache pip global"
    fi

    # Cache pytest
    safe_remove "$PROJECT_ROOT/.pytest_cache" "Cache pytest"

    # Cache mypy
    safe_remove "$PROJECT_ROOT/.mypy_cache" "Cache mypy"

    print_success "Nettoyage du cache Python terminé"
}

clean_logs() {
    print_header "Nettoyage des logs"

    if [[ "$CLEAN_LOGS" != true ]]; then
        print_info "Nettoyage des logs désactivé (utilisez --logs pour activer)"
        return 0
    fi

    # Logs de l'application
    safe_remove "$PROJECT_ROOT/logs" "Répertoire des logs"

    # Logs individuels à la racine
    while IFS= read -r -d '' log_file; do
        safe_remove "$log_file" "Fichier log $(basename "$log_file")"
    done < <(find "$PROJECT_ROOT" -maxdepth 1 -type f -name "*.log" -print0 2>/dev/null)

    # Logs de debug
    while IFS= read -r -d '' debug_file; do
        safe_remove "$debug_file" "Fichier debug $(basename "$debug_file")"
    done < <(find "$PROJECT_ROOT" -type f -name "debug.log" -o -name "error.log" -o -name "access.log" -print0 2>/dev/null)

    print_success "Nettoyage des logs terminé"
}

clean_data() {
    print_header "Nettoyage des données"

    if [[ "$CLEAN_DATA" != true ]]; then
        print_info "Nettoyage des données désactivé (utilisez --data pour activer)"
        print_warning "ATTENTION: Le nettoyage des données supprimera vos scans et rapports!"
        return 0
    fi

    if [[ "$FORCE_MODE" != true ]]; then
        print_warning "ATTENTION: Cette action supprimera toutes vos données de scan!"
        print_warning "Cela inclut: scans, rapports, scripts générés, base de données"
        read -p "Êtes-vous sûr de vouloir continuer? (tapez 'yes' pour confirmer): " -r
        if [[ "$REPLY" != "yes" ]]; then
            print_info "Nettoyage des données annulé"
            return 0
        fi
    fi

    # Données de scan
    safe_remove "$PROJECT_ROOT/data/scans" "Données de scan"

    # Rapports générés
    safe_remove "$PROJECT_ROOT/data/reports" "Rapports générés"

    # Scripts générés
    safe_remove "$PROJECT_ROOT/data/scripts" "Scripts générés"

    # Base de données (avec confirmation supplémentaire)
    if [[ -f "$PROJECT_ROOT/data/database/vulnerability_agent.db" ]]; then
        if [[ "$FORCE_MODE" != true ]]; then
            read -p "Supprimer aussi la base de données? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                safe_remove "$PROJECT_ROOT/data/database/vulnerability_agent.db" "Base de données"
            fi
        else
            safe_remove "$PROJECT_ROOT/data/database/vulnerability_agent.db" "Base de données"
        fi
    fi

    print_success "Nettoyage des données terminé"
}

clean_reports() {
    print_header "Nettoyage des rapports"

    if [[ "$CLEAN_REPORTS" != true ]]; then
        return 0
    fi

    # Rapports de test
    safe_remove "$PROJECT_ROOT/test_reports" "Rapports de test"
    safe_remove "$PROJECT_ROOT/htmlcov" "Rapports de couverture"

    # Rapports pytest
    while IFS= read -r -d '' report_file; do
        safe_remove "$report_file" "Rapport pytest $(basename "$report_file")"
    done < <(find "$PROJECT_ROOT" -type f -name "pytest.xml" -o -name "coverage.xml" -print0 2>/dev/null)

    print_success "Nettoyage des rapports terminé"
}

clean_temp_files() {
    print_header "Nettoyage des fichiers temporaires"

    # Fichiers temporaires génériques
    local temp_patterns=(
        "*.tmp" "*.temp" "*.bak" "*.backup" "*.swp" "*.swo"
        "*~" ".#*" "#*#" "*.orig" "*.rej"
    )

    for pattern in "${temp_patterns[@]}"; do
        while IFS= read -r -d '' temp_file; do
            safe_remove "$temp_file" "Fichier temporaire $(basename "$temp_file")"
        done < <(find "$PROJECT_ROOT" -type f -name "$pattern" -print0 2>/dev/null)
    done

    # Répertoires temporaires
    safe_remove "$PROJECT_ROOT/tmp" "Répertoire temporaire"
    safe_remove "$PROJECT_ROOT/temp" "Répertoire temporaire"

    # Fichiers de verrouillage
    while IFS= read -r -d '' lock_file; do
        safe_remove "$lock_file" "Fichier de verrouillage $(basename "$lock_file")"
    done < <(find "$PROJECT_ROOT" -type f -name "*.lock" -o -name "*.pid" -print0 2>/dev/null)

    # Fichiers système
    while IFS= read -r -d '' sys_file; do
        safe_remove "$sys_file" "Fichier système $(basename "$sys_file")"
    done < <(find "$PROJECT_ROOT" -type f -name ".DS_Store" -o -name "Thumbs.db" -print0 2>/dev/null)

    print_success "Nettoyage des fichiers temporaires terminé"
}

clean_build_artifacts() {
    print_header "Nettoyage des artefacts de build"

    # Artefacts Python
    safe_remove "$PROJECT_ROOT/build" "Répertoire de build"
    safe_remove "$PROJECT_ROOT/dist" "Répertoire de distribution"

    # Egg info
    while IFS= read -r -d '' egg_dir; do
        safe_remove "$egg_dir" "Egg info $(basename "$egg_dir")"
    done < <(find "$PROJECT_ROOT" -type d -name "*.egg-info" -print0 2>/dev/null)

    # Wheel
    while IFS= read -r -d '' wheel_file; do
        safe_remove "$wheel_file" "Fichier wheel $(basename "$wheel_file")"
    done < <(find "$PROJECT_ROOT" -type f -name "*.whl" -print0 2>/dev/null)

    print_success "Nettoyage des artefacts de build terminé"
}

clean_test_data() {
    print_header "Nettoyage des données de test"

    # Base de données de test
    while IFS= read -r -d '' test_db; do
        safe_remove "$test_db" "Base de données de test $(basename "$test_db")"
    done < <(find "$PROJECT_ROOT" -type f -name "test*.db" -o -name "*_test.db" -print0 2>/dev/null)

    # Fichiers de test temporaires
    safe_remove "$PROJECT_ROOT/tests/temp" "Données temporaires de test"
    safe_remove "$PROJECT_ROOT/tests/output" "Sorties de test"

    # Fixtures temporaires
    while IFS= read -r -d '' fixture_file; do
        safe_remove "$fixture_file" "Fixture temporaire $(basename "$fixture_file")"
    done < <(find "$PROJECT_ROOT/tests" -type f -name "*.tmp" -o -name "temp_*" -print0 2>/dev/null)

    print_success "Nettoyage des données de test terminé"
}

# === ANALYSE DE L'ESPACE DISQUE ===

show_disk_usage() {
    print_header "Utilisation de l'espace disque"

    local categories=(
        "Cache Python:$PROJECT_ROOT:__pycache__,*.pyc,*.pyo"
        "Logs:$PROJECT_ROOT/logs:*"
        "Données:$PROJECT_ROOT/data:*"
        "Rapports:$PROJECT_ROOT/test_reports,$PROJECT_ROOT/htmlcov:*"
        "Temporaire:$PROJECT_ROOT:*.tmp,*.temp,*.bak"
        "Build:$PROJECT_ROOT/build,$PROJECT_ROOT/dist:*"
    )

    echo -e "${BOLD}Catégorie                Fichiers    Taille${NC}"
    echo "──────────────────────────────────────────────────"

    for category in "${categories[@]}"; do
        local name=$(echo "$category" | cut -d: -f1)
        local paths=$(echo "$category" | cut -d: -f2)
        local patterns=$(echo "$category" | cut -d: -f3)

        local total_size=0
        local total_files=0

        IFS=',' read -ra PATH_ARRAY <<< "$paths"
        for path in "${PATH_ARRAY[@]}"; do
            if [[ -d "$path" ]]; then
                local size=$(get_directory_size "$path")
                local files=$(find "$path" -type f 2>/dev/null | wc -l)
                total_size=$((total_size + size))
                total_files=$((total_files + files))
            fi
        done

        printf "%-20s %8d    %s\n" "$name" "$total_files" "$(bytes_to_human $total_size)"
    done

    echo "──────────────────────────────────────────────────"
    local project_size=$(get_directory_size "$PROJECT_ROOT")
    printf "%-20s %8s    %s\n" "TOTAL PROJET" "-" "$(bytes_to_human $project_size)"
}

# === NETTOYAGE PAR ÂGE ===

clean_old_files() {
    local days="$1"
    print_header "Nettoyage des fichiers > $days jours"

    local find_args=(
        "$PROJECT_ROOT"
        -type f
        -mtime "+$days"
    )

    # Exclusions de sécurité
    find_args+=(
        ! -path "$PROJECT_ROOT/.git/*"
        ! -path "$PROJECT_ROOT/.venv/*"
        ! -path "$PROJECT_ROOT/src/*"
        ! -path "$PROJECT_ROOT/config/*"
        ! -name "*.py"
        ! -name "*.json"
        ! -name "requirements.txt"
        ! -name ".env*"
    )

    local old_files=0
    while IFS= read -r -d '' old_file; do
        safe_remove "$old_file" "Fichier ancien ($(basename "$old_file"))"
        ((old_files++))
    done < <(find "${find_args[@]}" -print0 2>/dev/null)

    if [[ $old_files -eq 0 ]]; then
        print_info "Aucun fichier ancien trouvé"
    else
        print_success "$old_files fichiers anciens supprimés"
    fi
}

# === FONCTION PRINCIPALE ===

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         Nettoyage Agent IA Cybersécurité        ║"
    echo "║                 Version 1.0.0                   ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    # Vérifier que nous sommes dans le bon répertoire
    if [[ ! -f "$PROJECT_ROOT/main.py" ]]; then
        print_error "Script lancé depuis le mauvais répertoire"
        exit 1
    fi

    if [[ "$DRY_RUN" == true ]]; then
        print_warning "Mode simulation activé - aucune suppression réelle"
    fi

    local start_time=$(date +%s)

    # Exécuter les nettoyages selon la configuration
    if [[ "$CLEAN_CACHE" == true ]]; then
        clean_python_cache
    fi

    if [[ "$CLEAN_LOGS" == true ]]; then
        clean_logs
    fi

    if [[ "$CLEAN_DATA" == true ]]; then
        clean_data
    fi

    if [[ "$CLEAN_REPORTS" == true ]]; then
        clean_reports
    fi

    if [[ "$CLEAN_TEMP" == true ]]; then
        clean_temp_files
    fi

    if [[ "$CLEAN_BUILD" == true ]]; then
        clean_build_artifacts
    fi

    if [[ "$CLEAN_TESTS" == true ]]; then
        clean_test_data
    fi

    # Résumé final
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    print_header "Résumé du nettoyage"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "Mode simulation - aucune suppression effectuée"
    else
        echo "Fichiers supprimés: $TOTAL_FILES_DELETED"
        echo "Espace libéré: $(bytes_to_human $TOTAL_SIZE_FREED)"
        echo "Durée: ${duration}s"

        if [[ $TOTAL_FILES_DELETED -gt 0 ]]; then
            print_success "Nettoyage terminé avec succès ! 🎉"
        else
            print_info "Aucun fichier à nettoyer trouvé"
        fi
    fi
}

# === GESTION DES ARGUMENTS ===

OLD_FILES_DAYS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --all)
            CLEAN_CACHE=true
            CLEAN_LOGS=true
            CLEAN_DATA=true
            CLEAN_REPORTS=true
            CLEAN_TEMP=true
            CLEAN_BUILD=true
            CLEAN_TESTS=true
            shift
            ;;
        --cache)
            CLEAN_CACHE=true
            shift
            ;;
        --logs)
            CLEAN_LOGS=true
            shift
            ;;
        --data)
            CLEAN_DATA=true
            shift
            ;;
        --reports)
            CLEAN_REPORTS=true
            shift
            ;;
        --temp)
            CLEAN_TEMP=true
            shift
            ;;
        --build)
            CLEAN_BUILD=true
            shift
            ;;
        --tests)
            CLEAN_TESTS=true
            shift
            ;;
        --force)
            FORCE_MODE=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --size)
            show_disk_usage
            exit 0
            ;;
        --old)
            OLD_FILES_DAYS="$2"
            shift 2
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

# Nettoyage par âge si spécifié
if [[ -n "$OLD_FILES_DAYS" ]]; then
    clean_old_files "$OLD_FILES_DAYS"
    exit 0
fi

# Lancement du nettoyage principal
cd "$PROJECT_ROOT"
main "$@"