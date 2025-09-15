#!/bin/bash

# Script de sauvegarde pour Agent IA de Cybersécurité
# Version: 1.0.0
# Usage: ./scripts/backup.sh [OPTIONS]

set -euo pipefail

# === CONFIGURATION ===
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
DEFAULT_RETENTION_DAYS=30

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Variables configurables
RETENTION_DAYS=$DEFAULT_RETENTION_DAYS
BACKUP_TYPE="full"
COMPRESSION="gzip"
EXCLUDE_PATTERNS=""
INCLUDE_LOGS=false
INCLUDE_CACHE=false
REMOTE_BACKUP=""
ENCRYPT_BACKUP=false
ENCRYPTION_KEY=""

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
    echo "Options de sauvegarde:"
    echo "  --type TYPE          Type de sauvegarde (full|data|config|db) [défaut: full]"
    echo "  --output DIR         Répertoire de destination [défaut: ./backups]"
    echo "  --retention DAYS     Rétention en jours [défaut: 30]"
    echo "  --compression TYPE   Compression (gzip|bzip2|xz|none) [défaut: gzip]"
    echo ""
    echo "Options d'inclusion/exclusion:"
    echo "  --include-logs       Inclure les logs dans la sauvegarde"
    echo "  --include-cache      Inclure les caches et fichiers temporaires"
    echo "  --exclude PATTERN    Pattern d'exclusion (peut être répété)"
    echo ""
    echo "Options avancées:"
    echo "  --encrypt            Chiffrer la sauvegarde"
    echo "  --key FILE           Fichier de clé de chiffrement"
    echo "  --remote URL         URL de sauvegarde distante (rsync, scp, s3, etc.)"
    echo "  --verify             Vérifier l'intégrité après sauvegarde"
    echo ""
    echo "Utilitaires:"
    echo "  --list               Lister les sauvegardes existantes"
    echo "  --restore FILE       Restaurer depuis une sauvegarde"
    echo "  --cleanup            Nettoyer les anciennes sauvegardes"
    echo "  --help               Afficher cette aide"
    echo ""
    echo "Types de sauvegarde:"
    echo "  full     Sauvegarde complète (code + data + config + db)"
    echo "  data     Données uniquement (scans, rapports, scripts)"
    echo "  config   Configuration uniquement"
    echo "  db       Base de données uniquement"
    echo ""
    echo "Exemples:"
    echo "  $0                           # Sauvegarde complète"
    echo "  $0 --type data --include-logs  # Données + logs"
    echo "  $0 --encrypt --key backup.key   # Sauvegarde chiffrée"
    echo "  $0 --remote user@server:/backup/ # Sauvegarde distante"
}

# === VÉRIFICATIONS PRÉALABLES ===

check_prerequisites() {
    print_header "Vérification des prérequis"

    # Vérifier que nous sommes dans le bon répertoire
    if [[ ! -f "$PROJECT_ROOT/main.py" ]]; then
        print_error "Script lancé depuis le mauvais répertoire"
        exit 1
    fi

    # Créer le répertoire de sauvegarde
    mkdir -p "$BACKUP_DIR"

    # Vérifier les outils nécessaires
    local missing_tools=()

    case $COMPRESSION in
        gzip)
            command -v gzip >/dev/null || missing_tools+=("gzip")
            ;;
        bzip2)
            command -v bzip2 >/dev/null || missing_tools+=("bzip2")
            ;;
        xz)
            command -v xz >/dev/null || missing_tools+=("xz")
            ;;
    esac

    if [[ "$ENCRYPT_BACKUP" == true ]]; then
        command -v gpg >/dev/null || missing_tools+=("gpg")
    fi

    if [[ -n "$REMOTE_BACKUP" ]]; then
        if [[ "$REMOTE_BACKUP" == s3://* ]]; then
            command -v aws >/dev/null || missing_tools+=("aws-cli")
        else
            command -v rsync >/dev/null || missing_tools+=("rsync")
        fi
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Outils manquants: ${missing_tools[*]}"
        print_info "Installation suggérée: sudo apt-get install ${missing_tools[*]}"
        exit 1
    fi

    print_success "Prérequis vérifiés"
}

# === FONCTIONS DE SAUVEGARDE ===

generate_backup_name() {
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local hostname=$(hostname -s)
    echo "vulnerability_agent_${BACKUP_TYPE}_${hostname}_${timestamp}"
}

create_exclusion_list() {
    local exclude_file=$(mktemp)

    # Exclusions par défaut
    cat > "$exclude_file" << EOF
__pycache__/
*.pyc
*.pyo
*.log
.git/
.venv/
node_modules/
*.tmp
*.temp
.DS_Store
Thumbs.db
EOF

    # Exclusions selon les options
    if [[ "$INCLUDE_LOGS" != true ]]; then
        echo "logs/" >> "$exclude_file"
        echo "*.log" >> "$exclude_file"
    fi

    if [[ "$INCLUDE_CACHE" != true ]]; then
        echo ".pytest_cache/" >> "$exclude_file"
        echo "htmlcov/" >> "$exclude_file"
        echo "test_reports/" >> "$exclude_file"
    fi

    # Exclusions personnalisées
    if [[ -n "$EXCLUDE_PATTERNS" ]]; then
        echo "$EXCLUDE_PATTERNS" | tr ',' '\n' >> "$exclude_file"
    fi

    echo "$exclude_file"
}

backup_full() {
    print_info "Sauvegarde complète du projet"

    local backup_name=$(generate_backup_name)
    local exclude_file=$(create_exclusion_list)
    local archive_file="$BACKUP_DIR/${backup_name}.tar"

    # Créer l'archive
    print_info "Création de l'archive: $archive_file"
    tar --create \
        --file="$archive_file" \
        --exclude-from="$exclude_file" \
        --verbose \
        --directory="$(dirname "$PROJECT_ROOT")" \
        "$(basename "$PROJECT_ROOT")"

    # Nettoyage
    rm "$exclude_file"

    # Compression
    compress_archive "$archive_file"

    echo "$archive_file"
}

backup_data() {
    print_info "Sauvegarde des données uniquement"

    local backup_name=$(generate_backup_name)
    local archive_file="$BACKUP_DIR/${backup_name}.tar"

    # Créer l'archive des données
    tar --create \
        --file="$archive_file" \
        --verbose \
        --directory="$PROJECT_ROOT" \
        data/ \
        $([ "$INCLUDE_LOGS" == true ] && echo "logs/" || true)

    # Compression
    compress_archive "$archive_file"

    echo "$archive_file"
}

backup_config() {
    print_info "Sauvegarde de la configuration uniquement"

    local backup_name=$(generate_backup_name)
    local archive_file="$BACKUP_DIR/${backup_name}.tar"

    # Créer l'archive de configuration
    tar --create \
        --file="$archive_file" \
        --verbose \
        --directory="$PROJECT_ROOT" \
        config/ \
        .env \
        requirements.txt \
        main.py

    # Compression
    compress_archive "$archive_file"

    echo "$archive_file"
}

backup_database() {
    print_info "Sauvegarde de la base de données uniquement"

    local backup_name=$(generate_backup_name)
    local db_backup="$BACKUP_DIR/${backup_name}.db"

    # Localiser la base de données
    local db_path="$PROJECT_ROOT/data/database/vulnerability_agent.db"

    if [[ -f "$db_path" ]]; then
        print_info "Copie de la base de données: $db_path"
        cp "$db_path" "$db_backup"

        # Créer un dump SQL également
        if command -v sqlite3 >/dev/null; then
            print_info "Création du dump SQL"
            sqlite3 "$db_path" ".dump" > "$BACKUP_DIR/${backup_name}.sql"
        fi

        # Compression
        if [[ "$COMPRESSION" != "none" ]]; then
            compress_file "$db_backup"
        fi

        echo "$db_backup"
    else
        print_warning "Base de données non trouvée: $db_path"
        return 1
    fi
}

compress_archive() {
    local archive_file="$1"

    if [[ "$COMPRESSION" == "none" ]]; then
        return 0
    fi

    print_info "Compression avec $COMPRESSION"

    case $COMPRESSION in
        gzip)
            gzip "$archive_file"
            ;;
        bzip2)
            bzip2 "$archive_file"
            ;;
        xz)
            xz "$archive_file"
            ;;
    esac
}

compress_file() {
    local file="$1"

    case $COMPRESSION in
        gzip)
            gzip "$file"
            ;;
        bzip2)
            bzip2 "$file"
            ;;
        xz)
            xz "$file"
            ;;
    esac
}

encrypt_backup() {
    local backup_file="$1"

    if [[ "$ENCRYPT_BACKUP" != true ]]; then
        return 0
    fi

    print_info "Chiffrement de la sauvegarde"

    if [[ -n "$ENCRYPTION_KEY" && -f "$ENCRYPTION_KEY" ]]; then
        # Chiffrement avec clé
        gpg --cipher-algo AES256 --compress-algo 2 --symmetric --output "${backup_file}.gpg" "$backup_file"
        rm "$backup_file"
        echo "${backup_file}.gpg"
    else
        # Chiffrement avec phrase de passe
        print_warning "Chiffrement interactif (phrase de passe requise)"
        gpg --cipher-algo AES256 --compress-algo 2 --symmetric --output "${backup_file}.gpg" "$backup_file"
        rm "$backup_file"
        echo "${backup_file}.gpg"
    fi
}

# === SAUVEGARDE DISTANTE ===

upload_to_remote() {
    local backup_file="$1"

    if [[ -z "$REMOTE_BACKUP" ]]; then
        return 0
    fi

    print_info "Upload vers: $REMOTE_BACKUP"

    if [[ "$REMOTE_BACKUP" == s3://* ]]; then
        # Upload S3
        aws s3 cp "$backup_file" "$REMOTE_BACKUP"
    else
        # Upload via rsync/scp
        rsync -avz --progress "$backup_file" "$REMOTE_BACKUP"
    fi

    print_success "Sauvegarde uploadée avec succès"
}

# === VÉRIFICATION ET NETTOYAGE ===

verify_backup() {
    local backup_file="$1"

    print_info "Vérification de l'intégrité"

    # Vérifier que le fichier existe et n'est pas vide
    if [[ ! -f "$backup_file" ]] || [[ ! -s "$backup_file" ]]; then
        print_error "Fichier de sauvegarde invalide"
        return 1
    fi

    # Vérifier l'archive selon le type
    local extension="${backup_file##*.}"
    case $extension in
        tar)
            tar --test-file="$backup_file"
            ;;
        gz)
            gzip --test "$backup_file"
            ;;
        bz2)
            bzip2 --test "$backup_file"
            ;;
        xz)
            xz --test "$backup_file"
            ;;
        gpg)
            print_info "Vérification du chiffrement GPG"
            gpg --list-packets "$backup_file" >/dev/null
            ;;
    esac

    print_success "Sauvegarde vérifiée avec succès"
}

cleanup_old_backups() {
    print_info "Nettoyage des anciennes sauvegardes (>$RETENTION_DAYS jours)"

    local deleted_count=0

    while IFS= read -r -d '' backup_file; do
        local file_age=$(( ($(date +%s) - $(stat -c %Y "$backup_file")) / 86400 ))

        if [[ $file_age -gt $RETENTION_DAYS ]]; then
            print_info "Suppression: $(basename "$backup_file") (${file_age} jours)"
            rm "$backup_file"
            ((deleted_count++))
        fi
    done < <(find "$BACKUP_DIR" -name "vulnerability_agent_*" -type f -print0)

    print_success "$deleted_count anciennes sauvegardes supprimées"
}

list_backups() {
    print_header "Sauvegardes existantes"

    if [[ ! -d "$BACKUP_DIR" ]] || [[ -z "$(ls -A "$BACKUP_DIR" 2>/dev/null)" ]]; then
        print_warning "Aucune sauvegarde trouvée"
        return 0
    fi

    echo -e "${BOLD}Fichier                                    Taille    Date${NC}"
    echo "─────────────────────────────────────────────────────────────────"

    find "$BACKUP_DIR" -name "vulnerability_agent_*" -type f -printf "%f %s %TY-%Tm-%Td %TH:%TM\n" | \
    sort -k3,4 -r | \
    while read -r filename size date time; do
        local size_human=$(numfmt --to=iec --suffix=B "$size" 2>/dev/null || echo "${size}B")
        printf "%-40s %8s  %s %s\n" "$filename" "$size_human" "$date" "$time"
    done
}

# === FONCTION PRINCIPALE ===

main() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║        Sauvegarde Agent IA Cybersécurité        ║"
    echo "║                Version 1.0.0                    ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}\n"

    local start_time=$(date +%s)

    # Vérifications
    check_prerequisites

    # Exécuter la sauvegarde selon le type
    local backup_file=""

    case $BACKUP_TYPE in
        full)
            backup_file=$(backup_full)
            ;;
        data)
            backup_file=$(backup_data)
            ;;
        config)
            backup_file=$(backup_config)
            ;;
        db)
            backup_file=$(backup_database)
            ;;
        *)
            print_error "Type de sauvegarde invalide: $BACKUP_TYPE"
            exit 1
            ;;
    esac

    # Chiffrement si demandé
    if [[ "$ENCRYPT_BACKUP" == true ]]; then
        backup_file=$(encrypt_backup "$backup_file")
    fi

    # Vérification
    verify_backup "$backup_file"

    # Upload distant
    upload_to_remote "$backup_file"

    # Nettoyage des anciennes sauvegardes
    cleanup_old_backups

    # Résumé
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local file_size=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
    local size_human=$(numfmt --to=iec --suffix=B "$file_size" 2>/dev/null || echo "${file_size}B")

    print_header "Résumé de la sauvegarde"
    echo "Type: $BACKUP_TYPE"
    echo "Fichier: $(basename "$backup_file")"
    echo "Taille: $size_human"
    echo "Durée: ${duration}s"
    echo "Emplacement: $backup_file"

    print_success "Sauvegarde terminée avec succès ! 🎉"
}

# === GESTION DES ARGUMENTS ===

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            BACKUP_TYPE="$2"
            shift 2
            ;;
        --output)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --retention)
            RETENTION_DAYS="$2"
            shift 2
            ;;
        --compression)
            COMPRESSION="$2"
            shift 2
            ;;
        --include-logs)
            INCLUDE_LOGS=true
            shift
            ;;
        --include-cache)
            INCLUDE_CACHE=true
            shift
            ;;
        --exclude)
            EXCLUDE_PATTERNS="${EXCLUDE_PATTERNS},$2"
            shift 2
            ;;
        --encrypt)
            ENCRYPT_BACKUP=true
            shift
            ;;
        --key)
            ENCRYPTION_KEY="$2"
            shift 2
            ;;
        --remote)
            REMOTE_BACKUP="$2"
            shift 2
            ;;
        --list)
            list_backups
            exit 0
            ;;
        --cleanup)
            cleanup_old_backups
            exit 0
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

# Nettoyage en cas d'interruption
trap cleanup_old_backups EXIT

# Lancement de la sauvegarde
cd "$PROJECT_ROOT"
main "$@"