"""
Package utils pour l'Agent IA de Cybersécurité

Ce package contient tous les utilitaires transversaux utilisés
par les différents modules de l'application :

- Logging centralisé et structuré
- Validation des données (IP, domaines, ports)
- Parsers pour formats de données (JSON, XML, CSV)
- Utilitaires de sécurité (hashing, encryption)
- Helpers pour formatage et conversion
- Décorateurs et middlewares utiles

Architecture des utilitaires :
    Logger (setup_logger, get_logger)
    ├── Validators (IP, domains, ports, CVE)
    ├── Parsers (Nmap XML, JSON, CSV, Tenable)
    ├── Security (hashing, tokens, sanitization)
    ├── Formatters (dates, sizes, durations)
    └── Decorators (retry, timeout, cache)
"""

from .logger import (
    # Fonctions principales de logging
    setup_logger,
    get_logger,
    configure_logging,

    # Classes de logging
    ColoredFormatter,
    StructuredLogger,

    # Constantes
    DEFAULT_LOG_FORMAT,
    COLORED_LOG_FORMAT,
    LOG_LEVELS,
)

from .validators import (
    # Validation réseau
    validate_ip_address,
    validate_ipv4_address,
    validate_ipv6_address,
    validate_domain,
    validate_url,
    validate_port,
    validate_port_range,
    validate_cidr,

    # Validation sécurité
    validate_cve_id,
    validate_cvss_score,
    validate_hash,

    # Validation données
    validate_json,
    validate_email,
    validate_filename,
    validate_path,

    # Classes de validation
    NetworkValidator,
    SecurityValidator,
    DataValidator,
)

from .parsers import (
    # Parsers principaux
    NmapXMLParser,
    NmapJSONParser,
    TenableParser,
    OpenVASParser,
    JSONDataParser,
    CSVDataParser,

    # Fonctions utilitaires
    parse_nmap_output,
    parse_vulnerability_report,
    extract_services_from_nmap,
    extract_vulnerabilities_from_scan,

    # Exceptions
    ParserError,
    InvalidFormatError,
)

from .security import (
    # Hashing et crypto
    hash_string,
    hash_file,
    generate_token,
    generate_uuid,

    # Sanitization
    sanitize_input,
    sanitize_filename,
    sanitize_command,
    escape_shell_command,

    # Validation sécurisée
    is_safe_path,
    is_safe_command,
    validate_script_content,

    # Classes de sécurité
    SecurityUtils,
    InputSanitizer,
    CommandValidator,
)

# Version du package utils
__version__ = "1.0.0"

# Export des éléments principaux
__all__ = [
    # Version
    "__version__",

    # Logger
    "setup_logger",
    "get_logger",
    "configure_logging",
    "ColoredFormatter",
    "StructuredLogger",
    "DEFAULT_LOG_FORMAT",
    "COLORED_LOG_FORMAT",
    "LOG_LEVELS",

    # Validators
    "validate_ip_address",
    "validate_ipv4_address",
    "validate_ipv6_address",
    "validate_domain",
    "validate_url",
    "validate_port",
    "validate_port_range",
    "validate_cidr",
    "validate_cve_id",
    "validate_cvss_score",
    "validate_hash",
    "validate_json",
    "validate_email",
    "validate_filename",
    "validate_path",
    "NetworkValidator",
    "SecurityValidator",
    "DataValidator",

    # Parsers
    "NmapXMLParser",
    "NmapJSONParser",
    "TenableParser",
    "OpenVASParser",
    "JSONDataParser",
    "CSVDataParser",
    "parse_nmap_output",
    "parse_vulnerability_report",
    "extract_services_from_nmap",
    "extract_vulnerabilities_from_scan",
    "ParserError",
    "InvalidFormatError",

    # Security
    "hash_string",
    "hash_file",
    "generate_token",
    "generate_uuid",
    "sanitize_input",
    "sanitize_filename",
    "sanitize_command",
    "escape_shell_command",
    "is_safe_path",
    "is_safe_command",
    "validate_script_content",
    "SecurityUtils",
    "InputSanitizer",
    "CommandValidator",

    # Fonctions utilitaires
    "format_duration",
    "format_file_size",
    "format_timestamp",
    "truncate_string",
    "normalize_whitespace",
    "deep_merge_dicts",
    "flatten_dict",
    "get_nested_value",
    "retry_on_failure",
    "timeout_decorator",
    "cache_result",
    "measure_time",
]

# === CONSTANTES GLOBALES ===

# Patterns de validation courants
PATTERNS = {
    "IPV4": r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    "IPV6": r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
    "DOMAIN": r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
    "CVE": r"^CVE-\d{4}-\d{4,}$",
    "EMAIL": r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    "URL": r"^https?://(?:[-\w.])+(?::[0-9]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?$",
}

# Configuration par défaut des utilitaires
DEFAULT_UTILS_CONFIG = {
    "logging": {
        "level": "INFO",
        "format": "detailed",
        "colored": True,
        "file_logging": True,
        "max_file_size": 10485760,  # 10MB
        "backup_count": 5
    },
    "validation": {
        "strict_mode": True,
        "allow_private_ips": True,
        "dns_validation": False,  # Validation DNS (plus lent)
        "max_string_length": 10000
    },
    "security": {
        "hash_algorithm": "sha256",
        "token_length": 32,
        "safe_chars_only": True,
        "max_command_length": 1000
    },
    "parsing": {
        "max_file_size": 52428800,  # 50MB
        "encoding": "utf-8",
        "skip_invalid_entries": True
    }
}

# Types de fichiers supportés
SUPPORTED_FILE_TYPES = {
    "nmap": [".xml", ".json", ".nmap"],
    "tenable": [".nessus", ".json"],
    "openvas": [".xml"],
    "reports": [".json", ".csv", ".txt"],
    "scripts": [".sh", ".ps1", ".py"]
}


# Codes d'erreur pour les utilitaires
class UtilsErrorCodes:
    """Codes d'erreur spécifiques aux utilitaires"""

    # Erreurs de validation (30000-30999)
    INVALID_IP_ADDRESS = 30000
    INVALID_DOMAIN = 30001
    INVALID_PORT = 30002
    INVALID_CVE_FORMAT = 30003
    INVALID_JSON_FORMAT = 30004

    # Erreurs de parsing (31000-31999)
    PARSER_ERROR = 31000
    UNSUPPORTED_FORMAT = 31001
    CORRUPTED_DATA = 31002
    INCOMPLETE_DATA = 31003

    # Erreurs de sécurité (32000-32999)
    UNSAFE_INPUT = 32000
    UNSAFE_PATH = 32001
    UNSAFE_COMMAND = 32002
    HASH_VERIFICATION_FAILED = 32003


# === EXCEPTIONS PERSONNALISÉES ===

class UtilsError(Exception):
    """Exception de base pour les utilitaires"""

    def __init__(self, message: str, error_code: int = None, details: dict = None):
        super().__init__(message)
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = __import__('datetime').datetime.utcnow()


class ValidationError(UtilsError):
    """Erreur de validation de données"""
    pass


class SecurityError(UtilsError):
    """Erreur de sécurité"""
    pass


# === FONCTIONS UTILITAIRES GÉNÉRALES ===

def format_duration(seconds: float) -> str:
    """
    Formate une durée en secondes en format lisible

    Args:
        seconds: Durée en secondes

    Returns:
        str: Durée formatée (ex: "2m 30s", "1h 15m")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_file_size(bytes_size: int) -> str:
    """
    Formate une taille de fichier en format lisible

    Args:
        bytes_size: Taille en bytes

    Returns:
        str: Taille formatée (ex: "1.2 MB", "500 KB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} PB"


def format_timestamp(timestamp, format_type: str = "iso") -> str:
    """
    Formate un timestamp selon différents formats

    Args:
        timestamp: Timestamp à formater
        format_type: Type de format ("iso", "human", "short")

    Returns:
        str: Timestamp formaté
    """
    from datetime import datetime

    if isinstance(timestamp, (int, float)):
        dt = datetime.fromtimestamp(timestamp)
    elif isinstance(timestamp, str):
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    else:
        dt = timestamp

    if format_type == "iso":
        return dt.isoformat()
    elif format_type == "human":
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    elif format_type == "short":
        return dt.strftime("%m/%d %H:%M")
    else:
        return str(dt)


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Tronque une chaîne si elle dépasse la longueur maximale

    Args:
        text: Texte à tronquer
        max_length: Longueur maximale
        suffix: Suffixe à ajouter si tronqué

    Returns:
        str: Texte tronqué si nécessaire
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def normalize_whitespace(text: str) -> str:
    """
    Normalise les espaces blancs dans un texte

    Args:
        text: Texte à normaliser

    Returns:
        str: Texte avec espaces normalisés
    """
    import re
    # Remplacer les espaces multiples par un seul
    text = re.sub(r'\s+', ' ', text)
    # Supprimer les espaces en début/fin
    return text.strip()


def deep_merge_dicts(dict1: dict, dict2: dict) -> dict:
    """
    Fusionne récursivement deux dictionnaires

    Args:
        dict1: Premier dictionnaire
        dict2: Deuxième dictionnaire (priorité)

    Returns:
        dict: Dictionnaire fusionné
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def flatten_dict(nested_dict: dict, separator: str = ".") -> dict:
    """
    Applatit un dictionnaire imbriqué

    Args:
        nested_dict: Dictionnaire imbriqué
        separator: Séparateur pour les clés

    Returns:
        dict: Dictionnaire aplati
    """

    def _flatten(obj, parent_key=""):
        items = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{parent_key}{separator}{key}" if parent_key else key
                items.extend(_flatten(value, new_key).items())
        else:
            return {parent_key: obj}
        return dict(items)

    return _flatten(nested_dict)


def get_nested_value(data: dict, key_path: str, default=None, separator: str = "."):
    """
    Récupère une valeur dans un dictionnaire imbriqué

    Args:
        data: Dictionnaire de données
        key_path: Chemin vers la clé (ex: "config.database.host")
        default: Valeur par défaut
        separator: Séparateur de chemin

    Returns:
        Valeur trouvée ou valeur par défaut
    """
    keys = key_path.split(separator)
    current = data

    try:
        for key in keys:
            current = current[key]
        return current
    except (KeyError, TypeError):
        return default


# === DÉCORATEURS UTILITAIRES ===

def retry_on_failure(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """
    Décorateur pour retry automatique en cas d'échec

    Args:
        max_attempts: Nombre maximum de tentatives
        delay: Délai initial entre les tentatives
        backoff: Facteur de multiplication du délai
    """

    def decorator(func):
        import time
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay

            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise

                    logger = get_logger(__name__)
                    logger.warning(f"Tentative {attempt + 1} échouée pour {func.__name__}: {e}")

                    time.sleep(current_delay)
                    current_delay *= backoff

        return wrapper

    return decorator


def timeout_decorator(timeout_seconds: float):
    """
    Décorateur pour limiter le temps d'exécution d'une fonction

    Args:
        timeout_seconds: Timeout en secondes
    """

    def decorator(func):
        import signal
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            def timeout_handler(signum, frame):
                raise TimeoutError(f"Fonction {func.__name__} timeout après {timeout_seconds}s")

            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(timeout_seconds))

            try:
                return func(*args, **kwargs)
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

        return wrapper

    return decorator


def cache_result(expiration_seconds: int = 300):
    """
    Décorateur pour mettre en cache le résultat d'une fonction

    Args:
        expiration_seconds: Durée de vie du cache en secondes
    """

    def decorator(func):
        import time
        import functools

        cache = {}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Créer une clé de cache
            key = str(args) + str(sorted(kwargs.items()))
            now = time.time()

            # Vérifier le cache
            if key in cache:
                result, timestamp = cache[key]
                if now - timestamp < expiration_seconds:
                    return result
                else:
                    del cache[key]

            # Calculer et mettre en cache
            result = func(*args, **kwargs)
            cache[key] = (result, now)

            return result

        return wrapper

    return decorator


def measure_time(func):
    """
    Décorateur pour mesurer le temps d'exécution d'une fonction
    """
    import time
    import functools

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            execution_time = time.time() - start_time
            logger = get_logger(__name__)
            logger.debug(f"Fonction {func.__name__} exécutée en {execution_time:.3f}s")

    return wrapper


# === HELPERS SPÉCIALISÉS ===

def extract_ips_from_text(text: str) -> list:
    """
    Extrait toutes les adresses IP d'un texte

    Args:
        text: Texte à analyser

    Returns:
        list: Liste des adresses IP trouvées
    """
    import re

    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

    return re.findall(ipv4_pattern, text)


def extract_domains_from_text(text: str) -> list:
    """
    Extrait tous les noms de domaine d'un texte

    Args:
        text: Texte à analyser

    Returns:
        list: Liste des domaines trouvés
    """
    import re

    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    domains = re.findall(domain_pattern, text)
    # Filtrer les faux positifs
    filtered_domains = []
    for domain in domains:
        if validate_domain(domain):
            filtered_domains.append(domain)

    return filtered_domains


def generate_scan_id() -> str:
    """
    Génère un ID unique pour un scan

    Returns:
        str: ID de scan au format scan_YYYYMMDD_HHMMSS_UUID
    """
    from datetime import datetime
    import uuid

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    short_uuid = str(uuid.uuid4())[:8]

    return f"scan_{timestamp}_{short_uuid}"


def generate_vulnerability_id() -> str:
    """
    Génère un ID unique pour une vulnérabilité

    Returns:
        str: ID de vulnérabilité au format vuln_TIMESTAMP_UUID
    """
    import time
    import uuid

    timestamp = int(time.time())
    short_uuid = str(uuid.uuid4())[:8]

    return f"vuln_{timestamp}_{short_uuid}"


# === CONFIGURATION GLOBALE ===

def get_utils_config() -> dict:
    """
    Retourne la configuration des utilitaires

    Returns:
        dict: Configuration complète des utilitaires
    """
    return DEFAULT_UTILS_CONFIG.copy()


def validate_utils_config(config: dict) -> bool:
    """
    Valide une configuration d'utilitaires

    Args:
        config: Configuration à valider

    Returns:
        bool: True si valide

    Raises:
        ValidationError: Si la configuration est invalide
    """
    required_sections = ["logging", "validation", "security", "parsing"]

    for section in required_sections:
        if section not in config:
            raise ValidationError(f"Section manquante dans la configuration: {section}")

    # Validation spécifique par section
    logging_config = config["logging"]
    if logging_config.get("level") not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        raise ValidationError("Niveau de log invalide")

    return True


# === INITIALISATION DU PACKAGE ===

def _initialize_utils_package():
    """Initialisation du package utils au chargement"""
    try:
        # Configurer le logging de base
        logger = setup_logger(__name__)
        logger.info(f"Package utils initialisé - version {__version__}")

        # Valider la configuration par défaut
        validate_utils_config(DEFAULT_UTILS_CONFIG)

    except Exception as e:
        import warnings
        warnings.warn(f"Erreur lors de l'initialisation du package utils: {e}")


# Exécuter l'initialisation au chargement
_initialize_utils_package()

# === INFORMATIONS DE DEBUG ===

if __name__ == "__main__":
    print(f"Package Utils v{__version__}")

    print("\nModules disponibles:")
    modules = ["logger", "validators", "parsers", "security"]
    for module in modules:
        print(f"  - {module}")

    print("\nPatterns de validation:")
    for name, pattern in PATTERNS.items():
        print(f"  {name}: {pattern[:50]}...")

    print(f"\nTypes de fichiers supportés: {len(SUPPORTED_FILE_TYPES)}")
    print("Fonctionnalités: Logging, Validation, Parsing, Security, Formatage")