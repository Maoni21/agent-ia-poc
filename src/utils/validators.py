"""
Module de validation pour l'Agent IA de Cybersécurité

Ce module fournit des fonctions de validation pour tous les types de données
utilisés dans l'application : adresses IP, domaines, fichiers, scripts, etc.

Fonctionnalités :
- Validation d'adresses IP (IPv4, IPv6)
- Validation de noms de domaine et d'hostnames
- Validation de formats de fichiers
- Validation de scripts et commandes
- Validation de données de vulnérabilités
- Validation de configuration
- Sanitization et nettoyage de données

Toutes les fonctions incluent une gestion d'erreur robuste et des messages
d'erreur explicites pour faciliter le debugging.
"""

import ipaddress
import re
import json
import os
import socket
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import logging

from .logger import setup_logger

# Configuration du logging
logger = setup_logger(__name__)

# === CONSTANTES ET PATTERNS ===

# Patterns regex pour validation
PATTERNS = {
    # Validation IP et réseau
    'ipv4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
    'ipv4_cidr': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$',
    'ipv6': r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',

    # Validation domaine
    'domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$',
    'hostname': r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$',

    # Validation URL
    'url': r'^https?://[^\s<>"{}|\\^`\[\]]+$',

    # Validation email
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',

    # Validation CVE
    'cve_id': r'^CVE-\d{4}-\d{4,}$',

    # Validation ports
    'port': r'^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$',
    'port_range': r'^(\d{1,5})-(\d{1,5})$',

    # Validation filename
    'safe_filename': r'^[a-zA-Z0-9._-]+$',
    'safe_path': r'^[a-zA-Z0-9/_.-]+$',
}

# Plages IP privées
PRIVATE_IP_RANGES = [
    ipaddress.IPv4Network('10.0.0.0/8'),
    ipaddress.IPv4Network('172.16.0.0/12'),
    ipaddress.IPv4Network('192.168.0.0/16'),
    ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
    ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
]

# Extensions de fichiers autorisées par type
ALLOWED_EXTENSIONS = {
    'reports': {'.json', '.txt', '.html', '.pdf', '.xml', '.csv'},
    'scripts': {'.sh', '.bash', '.py', '.pl'},
    'configs': {'.conf', '.cfg', '.ini', '.yaml', '.yml', '.json'},
    'logs': {'.log', '.txt'},
    'data': {'.json', '.xml', '.csv', '.db', '.sqlite', '.sqlite3'},
    'images': {'.png', '.jpg', '.jpeg', '.gif', '.svg'},
}

# Tailles maximales par type de fichier (en octets)
MAX_FILE_SIZES = {
    'reports': 50 * 1024 * 1024,  # 50MB
    'scripts': 1 * 1024 * 1024,  # 1MB
    'configs': 10 * 1024 * 1024,  # 10MB
    'logs': 100 * 1024 * 1024,  # 100MB
    'data': 500 * 1024 * 1024,  # 500MB
    'images': 5 * 1024 * 1024,  # 5MB
}


# === VALIDATION RÉSEAU ===

def validate_ip_address(ip_str: str, allow_private: bool = True) -> bool:
    """
    Valide une adresse IP (IPv4 ou IPv6)

    Args:
        ip_str: Chaîne représentant l'adresse IP
        allow_private: Autoriser les adresses privées

    Returns:
        bool: True si l'adresse est valide
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    try:
        ip = ipaddress.ip_address(ip_str.strip())

        # Vérifier si l'adresse privée est autorisée
        if not allow_private and ip.is_private:
            logger.debug(f"Adresse IP privée non autorisée: {ip_str}")
            return False

        return True

    except ValueError as e:
        logger.debug(f"Adresse IP invalide '{ip_str}': {e}")
        return False


def validate_ip_range(ip_range: str) -> Tuple[bool, Optional[str]]:
    """
    Valide une plage d'adresses IP (CIDR)

    Args:
        ip_range: Chaîne représentant la plage (ex: "192.168.1.0/24")

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not ip_range or not isinstance(ip_range, str):
        return False, "Plage IP vide ou invalide"

    try:
        network = ipaddress.ip_network(ip_range.strip(), strict=False)

        # Vérifications supplémentaires
        if network.prefixlen == 0:
            return False, "Plage trop large (préfixe /0 non autorisé)"

        if network.prefixlen > 30 and network.version == 4:
            logger.warning(f"Plage très petite: {ip_range}")

        return True, None

    except ValueError as e:
        return False, f"Plage IP invalide: {str(e)}"


def is_ip_in_private_ranges(ip_str: str) -> bool:
    """
    Vérifie si une IP est dans une plage privée

    Args:
        ip_str: Adresse IP à vérifier

    Returns:
        bool: True si l'IP est privée
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        for private_range in PRIVATE_IP_RANGES:
            if ip in private_range:
                return True
        return False
    except (ValueError, ipaddress.AddressValueError):
        return False


def validate_domain(domain: str, check_dns: bool = False) -> bool:
    """
    Valide un nom de domaine

    Args:
        domain: Nom de domaine à valider
        check_dns: Vérifier la résolution DNS

    Returns:
        bool: True si le domaine est valide
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    # Vérifier la longueur
    if len(domain) > 255:
        logger.debug(f"Domaine trop long: {domain}")
        return False

    # Vérifier le format avec regex
    if not re.match(PATTERNS['domain'], domain):
        logger.debug(f"Format de domaine invalide: {domain}")
        return False

    # Vérifications additionnelles
    if domain.startswith('.') or domain.endswith('.'):
        logger.debug(f"Domaine ne peut pas commencer/finir par un point: {domain}")
        return False

    if '..' in domain:
        logger.debug(f"Domaine ne peut pas contenir de points consécutifs: {domain}")
        return False

    # Vérifier la résolution DNS si demandé
    if check_dns:
        try:
            socket.gethostbyname(domain)
            logger.debug(f"Résolution DNS réussie pour: {domain}")
        except socket.gaierror:
            logger.debug(f"Résolution DNS échouée pour: {domain}")
            return False

    return True


def validate_hostname(hostname: str) -> bool:
    """
    Valide un hostname/nom d'hôte

    Args:
        hostname: Hostname à valider

    Returns:
        bool: True si le hostname est valide
    """
    if not hostname or not isinstance(hostname, str):
        return False

    hostname = hostname.strip().lower()

    # Vérifier la longueur
    if len(hostname) > 63:
        return False

    # Vérifier le format
    return bool(re.match(PATTERNS['hostname'], hostname))


def validate_url(url: str, allowed_schemes: List[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Valide une URL

    Args:
        url: URL à valider
        allowed_schemes: Schémas autorisés (défaut: http, https)

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not url or not isinstance(url, str):
        return False, "URL vide ou invalide"

    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']

    try:
        parsed = urllib.parse.urlparse(url)

        # Vérifier le schéma
        if parsed.scheme not in allowed_schemes:
            return False, f"Schéma non autorisé: {parsed.scheme}"

        # Vérifier la présence d'un netloc
        if not parsed.netloc:
            return False, "Nom d'hôte manquant dans l'URL"

        # Vérifier le hostname
        hostname = parsed.hostname
        if hostname and not validate_domain(hostname):
            return False, f"Nom d'hôte invalide: {hostname}"

        return True, None

    except Exception as e:
        return False, f"URL malformée: {str(e)}"


def validate_port(port: Union[str, int], allow_privileged: bool = False) -> bool:
    """
    Valide un numéro de port

    Args:
        port: Numéro de port à valider
        allow_privileged: Autoriser les ports privilégiés (<1024)

    Returns:
        bool: True si le port est valide
    """
    try:
        port_num = int(port)

        # Vérifier la plage
        if port_num < 1 or port_num > 65535:
            return False

        # Vérifier les ports privilégiés
        if not allow_privileged and port_num < 1024:
            logger.debug(f"Port privilégié non autorisé: {port_num}")
            return False

        return True

    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> Tuple[bool, Optional[str]]:
    """
    Valide une plage de ports

    Args:
        port_range: Plage de ports (ex: "80-8080")

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not port_range or not isinstance(port_range, str):
        return False, "Plage de ports vide"

    match = re.match(PATTERNS['port_range'], port_range.strip())
    if not match:
        return False, "Format de plage invalide (attendu: début-fin)"

    start_port, end_port = int(match.group(1)), int(match.group(2))

    # Valider chaque port
    if not validate_port(start_port) or not validate_port(end_port):
        return False, "Ports invalides dans la plage"

    # Vérifier l'ordre
    if start_port >= end_port:
        return False, "Le port de début doit être inférieur au port de fin"

    # Vérifier la taille de la plage
    if end_port - start_port > 10000:
        return False, "Plage trop large (max 10000 ports)"

    return True, None


# === VALIDATION DE FICHIERS ===

def validate_filename(filename: str, file_type: str = None, strict: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Valide un nom de fichier

    Args:
        filename: Nom de fichier à valider
        file_type: Type de fichier pour vérifier l'extension
        strict: Mode strict (caractères alphanumériques uniquement)

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not filename or not isinstance(filename, str):
        return False, "Nom de fichier vide"

    filename = filename.strip()

    # Vérifier la longueur
    if len(filename) > 255:
        return False, "Nom de fichier trop long (>255 caractères)"

    # Caractères interdits
    forbidden_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
    for char in forbidden_chars:
        if char in filename:
            return False, f"Caractère interdit dans le nom: {char}"

    # Vérification stricte
    if strict and not re.match(PATTERNS['safe_filename'], filename):
        return False, "Nom de fichier contient des caractères non autorisés (mode strict)"

    # Noms réservés Windows
    reserved_names = [
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
        'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
        'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    ]

    name_without_ext = Path(filename).stem.upper()
    if name_without_ext in reserved_names:
        return False, f"Nom de fichier réservé: {name_without_ext}"

    # Vérifier l'extension si type spécifié
    if file_type and file_type in ALLOWED_EXTENSIONS:
        extension = Path(filename).suffix.lower()
        if extension not in ALLOWED_EXTENSIONS[file_type]:
            allowed = ', '.join(ALLOWED_EXTENSIONS[file_type])
            return False, f"Extension non autorisée pour {file_type}. Autorisées: {allowed}"

    return True, None


def validate_file_path(file_path: str, must_exist: bool = False, must_be_readable: bool = False) -> Tuple[
    bool, Optional[str]]:
    """
    Valide un chemin de fichier

    Args:
        file_path: Chemin vers le fichier
        must_exist: Le fichier doit exister
        must_be_readable: Le fichier doit être lisible

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not file_path or not isinstance(file_path, str):
        return False, "Chemin de fichier vide"

    try:
        path = Path(file_path).resolve()

        # Vérifier que le chemin ne sort pas du répertoire autorisé
        # (protection contre directory traversal)
        current_dir = Path.cwd()
        try:
            path.relative_to(current_dir)
        except ValueError:
            logger.warning(f"Tentative d'accès à un fichier hors du répertoire de travail: {file_path}")

        # Vérifications d'existence
        if must_exist and not path.exists():
            return False, f"Fichier non trouvé: {file_path}"

        if must_exist and path.is_dir():
            return False, f"Chemin pointe vers un répertoire: {file_path}"

        # Vérifications de permissions
        if must_be_readable and path.exists() and not os.access(path, os.R_OK):
            return False, f"Fichier non lisible: {file_path}"

        return True, None

    except (OSError, ValueError) as e:
        return False, f"Chemin invalide: {str(e)}"


def validate_file_size(file_path: str, file_type: str = None, max_size: int = None) -> Tuple[bool, Optional[str]]:
    """
    Valide la taille d'un fichier

    Args:
        file_path: Chemin vers le fichier
        file_type: Type de fichier pour limite par défaut
        max_size: Taille maximale en octets (prioritaire sur file_type)

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    try:
        path = Path(file_path)

        if not path.exists():
            return False, "Fichier non trouvé"

        file_size = path.stat().st_size

        # Déterminer la taille maximale
        if max_size is not None:
            max_allowed = max_size
        elif file_type and file_type in MAX_FILE_SIZES:
            max_allowed = MAX_FILE_SIZES[file_type]
        else:
            max_allowed = 10 * 1024 * 1024  # 10MB par défaut

        if file_size > max_allowed:
            size_mb = file_size / (1024 * 1024)
            max_mb = max_allowed / (1024 * 1024)
            return False, f"Fichier trop volumineux: {size_mb:.1f}MB (max: {max_mb:.1f}MB)"

        return True, None

    except OSError as e:
        return False, f"Erreur d'accès au fichier: {str(e)}"


# === VALIDATION DE DONNÉES MÉTIER ===

def validate_cve_id(cve_id: str) -> bool:
    """
    Valide un identifiant CVE

    Args:
        cve_id: Identifiant CVE à valider

    Returns:
        bool: True si l'identifiant est valide
    """
    if not cve_id or not isinstance(cve_id, str):
        return False

    return bool(re.match(PATTERNS['cve_id'], cve_id.strip()))


def validate_severity_level(severity: str) -> bool:
    """
    Valide un niveau de gravité

    Args:
        severity: Niveau de gravité

    Returns:
        bool: True si le niveau est valide
    """
    valid_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']
    return severity and severity.upper() in valid_levels


def validate_cvss_score(score: Union[str, float, int]) -> bool:
    """
    Valide un score CVSS

    Args:
        score: Score CVSS à valider

    Returns:
        bool: True si le score est valide
    """
    try:
        score_float = float(score)
        return 0.0 <= score_float <= 10.0
    except (ValueError, TypeError):
        return False


def validate_vulnerability_data(vuln_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Valide les données d'une vulnérabilité

    Args:
        vuln_data: Dictionnaire contenant les données de vulnérabilité

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    # Champs obligatoires
    required_fields = ['name', 'severity', 'description']
    for field in required_fields:
        if field not in vuln_data or not vuln_data[field]:
            errors.append(f"Champ obligatoire manquant: {field}")

    # Validation du niveau de gravité
    if 'severity' in vuln_data:
        if not validate_severity_level(vuln_data['severity']):
            errors.append(f"Niveau de gravité invalide: {vuln_data['severity']}")

    # Validation du score CVSS
    if 'cvss_score' in vuln_data and vuln_data['cvss_score'] is not None:
        if not validate_cvss_score(vuln_data['cvss_score']):
            errors.append(f"Score CVSS invalide: {vuln_data['cvss_score']}")

    # Validation des CVE IDs
    if 'cve_ids' in vuln_data and isinstance(vuln_data['cve_ids'], list):
        for cve_id in vuln_data['cve_ids']:
            if not validate_cve_id(cve_id):
                errors.append(f"CVE ID invalide: {cve_id}")

    # Validation du port affecté
    if 'affected_port' in vuln_data and vuln_data['affected_port'] is not None:
        if not validate_port(vuln_data['affected_port']):
            errors.append(f"Port affecté invalide: {vuln_data['affected_port']}")

    # Validation des références (URLs)
    if 'references' in vuln_data and isinstance(vuln_data['references'], list):
        for ref in vuln_data['references']:
            is_valid, error_msg = validate_url(ref)
            if not is_valid:
                errors.append(f"URL de référence invalide: {ref} ({error_msg})")

    return len(errors) == 0, errors


def validate_scan_parameters(params: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Valide les paramètres d'un scan

    Args:
        params: Paramètres du scan

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    # Validation de la cible
    if 'target' not in params or not params['target']:
        errors.append("Cible de scan manquante")
    else:
        target = params['target']
        # Vérifier si c'est une IP ou un domaine
        if not validate_ip_address(target, allow_private=True) and not validate_domain(target):
            errors.append(f"Cible invalide (ni IP ni domaine valide): {target}")

    # Validation du type de scan
    if 'scan_type' in params:
        valid_scan_types = ['quick', 'full', 'stealth', 'aggressive', 'custom']
        if params['scan_type'] not in valid_scan_types:
            errors.append(f"Type de scan invalide: {params['scan_type']}")

    # Validation du timeout
    if 'timeout' in params:
        try:
            timeout = int(params['timeout'])
            if timeout < 30 or timeout > 3600:
                errors.append("Timeout doit être entre 30 et 3600 secondes")
        except (ValueError, TypeError):
            errors.append("Timeout doit être un nombre entier")

    # Validation des ports
    if 'ports' in params and params['ports']:
        ports_str = str(params['ports'])
        if ',' in ports_str:
            # Liste de ports
            for port_str in ports_str.split(','):
                port_str = port_str.strip()
                if '-' in port_str:
                    # Plage de ports
                    is_valid, error_msg = validate_port_range(port_str)
                    if not is_valid:
                        errors.append(f"Plage de ports invalide '{port_str}': {error_msg}")
                else:
                    # Port unique
                    if not validate_port(port_str):
                        errors.append(f"Port invalide: {port_str}")
        else:
            # Port unique ou plage
            if '-' in ports_str:
                is_valid, error_msg = validate_port_range(ports_str)
                if not is_valid:
                    errors.append(f"Plage de ports invalide: {error_msg}")
            else:
                if not validate_port(ports_str):
                    errors.append(f"Port invalide: {ports_str}")

    return len(errors) == 0, errors


# === VALIDATION DE CONFIGURATION ===

def validate_config_structure(config: Dict[str, Any], required_sections: List[str]) -> Tuple[bool, List[str]]:
    """
    Valide la structure d'un fichier de configuration

    Args:
        config: Configuration à valider
        required_sections: Sections obligatoires

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    if not isinstance(config, dict):
        errors.append("Configuration doit être un dictionnaire")
        return False, errors

    # Vérifier les sections obligatoires
    for section in required_sections:
        if section not in config:
            errors.append(f"Section de configuration manquante: {section}")
        elif not isinstance(config[section], dict):
            errors.append(f"Section '{section}' doit être un dictionnaire")

    return len(errors) == 0, errors


def validate_api_key(api_key: str, min_length: int = 20) -> bool:
    """
    Valide une clé API

    Args:
        api_key: Clé API à valider
        min_length: Longueur minimale requise

    Returns:
        bool: True si la clé est valide
    """
    if not api_key or not isinstance(api_key, str):
        return False

    # Vérifier la longueur
    if len(api_key) < min_length:
        logger.debug(f"Clé API trop courte: {len(api_key)} < {min_length}")
        return False

    # Vérifier qu'elle ne contient que des caractères valides
    valid_chars = re.match(r'^[a-zA-Z0-9\-._~]+$', api_key)
    if not valid_chars:
        logger.debug("Clé API contient des caractères invalides")
        return False

    return True


def validate_database_config(db_config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Valide la configuration de base de données

    Args:
        db_config: Configuration de la base de données

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    # Champs obligatoires
    if 'database_path' not in db_config:
        errors.append("Chemin de base de données manquant")
    else:
        # Valider le chemin
        db_path = db_config['database_path']
        is_valid, error_msg = validate_file_path(db_path, must_exist=False)
        if not is_valid:
            errors.append(f"Chemin de base invalide: {error_msg}")

    # Validation des paramètres optionnels
    numeric_params = {
        'cache_size': (1000, 100000),
        'connection_timeout': (5, 300),
        'busy_timeout': (1000, 60000),
        'backup_retention_days': (1, 365)
    }

    for param, (min_val, max_val) in numeric_params.items():
        if param in db_config:
            try:
                value = int(db_config[param])
                if value < min_val or value > max_val:
                    errors.append(f"{param} doit être entre {min_val} et {max_val}")
            except (ValueError, TypeError):
                errors.append(f"{param} doit être un nombre entier")

    # Validation des paramètres booléens
    boolean_params = ['backup_enabled', 'auto_vacuum', 'foreign_keys']
    for param in boolean_params:
        if param in db_config and not isinstance(db_config[param], bool):
            errors.append(f"{param} doit être un booléen")

    return len(errors) == 0, errors


# === VALIDATION DE SCRIPTS ===

def validate_script_content(script_content: str, allowed_commands: List[str] = None) -> Tuple[bool, List[str]]:
    """
    Validation basique du contenu d'un script

    Args:
        script_content: Contenu du script à valider
        allowed_commands: Commandes autorisées (optionnel)

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    if not script_content or not isinstance(script_content, str):
        errors.append("Contenu de script vide")
        return False, errors

    # Vérifier la longueur
    if len(script_content) > 100000:  # 100KB
        errors.append("Script trop volumineux (>100KB)")

    # Commandes potentiellement dangereuses
    dangerous_commands = [
        'rm -rf /', 'rm -rf /*', ':(){ :|:& };:', 'dd if=/dev/zero',
        'mkfs', 'fdisk', 'parted', 'shred', 'wipefs'
    ]

    for dangerous_cmd in dangerous_commands:
        if dangerous_cmd in script_content:
            errors.append(f"Commande dangereuse détectée: {dangerous_cmd}")

    # Vérifier les commandes autorisées si spécifiées
    if allowed_commands:
        lines = script_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                # Extraire la première commande de la ligne
                first_word = line.split()[0] if line.split() else ''
                if first_word and first_word not in allowed_commands:
                    errors.append(f"Commande non autorisée ligne {line_num}: {first_word}")

    return len(errors) == 0, errors


def validate_bash_syntax(script_content: str) -> Tuple[bool, Optional[str]]:
    """
    Valide la syntaxe bash d'un script (nécessite bash installé)

    Args:
        script_content: Contenu du script bash

    Returns:
        Tuple[bool, str]: (syntaxe_valide, message_erreur)
    """
    import subprocess
    import tempfile

    try:
        # Créer un fichier temporaire
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tmp_file:
            tmp_file.write(script_content)
            tmp_file.flush()

            # Vérifier avec bash -n
            result = subprocess.run(
                ['bash', '-n', tmp_file.name],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Nettoyer le fichier temporaire
            os.unlink(tmp_file.name)

            return result.returncode == 0, result.stderr if result.returncode != 0 else None

    except subprocess.TimeoutExpired:
        return False, "Timeout lors de la validation syntaxique"
    except FileNotFoundError:
        return False, "bash non trouvé pour la validation syntaxique"
    except Exception as e:
        return False, f"Erreur validation syntaxe: {str(e)}"


# === VALIDATION DE DONNÉES JSON ===

def validate_json_data(json_str: str, required_keys: List[str] = None) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Valide des données JSON

    Args:
        json_str: Chaîne JSON à valider
        required_keys: Clés obligatoires dans l'objet JSON

    Returns:
        Tuple[bool, str, dict]: (est_valide, message_erreur, données_parsées)
    """
    if not json_str or not isinstance(json_str, str):
        return False, "Données JSON vides", None

    try:
        data = json.loads(json_str)

        # Vérifier les clés obligatoires
        if required_keys and isinstance(data, dict):
            missing_keys = [key for key in required_keys if key not in data]
            if missing_keys:
                return False, f"Clés manquantes: {', '.join(missing_keys)}", data

        return True, None, data

    except json.JSONDecodeError as e:
        return False, f"JSON invalide: {str(e)}", None


def validate_json_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validation basique de schéma JSON

    Args:
        data: Données à valider
        schema: Schéma de validation simple

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    # Validation très basique des types
    for key, expected_type in schema.items():
        if key not in data:
            errors.append(f"Clé manquante: {key}")
            continue

        value = data[key]

        if expected_type == 'string' and not isinstance(value, str):
            errors.append(f"'{key}' doit être une chaîne")
        elif expected_type == 'number' and not isinstance(value, (int, float)):
            errors.append(f"'{key}' doit être un nombre")
        elif expected_type == 'boolean' and not isinstance(value, bool):
            errors.append(f"'{key}' doit être un booléen")
        elif expected_type == 'array' and not isinstance(value, list):
            errors.append(f"'{key}' doit être un tableau")
        elif expected_type == 'object' and not isinstance(value, dict):
            errors.append(f"'{key}' doit être un objet")

    return len(errors) == 0, errors


# === SANITIZATION ET NETTOYAGE ===

def sanitize_string(input_str: str, allow_html: bool = False, max_length: int = None) -> str:
    """
    Nettoie et sanitise une chaîne de caractères

    Args:
        input_str: Chaîne à nettoyer
        allow_html: Autoriser les balises HTML
        max_length: Longueur maximale

    Returns:
        str: Chaîne nettoyée
    """
    if not input_str or not isinstance(input_str, str):
        return ""

    # Nettoyer les espaces
    cleaned = input_str.strip()

    # Supprimer les caractères de contrôle
    cleaned = ''.join(char for char in cleaned if ord(char) >= 32 or char in '\n\r\t')

    # Supprimer les balises HTML si non autorisées
    if not allow_html:
        import html
        cleaned = html.escape(cleaned)
        # Supprimer les balises HTML restantes
        cleaned = re.sub(r'<[^>]+>', '', cleaned)

    # Limiter la longueur
    if max_length and len(cleaned) > max_length:
        cleaned = cleaned[:max_length]

    return cleaned


def sanitize_filename(filename: str, replacement_char: str = '_') -> str:
    """
    Sanitise un nom de fichier en remplaçant les caractères problématiques

    Args:
        filename: Nom de fichier original
        replacement_char: Caractère de remplacement

    Returns:
        str: Nom de fichier nettoyé
    """
    if not filename:
        return "unnamed_file"

    # Caractères à remplacer
    forbidden_chars = r'[<>:"/\\|?*\x00-\x1f]'

    # Remplacer les caractères interdits
    cleaned = re.sub(forbidden_chars, replacement_char, filename)

    # Supprimer les points en début/fin
    cleaned = cleaned.strip('. ')

    # Limiter la longueur
    if len(cleaned) > 255:
        name, ext = os.path.splitext(cleaned)
        max_name_len = 255 - len(ext)
        cleaned = name[:max_name_len] + ext

    # Assurer qu'on a un nom valide
    if not cleaned or cleaned in ['.', '..']:
        cleaned = "unnamed_file"

    return cleaned


def sanitize_command_input(command: str) -> str:
    """
    Sanitise un input destiné à être utilisé dans une commande shell

    Args:
        command: Commande à sanitiser

    Returns:
        str: Commande nettoyée
    """
    if not command:
        return ""

    # Supprimer les caractères dangereux pour le shell
    dangerous_chars = [';', '&', '|', '`', '(', ')', '{', '}', '[', ']', '<', '>']

    cleaned = command
    for char in dangerous_chars:
        cleaned = cleaned.replace(char, '')

    # Nettoyer les espaces multiples
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    return cleaned


# === VALIDATION COMPOSITE ===

def validate_scan_target(target: str, allow_private: bool = True, check_reachability: bool = False) -> Tuple[
    bool, Optional[str]]:
    """
    Validation complète d'une cible de scan

    Args:
        target: Cible à valider (IP ou domaine)
        allow_private: Autoriser les IPs privées
        check_reachability: Vérifier l'accessibilité

    Returns:
        Tuple[bool, str]: (est_valide, message_erreur)
    """
    if not target:
        return False, "Cible vide"

    target = target.strip()

    # Essayer validation IP
    if validate_ip_address(target, allow_private=allow_private):
        # C'est une IP valide
        if check_reachability:
            try:
                import subprocess
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '3', target],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    return False, f"Cible non accessible: {target}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug(f"Impossible de tester l'accessibilité de {target}")

        return True, None

    # Essayer validation domaine
    if validate_domain(target, check_dns=check_reachability):
        return True, None

    return False, f"Cible invalide (ni IP ni domaine valide): {target}"


def validate_workflow_parameters(params: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Valide les paramètres d'un workflow complet

    Args:
        params: Paramètres du workflow

    Returns:
        Tuple[bool, List[str]]: (est_valide, liste_erreurs)
    """
    errors = []

    # Validation de la cible
    if 'target' in params:
        is_valid, error_msg = validate_scan_target(params['target'])
        if not is_valid:
            errors.append(error_msg)

    # Validation des paramètres de scan
    scan_params = {k: v for k, v in params.items() if k.startswith('scan_') or k in ['target', 'timeout', 'ports']}
    if scan_params:
        is_valid, scan_errors = validate_scan_parameters(scan_params)
        if not is_valid:
            errors.extend(scan_errors)

    # Validation du type de workflow
    if 'workflow_type' in params:
        valid_types = ['scan_only', 'scan_and_analyze', 'full_workflow', 'analyze_existing', 'generate_scripts']
        if params['workflow_type'] not in valid_types:
            errors.append(f"Type de workflow invalide: {params['workflow_type']}")

    # Validation de la priorité
    if 'priority' in params:
        valid_priorities = ['low', 'normal', 'high', 'critical']
        if params['priority'] not in valid_priorities:
            errors.append(f"Priorité invalide: {params['priority']}")

    return len(errors) == 0, errors


# === FONCTIONS UTILITAIRES ===

def get_validation_summary(validation_results: List[Tuple[str, bool, Optional[str]]]) -> Dict[str, Any]:
    """
    Génère un résumé des résultats de validation

    Args:
        validation_results: Liste de (nom_validation, succès, erreur)

    Returns:
        Dict: Résumé des validations
    """
    total = len(validation_results)
    passed = sum(1 for _, success, _ in validation_results if success)
    failed = total - passed

    errors = [error for _, success, error in validation_results if not success and error]

    return {
        'total_validations': total,
        'passed': passed,
        'failed': failed,
        'success_rate': (passed / total * 100) if total > 0 else 0,
        'errors': errors,
        'overall_success': failed == 0
    }


def validate_multiple_targets(targets: List[str], allow_private: bool = True) -> Dict[str, Tuple[bool, Optional[str]]]:
    """
    Valide plusieurs cibles en une fois

    Args:
        targets: Liste des cibles à valider
        allow_private: Autoriser les IPs privées

    Returns:
        Dict: Résultats de validation par cible
    """
    results = {}

    for target in targets:
        is_valid, error_msg = validate_scan_target(target, allow_private=allow_private)
        results[target] = (is_valid, error_msg)

    return results


def create_validation_report(validations: Dict[str, Tuple[bool, Optional[str]]]) -> str:
    """
    Crée un rapport de validation lisible

    Args:
        validations: Résultats de validations

    Returns:
        str: Rapport formaté
    """
    lines = ["=== RAPPORT DE VALIDATION ===\n"]

    total = len(validations)
    passed = sum(1 for valid, _ in validations.values() if valid)

    lines.append(f"Total: {total} validations")
    lines.append(f"Réussies: {passed}")
    lines.append(f"Échouées: {total - passed}")
    lines.append(f"Taux de réussite: {passed / total * 100:.1f}%\n")

    if passed < total:
        lines.append("ERREURS DÉTECTÉES:")
        for item, (valid, error) in validations.items():
            if not valid:
                lines.append(f"  ❌ {item}: {error}")

    if passed > 0:
        lines.append("\nVALIDATIONS RÉUSSIES:")
        for item, (valid, _) in validations.items():
            if valid:
                lines.append(f"  ✅ {item}")

    return "\n".join(lines)


# === CLASSES DE VALIDATION ===

class ValidatorChain:
    """
    Chaîne de validateurs pour validation séquentielle
    """

    def __init__(self):
        self.validators = []

    def add_validator(self, name: str, validator_func, *args, **kwargs):
        """Ajoute un validateur à la chaîne"""
        self.validators.append((name, validator_func, args, kwargs))
        return self

    def validate(self, value: Any) -> Tuple[bool, List[str]]:
        """Exécute tous les validateurs"""
        errors = []

        for name, validator, args, kwargs in self.validators:
            try:
                # Appeler le validateur avec la valeur
                if args or kwargs:
                    result = validator(value, *args, **kwargs)
                else:
                    result = validator(value)

                # Traiter le résultat
                if isinstance(result, tuple):
                    is_valid, error = result[0], result[1] if len(result) > 1 else None
                    if not is_valid:
                        errors.append(f"{name}: {error}" if error else f"{name}: Validation échouée")
                elif isinstance(result, bool):
                    if not result:
                        errors.append(f"{name}: Validation échouée")
                else:
                    errors.append(f"{name}: Résultat de validation invalide")

            except Exception as e:
                errors.append(f"{name}: Erreur lors de la validation - {str(e)}")

        return len(errors) == 0, errors


class ConfigValidator:
    """
    Validateur spécialisé pour les configurations
    """

    def __init__(self, config_schema: Dict[str, Any]):
        self.schema = config_schema

    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Valide une configuration selon le schéma

        Args:
            config: Configuration à valider

        Returns:
            Tuple[bool, List[str]]: (est_valide, erreurs)
        """
        errors = []

        # Vérifier la structure de base
        if not isinstance(config, dict):
            return False, ["Configuration doit être un dictionnaire"]

        # Valider chaque section
        for section, section_schema in self.schema.items():
            if section not in config:
                if section_schema.get('required', True):
                    errors.append(f"Section obligatoire manquante: {section}")
                continue

            section_config = config[section]
            section_errors = self._validate_section(section, section_config, section_schema)
            errors.extend(section_errors)

        return len(errors) == 0, errors

    def _validate_section(self, section_name: str, section_config: Any, section_schema: Dict[str, Any]) -> List[str]:
        """Valide une section spécifique"""
        errors = []

        expected_type = section_schema.get('type', 'object')

        if expected_type == 'object' and not isinstance(section_config, dict):
            errors.append(f"Section '{section_name}' doit être un objet")
            return errors

        # Valider les champs de la section
        fields = section_schema.get('fields', {})
        for field_name, field_schema in fields.items():
            if field_name not in section_config:
                if field_schema.get('required', False):
                    errors.append(f"Champ obligatoire manquant: {section_name}.{field_name}")
                continue

            field_value = section_config[field_name]
            field_errors = self._validate_field(
                f"{section_name}.{field_name}",
                field_value,
                field_schema
            )
            errors.extend(field_errors)

        return errors

    def _validate_field(self, field_path: str, field_value: Any, field_schema: Dict[str, Any]) -> List[str]:
        """Valide un champ spécifique"""
        errors = []

        field_type = field_schema.get('type', 'string')

        # Validation du type
        type_validators = {
            'string': lambda x: isinstance(x, str),
            'integer': lambda x: isinstance(x, int),
            'number': lambda x: isinstance(x, (int, float)),
            'boolean': lambda x: isinstance(x, bool),
            'array': lambda x: isinstance(x, list),
            'object': lambda x: isinstance(x, dict)
        }

        validator = type_validators.get(field_type)
        if validator and not validator(field_value):
            errors.append(f"Type invalide pour {field_path}: attendu {field_type}")
            return errors

        # Validations spécifiques
        if field_type == 'string':
            min_len = field_schema.get('min_length')
            max_len = field_schema.get('max_length')
            pattern = field_schema.get('pattern')

            if min_len and len(field_value) < min_len:
                errors.append(f"{field_path} trop court (min: {min_len})")
            if max_len and len(field_value) > max_len:
                errors.append(f"{field_path} trop long (max: {max_len})")
            if pattern and not re.match(pattern, field_value):
                errors.append(f"{field_path} ne correspond pas au pattern requis")

        elif field_type in ['integer', 'number']:
            min_val = field_schema.get('minimum')
            max_val = field_schema.get('maximum')

            if min_val is not None and field_value < min_val:
                errors.append(f"{field_path} trop petit (min: {min_val})")
            if max_val is not None and field_value > max_val:
                errors.append(f"{field_path} trop grand (max: {max_val})")

        elif field_type == 'array':
            min_items = field_schema.get('min_items')
            max_items = field_schema.get('max_items')

            if min_items and len(field_value) < min_items:
                errors.append(f"{field_path} pas assez d'éléments (min: {min_items})")
            if max_items and len(field_value) > max_items:
                errors.append(f"{field_path} trop d'éléments (max: {max_items})")

        return errors


# === TESTS ET EXEMPLES ===

def run_validation_tests():
    """Lance une série de tests de validation"""
    print("=== Tests de validation ===\n")

    # Test validation IP
    print("Test validation IP:")
    test_ips = ["192.168.1.1", "invalid", "10.0.0.1", "256.256.256.256", "::1"]
    for ip in test_ips:
        valid = validate_ip_address(ip)
        print(f"  {ip}: {'✅' if valid else '❌'}")

    # Test validation domaine
    print("\nTest validation domaine:")
    test_domains = ["example.com", "sub.example.com", "invalid..domain", "valid-domain.org"]
    for domain in test_domains:
        valid = validate_domain(domain)
        print(f"  {domain}: {'✅' if valid else '❌'}")

    # Test validation CVE
    print("\nTest validation CVE:")
    test_cves = ["CVE-2024-1234", "CVE-2023-12345", "invalid-cve", "CVE-24-123"]
    for cve in test_cves:
        valid = validate_cve_id(cve)
        print(f"  {cve}: {'✅' if valid else '❌'}")

    # Test chaîne de validateurs
    print("\nTest chaîne de validateurs:")
    chain = ValidatorChain()
    chain.add_validator("IP", validate_ip_address)
    chain.add_validator("Private", lambda ip: not is_ip_in_private_ranges(ip))

    test_ip = "8.8.8.8"
    valid, errors = chain.validate(test_ip)
    print(f"  {test_ip}: {'✅' if valid else '❌'} {errors}")

    print("\n=== Tests terminés ===")


if __name__ == "__main__":
    run_validation_tests()