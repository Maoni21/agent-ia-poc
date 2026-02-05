"""
Module Security pour l'Agent IA de Cybersécurité

Ce module fournit des utilitaires de sécurité pour l'application :
- Validation et nettoyage des inputs
- Chiffrement et hachage sécurisé
- Génération de tokens et mots de passe
- Validation de scripts bash
- Sandboxing et isolation
- Audit de sécurité des données

Fonctionnalités :
- Protection contre les injections de commandes
- Validation des scripts générés par l'IA
- Chiffrement des données sensibles
- Authentification et autorisation
- Audit trail sécurisé
- Détection de patterns malveillants
"""

import hashlib
import hmac
import os
import re
import secrets
import subprocess
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Set
import base64
import json
import shlex
from dataclasses import dataclass
from enum import Enum
import logging

from .logger import setup_logger

# Configuration du logging
logger = setup_logger(__name__)


# === ÉNUMÉRATIONS ===

class SecurityLevel(Enum):
    """Niveaux de sécurité pour la validation"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatLevel(Enum):
    """Niveaux de menace détectés"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    MALICIOUS = "malicious"


class ValidationResult(Enum):
    """Résultats de validation"""
    APPROVED = "approved"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"


# === STRUCTURES DE DONNÉES ===

@dataclass
class SecurityCheck:
    """Résultat d'une vérification de sécurité"""
    check_type: str
    status: bool
    threat_level: ThreatLevel
    message: str
    details: Dict[str, Any]
    timestamp: datetime


@dataclass
class ScriptValidation:
    """Résultat de validation d'un script"""
    script_hash: str
    is_safe: bool
    validation_result: ValidationResult
    threat_level: ThreatLevel
    issues: List[Dict[str, Any]]
    recommendations: List[str]
    execution_risk: str
    validated_at: datetime


@dataclass
class InputSanitization:
    """Résultat de nettoyage d'input"""
    original_input: str
    sanitized_input: str
    threats_removed: List[str]
    is_safe: bool
    modifications_made: bool


# === VALIDATION DES INPUTS ===

class InputValidator:
    """Validateur d'inputs pour prévenir les injections"""

    # Patterns dangereux pour injection de commandes
    DANGEROUS_PATTERNS = [
        # Injection de commandes
        r'[;&|`$(){}[\]<>]',
        r'\$\([^)]*\)',  # Command substitution
        r'`[^`]*`',  # Backticks
        r'&&|\|\|',  # Logical operators
        r';\s*\w+',  # Command chaining

        # Path traversal
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e\\',

        # SQL Injection basique
        r"'.*(?:or|and|union|select|insert|update|delete|drop).*'",
        r'--\s*$',
        r'/\*.*\*/',

        # XSS basique
        r'<script[^>]*>',
        r'javascript:',
        r'onload\s*=',
        r'onclick\s*=',

        # Autres patterns dangereux
        r'rm\s+-rf',
        r'sudo\s+',
        r'wget\s+',
        r'curl\s+',
    ]

    # Extensions de fichiers dangereuses
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi'
    }

    @staticmethod
    def validate_ip_input(ip_input: str) -> Tuple[bool, str]:
        """
        Valide un input d'adresse IP

        Args:
            ip_input: Input à valider

        Returns:
            Tuple[bool, str]: (est_valide, message_erreur)
        """
        if not ip_input:
            return False, "Adresse IP vide"

        # Nettoyer l'input
        cleaned_ip = ip_input.strip()

        # Vérifier les caractères autorisés (IP ou hostname)
        if not re.match(r'^[a-zA-Z0-9.-]+$', cleaned_ip):
            return False, "Caractères non autorisés dans l'adresse"

        # Vérifier la longueur
        if len(cleaned_ip) > 255:
            return False, "Adresse trop longue"

        # Patterns dangereux spécifiques aux IPs
        dangerous_ip_patterns = [
            r'[;&|`$]',  # Injection de commandes
            r'\.\./',  # Path traversal
            r'<|>',  # Redirection
        ]

        for pattern in dangerous_ip_patterns:
            if re.search(pattern, cleaned_ip):
                return False, f"Pattern dangereux détecté: {pattern}"

        return True, "Adresse IP valide"

    @staticmethod
    def validate_filename(filename: str, allow_path: bool = False) -> Tuple[bool, str]:
        """
        Valide un nom de fichier

        Args:
            filename: Nom de fichier à valider
            allow_path: Autoriser les chemins complets

        Returns:
            Tuple[bool, str]: (est_valide, message_erreur)
        """
        if not filename:
            return False, "Nom de fichier vide"

        # Nettoyer l'input
        cleaned_name = filename.strip()

        # Vérifier la longueur
        if len(cleaned_name) > 255:
            return False, "Nom de fichier trop long"

        # Vérifier les caractères interdits
        forbidden_chars = ['<', '>', ':', '"', '|', '?', '*']
        if not allow_path:
            forbidden_chars.extend(['/', '\\'])

        for char in forbidden_chars:
            if char in cleaned_name:
                return False, f"Caractère interdit: {char}"

        # Vérifier les noms réservés Windows
        reserved_names = [
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
            'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        ]

        name_without_ext = cleaned_name.split('.')[0].upper()
        if name_without_ext in reserved_names:
            return False, f"Nom de fichier réservé: {name_without_ext}"

        # Vérifier l'extension
        if '.' in cleaned_name:
            ext = Path(cleaned_name).suffix.lower()
            if ext in InputValidator.DANGEROUS_EXTENSIONS:
                return False, f"Extension dangereuse: {ext}"

        # Vérifier le path traversal
        if '../' in cleaned_name or '..\\' in cleaned_name:
            return False, "Tentative de path traversal détectée"

        return True, "Nom de fichier valide"

    @staticmethod
    def sanitize_shell_input(input_string: str) -> InputSanitization:
        """
        Nettoie un input destiné au shell

        Args:
            input_string: String à nettoyer

        Returns:
            InputSanitization: Résultat du nettoyage
        """
        if not input_string:
            return InputSanitization(
                original_input="",
                sanitized_input="",
                threats_removed=[],
                is_safe=True,
                modifications_made=False
            )

        original = input_string
        sanitized = input_string
        threats_removed = []
        modifications_made = False

        # Supprimer les caractères dangereux
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>']
        for char in dangerous_chars:
            if char in sanitized:
                sanitized = sanitized.replace(char, '')
                threats_removed.append(f"Caractère dangereux: {char}")
                modifications_made = True

        # Supprimer les patterns de substitution de commande
        command_substitution = [r'\$\([^)]*\)', r'`[^`]*`']
        for pattern in command_substitution:
            matches = re.findall(pattern, sanitized)
            if matches:
                for match in matches:
                    sanitized = sanitized.replace(match, '')
                    threats_removed.append(f"Substitution de commande: {match}")
                    modifications_made = True

        # Nettoyer les espaces multiples
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        if sanitized != original.strip():
            modifications_made = True

        # Vérifier si le résultat est sûr
        is_safe = len(threats_removed) == 0

        return InputSanitization(
            original_input=original,
            sanitized_input=sanitized,
            threats_removed=threats_removed,
            is_safe=is_safe,
            modifications_made=modifications_made
        )

    @staticmethod
    def validate_command_args(args: List[str]) -> Tuple[bool, List[str]]:
        """
        Valide une liste d'arguments de commande

        Args:
            args: Liste d'arguments

        Returns:
            Tuple[bool, List[str]]: (est_valide, erreurs)
        """
        errors = []

        if not args:
            return True, []

        for i, arg in enumerate(args):
            if not isinstance(arg, str):
                errors.append(f"Argument {i} n'est pas une string")
                continue

            # Vérifier chaque argument
            for pattern in InputValidator.DANGEROUS_PATTERNS[:5]:  # Patterns de base
                if re.search(pattern, arg):
                    errors.append(f"Pattern dangereux dans l'argument {i}: {pattern}")

        return len(errors) == 0, errors


# === VALIDATION DE SCRIPTS ===

class ScriptValidator:
    """Validateur de scripts bash pour prévenir l'exécution de code malveillant"""

    # Commandes considérées comme dangereuses
    DANGEROUS_COMMANDS = {
        # Commandes destructrices
        'rm': ThreatLevel.DANGEROUS,
        'rmdir': ThreatLevel.SUSPICIOUS,
        'dd': ThreatLevel.DANGEROUS,
        'shred': ThreatLevel.DANGEROUS,
        'wipefs': ThreatLevel.DANGEROUS,
        'mkfs': ThreatLevel.DANGEROUS,
        'fdisk': ThreatLevel.DANGEROUS,
        'parted': ThreatLevel.DANGEROUS,

        # Commandes système
        'reboot': ThreatLevel.SUSPICIOUS,
        'shutdown': ThreatLevel.SUSPICIOUS,
        'halt': ThreatLevel.SUSPICIOUS,
        'init': ThreatLevel.SUSPICIOUS,
        'systemctl': ThreatLevel.SUSPICIOUS,
        'service': ThreatLevel.SUSPICIOUS,

        # Commandes réseau
        'iptables': ThreatLevel.SUSPICIOUS,
        'ufw': ThreatLevel.SUSPICIOUS,
        'firewall-cmd': ThreatLevel.SUSPICIOUS,
        'netsh': ThreatLevel.SUSPICIOUS,

        # Commandes de téléchargement
        'wget': ThreatLevel.SUSPICIOUS,
        'curl': ThreatLevel.SUSPICIOUS,
        'nc': ThreatLevel.SUSPICIOUS,
        'netcat': ThreatLevel.SUSPICIOUS,

        # Commandes privilégiées
        'sudo': ThreatLevel.SUSPICIOUS,
        'su': ThreatLevel.SUSPICIOUS,
        'passwd': ThreatLevel.SUSPICIOUS,
        'usermod': ThreatLevel.SUSPICIOUS,
        'adduser': ThreatLevel.SUSPICIOUS,
        'userdel': ThreatLevel.SUSPICIOUS,

        # Fork bombs et patterns dangereux
        ':(': ThreatLevel.MALICIOUS,
        'while true': ThreatLevel.SUSPICIOUS,
    }

    # Patterns de scripts malveillants
    MALICIOUS_PATTERNS = [
        # Fork bomb
        r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:',

        # Suppression récursive dangereuse
        r'rm\s+-rf\s+/',
        r'rm\s+-rf\s+\*',
        r'rm\s+-rf\s+~',

        # Redirection vers des fichiers système
        r'>\s*/etc/',
        r'>\s*/bin/',
        r'>\s*/usr/bin/',
        r'>\s*/sbin/',

        # Téléchargement et exécution
        r'(wget|curl).*\|\s*(bash|sh)',
        r'(wget|curl).*&&.*\.(sh|py|pl)',

        # Backdoors
        r'nc\s+-l.*-e\s*(bash|sh)',
        r'/dev/tcp/.*bash',

        # Modification de fichiers critiques
        r'>\s*/etc/passwd',
        r'>\s*/etc/shadow',
        r'>\s*/etc/sudoers',

        # Cron jobs suspects
        r'crontab.*-e',
        r'\*.*\*.*\*.*\*.*\*.*bash',
    ]

    @staticmethod
    def validate_bash_script(script_content: str,
                             security_level: SecurityLevel = SecurityLevel.MEDIUM) -> ScriptValidation:
        """
        Valide un script bash pour détecter les risques de sécurité

        Args:
            script_content: Contenu du script à valider
            security_level: Niveau de sécurité pour la validation

        Returns:
            ScriptValidation: Résultat détaillé de la validation
        """
        if not script_content:
            return ScriptValidation(
                script_hash="",
                is_safe=False,
                validation_result=ValidationResult.REJECTED,
                threat_level=ThreatLevel.SUSPICIOUS,
                issues=[{"type": "empty_script", "message": "Script vide"}],
                recommendations=["Fournir un script non vide"],
                execution_risk="HIGH",
                validated_at=datetime.utcnow()
            )

        # Calculer le hash du script
        script_hash = hashlib.sha256(script_content.encode()).hexdigest()

        issues = []
        recommendations = []
        max_threat_level = ThreatLevel.SAFE

        # Vérifications de base
        basic_checks = ScriptValidator._perform_basic_checks(script_content)
        issues.extend(basic_checks)

        # Vérifier les commandes dangereuses
        dangerous_commands = ScriptValidator._check_dangerous_commands(script_content)
        issues.extend(dangerous_commands)

        # Vérifier les patterns malveillants
        malicious_patterns = ScriptValidator._check_malicious_patterns(script_content)
        issues.extend(malicious_patterns)

        # Vérifier la syntaxe bash
        syntax_check = ScriptValidator._validate_bash_syntax(script_content)
        if not syntax_check['valid']:
            issues.append({
                "type": "syntax_error",
                "severity": "HIGH",
                "message": f"Erreur de syntaxe: {syntax_check['error']}"
            })

        # Déterminer le niveau de menace maximum
        for issue in issues:
            issue_threat = ThreatLevel(issue.get('threat_level', ThreatLevel.SAFE.value))
            if issue_threat.value == ThreatLevel.MALICIOUS.value:
                max_threat_level = ThreatLevel.MALICIOUS
            elif issue_threat.value == ThreatLevel.DANGEROUS.value and max_threat_level != ThreatLevel.MALICIOUS:
                max_threat_level = ThreatLevel.DANGEROUS
            elif issue_threat.value == ThreatLevel.SUSPICIOUS.value and max_threat_level == ThreatLevel.SAFE:
                max_threat_level = ThreatLevel.SUSPICIOUS

        # Générer les recommandations
        recommendations = ScriptValidator._generate_recommendations(issues, security_level)

        # Déterminer le résultat de validation
        validation_result = ScriptValidator._determine_validation_result(
            max_threat_level, security_level, issues
        )

        # Évaluer le risque d'exécution
        execution_risk = ScriptValidator._assess_execution_risk(max_threat_level, issues)

        is_safe = max_threat_level == ThreatLevel.SAFE and validation_result == ValidationResult.APPROVED

        return ScriptValidation(
            script_hash=script_hash,
            is_safe=is_safe,
            validation_result=validation_result,
            threat_level=max_threat_level,
            issues=issues,
            recommendations=recommendations,
            execution_risk=execution_risk,
            validated_at=datetime.utcnow()
        )

    @staticmethod
    def _perform_basic_checks(script_content: str) -> List[Dict[str, Any]]:
        """Vérifications de base du script"""
        issues = []

        # Vérifier la longueur
        if len(script_content) > 50000:  # 50KB
            issues.append({
                "type": "script_too_long",
                "severity": "MEDIUM",
                "threat_level": ThreatLevel.SUSPICIOUS.value,
                "message": "Script exceptionnellement long (>50KB)"
            })

        # Vérifier la présence de shebang
        if not script_content.startswith('#!'):
            issues.append({
                "type": "missing_shebang",
                "severity": "LOW",
                "threat_level": ThreatLevel.SAFE.value,
                "message": "Shebang manquant (#!/bin/bash recommandé)"
            })

        # Vérifier la présence de 'set -e' pour la gestion d'erreur
        if 'set -e' not in script_content and 'set -euo pipefail' not in script_content:
            issues.append({
                "type": "no_error_handling",
                "severity": "MEDIUM",
                "threat_level": ThreatLevel.SAFE.value,
                "message": "Pas de gestion d'erreur (set -e recommandé)"
            })

        # Vérifier les caractères non-ASCII
        try:
            script_content.encode('ascii')
        except UnicodeEncodeError:
            issues.append({
                "type": "non_ascii_chars",
                "severity": "LOW",
                "threat_level": ThreatLevel.SAFE.value,
                "message": "Caractères non-ASCII détectés"
            })

        return issues

    @staticmethod
    def _check_dangerous_commands(script_content: str) -> List[Dict[str, Any]]:
        """Vérifie les commandes dangereuses dans le script"""
        issues = []
        lines = script_content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Vérifier chaque commande dangereuse
            for cmd, threat_level in ScriptValidator.DANGEROUS_COMMANDS.items():
                if re.search(r'\b' + re.escape(cmd) + r'\b', line):
                    severity = "HIGH" if threat_level == ThreatLevel.MALICIOUS else \
                        "MEDIUM" if threat_level == ThreatLevel.DANGEROUS else "LOW"

                    issues.append({
                        "type": "dangerous_command",
                        "severity": severity,
                        "threat_level": threat_level.value,
                        "message": f"Commande potentiellement dangereuse: {cmd}",
                        "line_number": line_num,
                        "line_content": line,
                        "command": cmd
                    })

        return issues

    @staticmethod
    def _check_malicious_patterns(script_content: str) -> List[Dict[str, Any]]:
        """Vérifie les patterns malveillants dans le script"""
        issues = []

        for pattern in ScriptValidator.MALICIOUS_PATTERNS:
            matches = list(re.finditer(pattern, script_content, re.IGNORECASE | re.MULTILINE))

            for match in matches:
                # Trouver le numéro de ligne
                line_num = script_content[:match.start()].count('\n') + 1
                line_start = script_content.rfind('\n', 0, match.start()) + 1
                line_end = script_content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(script_content)
                line_content = script_content[line_start:line_end]

                issues.append({
                    "type": "malicious_pattern",
                    "severity": "CRITICAL",
                    "threat_level": ThreatLevel.MALICIOUS.value,
                    "message": f"Pattern malveillant détecté: {match.group()}",
                    "line_number": line_num,
                    "line_content": line_content.strip(),
                    "pattern": pattern
                })

        return issues

    @staticmethod
    def _validate_bash_syntax(script_content: str) -> Dict[str, Any]:
        """Valide la syntaxe bash d'un script"""
        try:
            # Créer un fichier temporaire
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as tmp_file:
                tmp_file.write(script_content)
                tmp_file.flush()

                # Vérifier la syntaxe avec bash -n
                result = subprocess.run(
                    ['bash', '-n', tmp_file.name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Nettoyer le fichier temporaire
                os.unlink(tmp_file.name)

                return {
                    "valid": result.returncode == 0,
                    "error": result.stderr if result.returncode != 0 else None
                }

        except subprocess.TimeoutExpired:
            return {
                "valid": False,
                "error": "Timeout lors de la validation syntaxique"
            }
        except Exception as e:
            return {
                "valid": False,
                "error": f"Erreur validation syntaxe: {str(e)}"
            }

    @staticmethod
    def _generate_recommendations(issues: List[Dict[str, Any]], security_level: SecurityLevel) -> List[str]:
        """Génère des recommandations basées sur les problèmes détectés"""
        recommendations = []

        # Recommandations spécifiques par type de problème
        issue_types = [issue['type'] for issue in issues]

        if 'malicious_pattern' in issue_types:
            recommendations.append("CRITIQUE: Script contenant des patterns malveillants - NE PAS EXÉCUTER")

        if 'dangerous_command' in issue_types:
            recommendations.append("Réviser attentivement les commandes dangereuses avant exécution")
            recommendations.append("Tester dans un environnement isolé")

        if 'syntax_error' in issue_types:
            recommendations.append("Corriger les erreurs de syntaxe avant exécution")

        if 'no_error_handling' in issue_types:
            recommendations.append("Ajouter 'set -euo pipefail' pour une meilleure gestion d'erreur")

        if 'missing_shebang' in issue_types:
            recommendations.append("Ajouter un shebang approprié (#!/bin/bash)")

        # Recommandations générales selon le niveau de sécurité
        if security_level == SecurityLevel.CRITICAL:
            recommendations.append("Validation manuelle requise par un expert sécurité")
            recommendations.append("Exécution uniquement en environnement de test isolé")

        elif security_level == SecurityLevel.HIGH:
            recommendations.append("Révision approfondie recommandée")
            recommendations.append("Sauvegarde du système avant exécution")

        return recommendations

    @staticmethod
    def _determine_validation_result(
            threat_level: ThreatLevel,
            security_level: SecurityLevel,
            issues: List[Dict[str, Any]]
    ) -> ValidationResult:
        """Détermine le résultat de validation final"""

        # Rejet automatique pour patterns malveillants
        if threat_level == ThreatLevel.MALICIOUS:
            return ValidationResult.REJECTED

        # Logique selon niveau de sécurité
        if security_level == SecurityLevel.CRITICAL:
            if threat_level in [ThreatLevel.DANGEROUS, ThreatLevel.SUSPICIOUS]:
                return ValidationResult.REJECTED
            else:
                return ValidationResult.REVIEW_REQUIRED

        elif security_level == SecurityLevel.HIGH:
            if threat_level == ThreatLevel.DANGEROUS:
                return ValidationResult.REJECTED
            elif threat_level == ThreatLevel.SUSPICIOUS:
                return ValidationResult.REVIEW_REQUIRED
            else:
                return ValidationResult.APPROVED

        elif security_level == SecurityLevel.MEDIUM:
            if threat_level == ThreatLevel.DANGEROUS:
                return ValidationResult.REVIEW_REQUIRED
            elif threat_level == ThreatLevel.SUSPICIOUS:
                critical_issues = [i for i in issues if i.get('severity') == 'CRITICAL']
                return ValidationResult.REVIEW_REQUIRED if critical_issues else ValidationResult.APPROVED
            else:
                return ValidationResult.APPROVED

        else:  # LOW
            if threat_level == ThreatLevel.DANGEROUS:
                return ValidationResult.REVIEW_REQUIRED
            else:
                return ValidationResult.APPROVED

    @staticmethod
    def _assess_execution_risk(threat_level: ThreatLevel, issues: List[Dict[str, Any]]) -> str:
        """Évalue le risque d'exécution du script"""

        if threat_level == ThreatLevel.MALICIOUS:
            return "CRITICAL"
        elif threat_level == ThreatLevel.DANGEROUS:
            return "HIGH"
        elif threat_level == ThreatLevel.SUSPICIOUS:
            # Vérifier la sévérité des problèmes
            critical_count = len([i for i in issues if i.get('severity') == 'CRITICAL'])
            high_count = len([i for i in issues if i.get('severity') == 'HIGH'])

            if critical_count > 0:
                return "HIGH"
            elif high_count > 2:
                return "MEDIUM"
            else:
                return "LOW"
        else:
            return "LOW"


# === CHIFFREMENT ET HACHAGE ===

class CryptoUtils:
    """Utilitaires de chiffrement et hachage sécurisé"""

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Génère un token sécurisé

        Args:
            length: Longueur du token

        Returns:
            str: Token sécurisé en base64
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('ascii')

    @staticmethod
    def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """
        Hache un mot de passe avec salt

        Args:
            password: Mot de passe à hacher
            salt: Salt optionnel (généré si non fourni)

        Returns:
            Tuple[str, str]: (hash_hex, salt_hex)
        """
        if salt is None:
            salt = secrets.token_bytes(32)

        # Utiliser PBKDF2 avec SHA-256
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        return hash_bytes.hex(), salt.hex()

    @staticmethod
    def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
        """
        Vérifie un mot de passe contre son hash

        Args:
            password: Mot de passe à vérifier
            hash_hex: Hash stocké (hex)
            salt_hex: Salt utilisé (hex)

        Returns:
            bool: True si le mot de passe correspond
        """
        try:
            salt = bytes.fromhex(salt_hex)
            expected_hash = bytes.fromhex(hash_hex)

            actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            return hmac.compare_digest(expected_hash, actual_hash)
        except Exception:
            return False

    @staticmethod
    def generate_hmac(message: str, secret_key: str) -> str:
        """
        Génère un HMAC pour l'intégrité des données

        Args:
            message: Message à signer
            secret_key: Clé secrète

        Returns:
            str: HMAC en hexadécimal
        """
        return hmac.new(
            secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_hmac(message: str, secret_key: str, expected_hmac: str) -> bool:
        """
        Vérifie un HMAC

        Args:
            message: Message original
            secret_key: Clé secrète
            expected_hmac: HMAC attendu

        Returns:
            bool: True si le HMAC est valide
        """
        try:
            actual_hmac = CryptoUtils.generate_hmac(message, secret_key)
            return hmac.compare_digest(expected_hmac, actual_hmac)
        except Exception:
            return False

    @staticmethod
    def hash_file(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
        """
        Calcule le hash d'un fichier

        Args:
            file_path: Chemin vers le fichier
            algorithm: Algorithme de hachage (md5, sha1, sha256, sha512)

        Returns:
            str: Hash du fichier en hexadécimal
        """
        hash_obj = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    @staticmethod
    def secure_random_string(length: int = 16, charset: str = None) -> str:
        """
        Génère une chaîne aléatoire sécurisée

        Args:
            length: Longueur de la chaîne
            charset: Jeu de caractères (par défaut: alphanumerique)

        Returns:
            str: Chaîne aléatoire
        """
        if charset is None:
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

        return ''.join(secrets.choice(charset) for _ in range(length))


# === AUDIT ET LOGGING SÉCURISÉ ===

class SecurityAuditor:
    """Auditeur de sécurité pour tracer les actions sensibles"""

    def __init__(self, audit_file: str = "logs/security_audit.log"):
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(exist_ok=True)
        self.logger = setup_logger(f"{__name__}.audit")

    def log_security_event(
            self,
            event_type: str,
            user_id: str,
            action: str,
            target: str = None,
            result: str = "SUCCESS",
            details: Dict[str, Any] = None,
            risk_level: str = "LOW"
    ):
        """
        Log un événement de sécurité

        Args:
            event_type: Type d'événement (AUTH, SCAN, SCRIPT_GEN, etc.)
            user_id: Identifiant de l'utilisateur
            action: Action effectuée
            target: Cible de l'action
            result: Résultat (SUCCESS, FAILURE, BLOCKED)
            details: Détails supplémentaires
            risk_level: Niveau de risque (LOW, MEDIUM, HIGH, CRITICAL)
        """
        event_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'action': action,
            'target': target,
            'result': result,
            'risk_level': risk_level,
            'source_ip': self._get_source_ip(),
            'details': details or {}
        }

        # Calculer un hash d'intégrité
        event_json = json.dumps(event_data, sort_keys=True)
        event_data['integrity_hash'] = hashlib.sha256(event_json.encode()).hexdigest()

        # Logger l'événement
        log_message = f"[{event_type}] {user_id} -> {action}"
        if target:
            log_message += f" on {target}"
        log_message += f" [{result}]"

        if risk_level in ['HIGH', 'CRITICAL']:
            self.logger.warning(f"{log_message} | {json.dumps(event_data)}")
        else:
            self.logger.info(f"{log_message} | {json.dumps(event_data)}")

        # Écrire dans le fichier d'audit
        self._write_audit_log(event_data)

    def _get_source_ip(self) -> str:
        """Récupère l'IP source (simulé pour CLI)"""
        return "127.0.0.1"  # À adapter selon le contexte

    def _write_audit_log(self, event_data: Dict[str, Any]):
        """Écrit dans le fichier d'audit sécurisé"""
        try:
            with open(self.audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event_data) + '\n')
        except Exception as e:
            self.logger.error(f"Erreur écriture audit: {e}")

    def get_security_events(
            self,
            start_time: datetime = None,
            end_time: datetime = None,
            event_type: str = None,
            user_id: str = None,
            risk_level: str = None
    ) -> List[Dict[str, Any]]:
        """
        Récupère les événements de sécurité avec filtres

        Args:
            start_time: Date de début
            end_time: Date de fin
            event_type: Type d'événement à filtrer
            user_id: Utilisateur à filtrer
            risk_level: Niveau de risque minimum

        Returns:
            List[Dict]: Liste des événements correspondants
        """
        events = []

        try:
            if not self.audit_file.exists():
                return events

            with open(self.audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        event = json.loads(line.strip())

                        # Appliquer les filtres
                        event_time = datetime.fromisoformat(event['timestamp'])

                        if start_time and event_time < start_time:
                            continue
                        if end_time and event_time > end_time:
                            continue
                        if event_type and event['event_type'] != event_type:
                            continue
                        if user_id and event['user_id'] != user_id:
                            continue
                        if risk_level and not self._risk_level_matches(
                                event['risk_level'], risk_level
                        ):
                            continue

                        events.append(event)

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            self.logger.error(f"Erreur lecture audit: {e}")

        return events

    def _risk_level_matches(self, event_risk: str, min_risk: str) -> bool:
        """Vérifie si le niveau de risque correspond au filtre"""
        risk_levels = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        event_level = risk_levels.get(event_risk, 1)
        min_level = risk_levels.get(min_risk, 1)
        return event_level >= min_level


# === DÉTECTION D'ANOMALIES ===

class AnomalyDetector:
    """Détecteur d'anomalies et de comportements suspects"""

    def __init__(self):
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Écarts-types
        self.logger = setup_logger(f"{__name__}.anomaly")

    def analyze_script_behavior(self, script_content: str) -> Dict[str, Any]:
        """
        Analyse le comportement d'un script pour détecter les anomalies

        Args:
            script_content: Contenu du script

        Returns:
            Dict: Résultat de l'analyse comportementale
        """
        analysis = {
            'script_metrics': self._extract_script_metrics(script_content),
            'anomalies': [],
            'risk_score': 0.0,
            'behavioral_flags': []
        }

        metrics = analysis['script_metrics']

        # Détection d'anomalies basées sur les métriques

        # 1. Longueur anormale
        if metrics['length'] > 10000:
            analysis['anomalies'].append({
                'type': 'unusual_length',
                'severity': 'MEDIUM',
                'description': f"Script exceptionnellement long ({metrics['length']} caractères)"
            })
            analysis['risk_score'] += 0.3

        # 2. Trop de commandes système
        if metrics['system_commands'] > 10:
            analysis['anomalies'].append({
                'type': 'excessive_system_commands',
                'severity': 'HIGH',
                'description': f"Nombre élevé de commandes système ({metrics['system_commands']})"
            })
            analysis['risk_score'] += 0.5

        # 3. Ratio de commentaires faible (potentiel obfuscation)
        if metrics['line_count'] > 20 and metrics['comment_ratio'] < 0.1:
            analysis['anomalies'].append({
                'type': 'low_comment_ratio',
                'severity': 'LOW',
                'description': "Très peu de commentaires pour un script long"
            })
            analysis['risk_score'] += 0.2

        # 4. Commandes de réseau suspectes
        if metrics['network_commands'] > 3:
            analysis['anomalies'].append({
                'type': 'excessive_network_activity',
                'severity': 'HIGH',
                'description': f"Nombreuses commandes réseau ({metrics['network_commands']})"
            })
            analysis['risk_score'] += 0.6

        # 5. Patterns d'obfuscation
        if metrics['obfuscation_score'] > 0.5:
            analysis['anomalies'].append({
                'type': 'potential_obfuscation',
                'severity': 'HIGH',
                'description': "Patterns d'obfuscation détectés"
            })
            analysis['risk_score'] += 0.7

        # Flags comportementaux
        if analysis['risk_score'] > 1.0:
            analysis['behavioral_flags'].append('HIGH_RISK_BEHAVIOR')

        if metrics['downloads'] > 0:
            analysis['behavioral_flags'].append('DOWNLOADS_FILES')

        if metrics['privilege_escalation'] > 0:
            analysis['behavioral_flags'].append('ESCALATES_PRIVILEGES')

        if metrics['persistence_indicators'] > 0:
            analysis['behavioral_flags'].append('PERSISTENCE_MECHANISMS')

        return analysis

    def _extract_script_metrics(self, script_content: str) -> Dict[str, Any]:
        """Extrait des métriques comportementales du script"""
        lines = script_content.split('\n')

        metrics = {
            'length': len(script_content),
            'line_count': len(lines),
            'comment_lines': 0,
            'empty_lines': 0,
            'system_commands': 0,
            'network_commands': 0,
            'file_operations': 0,
            'downloads': 0,
            'privilege_escalation': 0,
            'persistence_indicators': 0,
            'obfuscation_score': 0.0,
            'entropy': 0.0
        }

        # Compter les types de lignes
        for line in lines:
            line = line.strip()
            if not line:
                metrics['empty_lines'] += 1
            elif line.startswith('#'):
                metrics['comment_lines'] += 1

        # Commandes système
        system_commands = ['systemctl', 'service', 'reboot', 'shutdown', 'mount']
        for cmd in system_commands:
            metrics['system_commands'] += script_content.count(cmd)

        # Commandes réseau
        network_commands = ['wget', 'curl', 'nc', 'netcat', 'ssh', 'scp', 'ftp']
        for cmd in network_commands:
            metrics['network_commands'] += script_content.count(cmd)

        # Opérations sur fichiers
        file_operations = ['rm ', 'cp ', 'mv ', 'chmod', 'chown']
        for op in file_operations:
            metrics['file_operations'] += script_content.count(op)

        # Téléchargements
        if 'wget' in script_content or 'curl' in script_content:
            metrics['downloads'] += script_content.count('wget') + script_content.count('curl')

        # Escalade de privilèges
        privilege_commands = ['sudo', 'su ', 'passwd']
        for cmd in privilege_commands:
            metrics['privilege_escalation'] += script_content.count(cmd)

        # Indicateurs de persistance
        persistence_indicators = ['crontab', '/etc/rc', 'systemd', '.bashrc']
        for indicator in persistence_indicators:
            metrics['persistence_indicators'] += script_content.count(indicator)

        # Score d'obfuscation
        metrics['obfuscation_score'] = self._calculate_obfuscation_score(script_content)

        # Entropie (complexité)
        metrics['entropy'] = self._calculate_entropy(script_content)

        # Ratio de commentaires
        if metrics['line_count'] > 0:
            metrics['comment_ratio'] = metrics['comment_lines'] / metrics['line_count']
        else:
            metrics['comment_ratio'] = 0.0

        return metrics

    def _calculate_obfuscation_score(self, content: str) -> float:
        """Calcule un score d'obfuscation basé sur différents indicateurs"""
        score = 0.0

        # Variables avec noms courts ou cryptiques
        short_vars = len(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]{0,2}\b=', content))
        if short_vars > 10:
            score += 0.3

        # Encodage/décodage suspect
        if 'base64' in content or 'decode' in content or 'encode' in content:
            score += 0.4

        # Caractères hexadécimaux longs
        hex_strings = re.findall(r'[0-9a-fA-F]{20,}', content)
        if hex_strings:
            score += 0.3

        # Évitement de détection
        evasion_patterns = ['eval', 'exec', '${', '$(']
        for pattern in evasion_patterns:
            if pattern in content:
                score += 0.2

        return min(score, 1.0)

    def _calculate_entropy(self, content: str) -> float:
        """Calcule l'entropie de Shannon du contenu"""
        if not content:
            return 0.0

        # Compter la fréquence des caractères
        char_counts = {}
        for char in content:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculer l'entropie
        entropy = 0.0
        content_length = len(content)

        for count in char_counts.values():
            probability = count / content_length
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)

        return entropy


# === SANDBOXING ET ISOLATION ===

class ScriptSandbox:
    """Sandbox pour l'exécution sécurisée de scripts"""

    def __init__(self, sandbox_dir: str = "/tmp/vuln_agent_sandbox"):
        self.sandbox_dir = Path(sandbox_dir)
        self.sandbox_dir.mkdir(exist_ok=True)
        self.logger = setup_logger(f"{__name__}.sandbox")

    def create_isolated_environment(self, script_id: str) -> Dict[str, Any]:
        """
        Crée un environnement isolé pour l'exécution d'un script

        Args:
            script_id: Identifiant unique du script

        Returns:
            Dict: Informations sur l'environnement créé
        """
        env_dir = self.sandbox_dir / f"env_{script_id}"
        env_dir.mkdir(exist_ok=True)

        # Créer les répertoires nécessaires
        (env_dir / "bin").mkdir(exist_ok=True)
        (env_dir / "tmp").mkdir(exist_ok=True)
        (env_dir / "logs").mkdir(exist_ok=True)

        # Créer un script wrapper sécurisé
        wrapper_script = env_dir / "wrapper.sh"
        with open(wrapper_script, 'w') as f:
            f.write(f"""#!/bin/bash
# Wrapper sécurisé pour script {script_id}
set -euo pipefail

# Variables d'environnement restreintes
export PATH="/usr/bin:/bin"
export HOME="{env_dir}"
export TMPDIR="{env_dir}/tmp"

# Limites de ressources
ulimit -t 300    # CPU time: 5 minutes
ulimit -f 1024   # File size: 1MB
ulimit -d 1024   # Data size: 1MB
ulimit -s 64     # Stack size: 64KB
ulimit -u 10     # Max processes: 10

# Exécuter le script avec timeout
timeout 300s bash "$1" 2>&1 | tee "{env_dir}/logs/execution.log"
""")

        wrapper_script.chmod(0o755)

        env_info = {
            'env_id': script_id,
            'env_dir': str(env_dir),
            'wrapper_script': str(wrapper_script),
            'created_at': datetime.utcnow().isoformat(),
            'limits': {
                'cpu_time': 300,
                'file_size': 1024,
                'memory': 1024,
                'processes': 10
            }
        }

        self.logger.info(f"Environnement sandbox créé: {script_id}")
        return env_info

    def validate_script_in_sandbox(
            self,
            script_content: str,
            script_id: str,
            dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Valide un script en environnement sandbox

        Args:
            script_content: Contenu du script
            script_id: Identifiant du script
            dry_run: Exécution à blanc (syntaxe seulement)

        Returns:
            Dict: Résultat de la validation
        """
        # Créer l'environnement
        env_info = self.create_isolated_environment(script_id)
        env_dir = Path(env_info['env_dir'])

        try:
            # Écrire le script dans l'environnement
            script_file = env_dir / "script.sh"
            with open(script_file, 'w') as f:
                f.write(script_content)
            script_file.chmod(0o755)

            # Validation de syntaxe
            syntax_result = subprocess.run(
                ['bash', '-n', str(script_file)],
                capture_output=True,
                text=True,
                timeout=10
            )

            result = {
                'script_id': script_id,
                'syntax_valid': syntax_result.returncode == 0,
                'syntax_error': syntax_result.stderr if syntax_result.returncode != 0 else None,
                'sandbox_path': str(env_dir),
                'validated_at': datetime.utcnow().isoformat()
            }

            if dry_run or syntax_result.returncode != 0:
                return result

            # Exécution en sandbox (mode test seulement)
            wrapper = env_info['wrapper_script']
            exec_result = subprocess.run(
                [wrapper, str(script_file)],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(env_dir)
            )

            result.update({
                'execution_successful': exec_result.returncode == 0,
                'execution_output': exec_result.stdout,
                'execution_error': exec_result.stderr,
                'return_code': exec_result.returncode
            })

            # Analyser les logs d'exécution
            log_file = env_dir / "logs" / "execution.log"
            if log_file.exists():
                with open(log_file, 'r') as f:
                    result['execution_log'] = f.read()

            return result

        except subprocess.TimeoutExpired:
            return {
                'script_id': script_id,
                'syntax_valid': False,
                'error': 'Timeout lors de la validation',
                'timeout': True
            }

        except Exception as e:
            self.logger.error(f"Erreur validation sandbox {script_id}: {e}")
            return {
                'script_id': script_id,
                'syntax_valid': False,
                'error': str(e),
                'exception': True
            }

        finally:
            # Nettoyer l'environnement de test
            self.cleanup_environment(script_id)

    def cleanup_environment(self, script_id: str):
        """Nettoie un environnement sandbox"""
        try:
            env_dir = self.sandbox_dir / f"env_{script_id}"
            if env_dir.exists():
                import shutil
                shutil.rmtree(env_dir)
                self.logger.debug(f"Environnement sandbox nettoyé: {script_id}")
        except Exception as e:
            self.logger.warning(f"Erreur nettoyage sandbox {script_id}: {e}")


# === GESTIONNAIRE DE SÉCURITÉ PRINCIPAL ===

class SecurityManager:
    """Gestionnaire principal de sécurité pour l'agent IA"""

    def __init__(self):
        self.input_validator = InputValidator()
        self.script_validator = ScriptValidator()
        self.crypto_utils = CryptoUtils()
        self.auditor = SecurityAuditor()
        self.anomaly_detector = AnomalyDetector()
        self.sandbox = ScriptSandbox()
        self.logger = setup_logger(f"{__name__}.manager")

        # Configuration de sécurité
        self.config = {
            'default_security_level': SecurityLevel.MEDIUM,
            'enable_sandboxing': True,
            'enable_anomaly_detection': True,
            'auto_quarantine': True,
            'max_script_size': 50000,  # 50KB
            'audit_all_actions': True
        }

    def comprehensive_security_check(
            self,
            script_content: str,
            user_id: str = "system",
            security_level: SecurityLevel = None
    ) -> Dict[str, Any]:
        """
        Vérification de sécurité complète d'un script

        Args:
            script_content: Contenu du script à vérifier
            user_id: Identifiant de l'utilisateur
            security_level: Niveau de sécurité souhaité

        Returns:
            Dict: Résultat complet de l'analyse de sécurité
        """
        if security_level is None:
            security_level = self.config['default_security_level']

        start_time = time.time()
        script_id = CryptoUtils.generate_secure_token(16)

        # Log de l'événement de sécurité
        self.auditor.log_security_event(
            'SECURITY_CHECK',
            user_id,
            'comprehensive_security_check',
            f"script_{script_id}",
            'STARTED',
            {'security_level': security_level.value}
        )

        try:
            # 1. Validation du script
            script_validation = self.script_validator.validate_bash_script(
                script_content, security_level
            )

            # 2. Détection d'anomalies
            anomaly_analysis = None
            if self.config['enable_anomaly_detection']:
                anomaly_analysis = self.anomaly_detector.analyze_script_behavior(script_content)

            # 3. Validation en sandbox
            sandbox_result = None
            if self.config['enable_sandboxing'] and script_validation.is_safe:
                sandbox_result = self.sandbox.validate_script_in_sandbox(
                    script_content, script_id, dry_run=True
                )

            # 4. Calcul du score de risque global
            global_risk_score = self._calculate_global_risk_score(
                script_validation, anomaly_analysis, sandbox_result
            )

            # 5. Décision finale
            final_decision = self._make_final_security_decision(
                script_validation, anomaly_analysis, global_risk_score, security_level
            )

            # Résultat complet
            result = {
                'script_id': script_id,
                'user_id': user_id,
                'security_level': security_level.value,
                'script_validation': script_validation.__dict__,
                'anomaly_analysis': anomaly_analysis,
                'sandbox_result': sandbox_result,
                'global_risk_score': global_risk_score,
                'final_decision': final_decision,
                'processing_time': time.time() - start_time,
                'checked_at': datetime.utcnow().isoformat()
            }

            # Log du résultat
            risk_level = 'CRITICAL' if global_risk_score > 0.8 else \
                'HIGH' if global_risk_score > 0.6 else \
                    'MEDIUM' if global_risk_score > 0.3 else 'LOW'

            self.auditor.log_security_event(
                'SECURITY_CHECK',
                user_id,
                'comprehensive_security_check',
                f"script_{script_id}",
                'COMPLETED',
                {
                    'final_decision': final_decision,
                    'risk_score': global_risk_score,
                    'processing_time': result['processing_time']
                },
                risk_level
            )

            return result

        except Exception as e:
            self.logger.error(f"Erreur vérification sécurité: {e}")

            self.auditor.log_security_event(
                'SECURITY_CHECK',
                user_id,
                'comprehensive_security_check',
                f"script_{script_id}",
                'FAILED',
                {'error': str(e)},
                'HIGH'
            )

            return {
                'script_id': script_id,
                'error': str(e),
                'final_decision': ValidationResult.REJECTED.value,
                'global_risk_score': 1.0
            }

    def _calculate_global_risk_score(
            self,
            script_validation: ScriptValidation,
            anomaly_analysis: Dict[str, Any],
            sandbox_result: Dict[str, Any]
    ) -> float:
        """Calcule un score de risque global"""

        risk_score = 0.0

        # Score basé sur la validation de script (40% du score)
        if script_validation.threat_level == ThreatLevel.MALICIOUS:
            risk_score += 0.4
        elif script_validation.threat_level == ThreatLevel.DANGEROUS:
            risk_score += 0.3
        elif script_validation.threat_level == ThreatLevel.SUSPICIOUS:
            risk_score += 0.2

        # Score basé sur les anomalies (30% du score)
        if anomaly_analysis:
            anomaly_risk = min(anomaly_analysis['risk_score'], 1.0)
            risk_score += anomaly_risk * 0.3

        # Score basé sur le sandbox (20% du score)
        if sandbox_result:
            if not sandbox_result.get('syntax_valid', True):
                risk_score += 0.2
            elif sandbox_result.get('timeout', False):
                risk_score += 0.15
            elif sandbox_result.get('exception', False):
                risk_score += 0.1

        # Ajustement pour les problèmes critiques (10% du score)
        critical_issues = [
            issue for issue in script_validation.issues
            if issue.get('severity') == 'CRITICAL'
        ]
        if critical_issues:
            risk_score += len(critical_issues) * 0.05

        return min(risk_score, 1.0)

    def _make_final_security_decision(
            self,
            script_validation: ScriptValidation,
            anomaly_analysis: Dict[str, Any],
            global_risk_score: float,
            security_level: SecurityLevel
    ) -> str:
        """Prend la décision finale de sécurité"""

        # Rejet automatique pour patterns malveillants
        if script_validation.threat_level == ThreatLevel.MALICIOUS:
            return ValidationResult.REJECTED.value

        # Rejet automatique pour score de risque très élevé
        if global_risk_score >= 0.9:
            return ValidationResult.REJECTED.value

        # Logique selon le niveau de sécurité
        if security_level == SecurityLevel.CRITICAL:
            if global_risk_score >= 0.3:
                return ValidationResult.REJECTED.value
            else:
                return ValidationResult.REVIEW_REQUIRED.value

        elif security_level == SecurityLevel.HIGH:
            if global_risk_score >= 0.7:
                return ValidationResult.REJECTED.value
            elif global_risk_score >= 0.4:
                return ValidationResult.REVIEW_REQUIRED.value
            else:
                return ValidationResult.APPROVED.value

        elif security_level == SecurityLevel.MEDIUM:
            if global_risk_score >= 0.8:
                return ValidationResult.REJECTED.value
            elif global_risk_score >= 0.5:
                return ValidationResult.REVIEW_REQUIRED.value
            else:
                return ValidationResult.APPROVED.value

        else:  # LOW
            if global_risk_score >= 0.8:
                return ValidationResult.REVIEW_REQUIRED.value
            else:
                return ValidationResult.APPROVED.value

                def quarantine_script(self, script_content: str, script_id: str, reason: str) -> Dict[str, Any]:
                    """
                    Met en quarantaine un script dangereux

                    Args:
                        script_content: Contenu du script
                        script_id: Identifiant du script
                        reason: Raison de la quarantaine

                    Returns:
                        Dict: Informations sur la quarantaine
                    """
                    quarantine_dir = Path("data/quarantine")
                    quarantine_dir.mkdir(exist_ok=True)

                    quarantine_info = {
                        'script_id': script_id,
                        'quarantine_time': datetime.utcnow().isoformat(),
                        'reason': reason,
                        'script_hash': hashlib.sha256(script_content.encode()).hexdigest(),
                        'script_size': len(script_content)
                    }

                    # Sauvegarder le script en quarantaine
                    script_file = quarantine_dir / f"{script_id}.sh"
                    with open(script_file, 'w', encoding='utf-8') as f:
                        f.write(f"# SCRIPT EN QUARANTAINE - NE PAS EXÉCUTER\n")
                        f.write(f"# Raison: {reason}\n")
                        f.write(f"# Date: {quarantine_info['quarantine_time']}\n")
                        f.write(f"# Hash: {quarantine_info['script_hash']}\n")
                        f.write("#" + "=" * 70 + "\n\n")
                        f.write(script_content)

                    # Sauvegarder les métadonnées
                    meta_file = quarantine_dir / f"{script_id}.json"
                    with open(meta_file, 'w', encoding='utf-8') as f:
                        json.dump(quarantine_info, f, indent=2)

                    self.logger.warning(f"Script mis en quarantaine: {script_id} - {reason}")

                    # Log de sécurité
                    self.auditor.log_security_event(
                        'QUARANTINE',
                        'system',
                        'quarantine_script',
                        script_id,
                        'SUCCESS',
                        quarantine_info,
                        'HIGH'
                    )

                    return quarantine_info

                def get_security_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
                    """
                    Génère des recommandations de sécurité personnalisées

                    Args:
                        analysis_result: Résultat d'analyse de sécurité

                    Returns:
                        List[str]: Liste de recommandations
                    """
                    recommendations = []

                    script_validation = analysis_result.get('script_validation', {})
                    anomaly_analysis = analysis_result.get('anomaly_analysis', {})
                    global_risk_score = analysis_result.get('global_risk_score', 0.0)

                    # Recommandations basées sur le score de risque
                    if global_risk_score >= 0.8:
                        recommendations.append("🚨 CRITIQUE: Ne pas exécuter ce script")
                        recommendations.append("Faire analyser par un expert en sécurité")
                        recommendations.append("Considérer comme potentiellement malveillant")

                    elif global_risk_score >= 0.6:
                        recommendations.append("⚠️ RISQUE ÉLEVÉ: Révision obligatoire")
                        recommendations.append("Test en environnement isolé uniquement")
                        recommendations.append("Validation par un administrateur senior")

                    elif global_risk_score >= 0.3:
                        recommendations.append("🔍 RÉVISION: Vérification recommandée")
                        recommendations.append("Test dans un environnement de développement")
                        recommendations.append("Sauvegarde système avant exécution")

                    else:
                        recommendations.append("✅ RISQUE FAIBLE: Script relativement sûr")
                        recommendations.append("Validation de la syntaxe effectuée")

                    # Recommandations spécifiques aux problèmes détectés
                    issues = script_validation.get('issues', [])

                    # Problèmes critiques
                    critical_issues = [i for i in issues if i.get('severity') == 'CRITICAL']
                    if critical_issues:
                        recommendations.append("Corriger immédiatement les problèmes critiques")

                    # Commandes dangereuses
                    dangerous_commands = [i for i in issues if i.get('type') == 'dangerous_command']
                    if dangerous_commands:
                        recommendations.append("Réviser attentivement les commandes système")
                        recommendations.append("Vérifier les permissions nécessaires")

                    # Patterns malveillants
                    malicious_patterns = [i for i in issues if i.get('type') == 'malicious_pattern']
                    if malicious_patterns:
                        recommendations.append("Supprimer les patterns malveillants détectés")
                        recommendations.append("Réécrire les sections problématiques")

                    # Recommandations d'amélioration du code
                    if script_validation.get('execution_risk') in ['HIGH', 'CRITICAL']:
                        recommendations.append("Ajouter une gestion d'erreur robuste (set -euo pipefail)")
                        recommendations.append("Valider tous les inputs utilisateur")
                        recommendations.append("Utiliser des chemins absolus pour les commandes")

                    # Recommandations basées sur les anomalies
                    if anomaly_analysis:
                        behavioral_flags = anomaly_analysis.get('behavioral_flags', [])

                        if 'HIGH_RISK_BEHAVIOR' in behavioral_flags:
                            recommendations.append("Comportement à haut risque détecté")

                        if 'DOWNLOADS_FILES' in behavioral_flags:
                            recommendations.append("Vérifier la légitimité des téléchargements")
                            recommendations.append("Scanner les fichiers téléchargés")

                        if 'ESCALATES_PRIVILEGES' in behavioral_flags:
                            recommendations.append("Justifier la nécessité de l'escalade de privilèges")
                            recommendations.append("Utiliser le principe du moindre privilège")

                        if 'PERSISTENCE_MECHANISMS' in behavioral_flags:
                            recommendations.append("Documenter les mécanismes de persistance")
                            recommendations.append("S'assurer de la réversibilité des modifications")

                    return recommendations

                def generate_security_report(self, analysis_results: List[Dict[str, Any]]) -> str:
                    """
                    Génère un rapport de sécurité complet

                    Args:
                        analysis_results: Liste des résultats d'analyses

                    Returns:
                        str: Rapport de sécurité formaté
                    """
                    if not analysis_results:
                        return "Aucune analyse de sécurité à reporter."

                    report_lines = []
                    report_lines.append("=" * 80)
                    report_lines.append("RAPPORT DE SÉCURITÉ - AGENT IA CYBERSÉCURITÉ")
                    report_lines.append("=" * 80)
                    report_lines.append(f"Généré le: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    report_lines.append(f"Nombre d'analyses: {len(analysis_results)}")
                    report_lines.append("")

                    # Statistiques globales
                    report_lines.append("STATISTIQUES GLOBALES")
                    report_lines.append("-" * 40)

                    risk_distribution = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
                    decision_distribution = {'APPROVED': 0, 'REVIEW_REQUIRED': 0, 'REJECTED': 0}
                    total_issues = 0

                    for result in analysis_results:
                        risk_score = result.get('global_risk_score', 0.0)
                        if risk_score >= 0.8:
                            risk_distribution['CRITICAL'] += 1
                        elif risk_score >= 0.6:
                            risk_distribution['HIGH'] += 1
                        elif risk_score >= 0.3:
                            risk_distribution['MEDIUM'] += 1
                        else:
                            risk_distribution['LOW'] += 1

                        decision = result.get('final_decision', 'UNKNOWN')
                        if decision in decision_distribution:
                            decision_distribution[decision] += 1

                        script_validation = result.get('script_validation', {})
                        issues = script_validation.get('issues', [])
                        total_issues += len(issues)

                    report_lines.append(f"Scripts analysés: {len(analysis_results)}")
                    report_lines.append(f"Problèmes détectés: {total_issues}")
                    report_lines.append("")
                    report_lines.append("Distribution des risques:")
                    for level, count in risk_distribution.items():
                        percentage = (count / len(analysis_results)) * 100 if analysis_results else 0
                        report_lines.append(f"  {level}: {count} ({percentage:.1f}%)")

                    report_lines.append("")
                    report_lines.append("Distribution des décisions:")
                    for decision, count in decision_distribution.items():
                        percentage = (count / len(analysis_results)) * 100 if analysis_results else 0
                        report_lines.append(f"  {decision}: {count} ({percentage:.1f}%)")

                    report_lines.append("")

                    # Détails par analyse
                    report_lines.append("DÉTAILS DES ANALYSES")
                    report_lines.append("-" * 40)

                    for i, result in enumerate(analysis_results, 1):
                        script_id = result.get('script_id', f'script_{i}')
                        risk_score = result.get('global_risk_score', 0.0)
                        decision = result.get('final_decision', 'UNKNOWN')

                        report_lines.append(f"\n{i}. Script ID: {script_id}")
                        report_lines.append(f"   Score de risque: {risk_score:.3f}")
                        report_lines.append(f"   Décision finale: {decision}")

                        # Problèmes détectés
                        script_validation = result.get('script_validation', {})
                        issues = script_validation.get('issues', [])

                        if issues:
                            report_lines.append(f"   Problèmes détectés ({len(issues)}):")
                            for issue in issues[:5]:  # Limiter aux 5 premiers
                                severity = issue.get('severity', 'UNKNOWN')
                                message = issue.get('message', 'Aucun message')
                                report_lines.append(f"     - [{severity}] {message}")

                            if len(issues) > 5:
                                report_lines.append(f"     ... et {len(issues) - 5} autres problèmes")
                        else:
                            report_lines.append("   Aucun problème détecté")

                        # Recommandations principales
                        recommendations = self.get_security_recommendations(result)
                        if recommendations:
                            report_lines.append("   Recommandations principales:")
                            for rec in recommendations[:3]:  # Top 3
                                report_lines.append(f"     • {rec}")

                    # Recommandations globales
                    report_lines.append("")
                    report_lines.append("RECOMMANDATIONS GLOBALES")
                    report_lines.append("-" * 40)

                    high_risk_count = risk_distribution['HIGH'] + risk_distribution['CRITICAL']
                    if high_risk_count > 0:
                        report_lines.append(f"⚠️  {high_risk_count} script(s) à haut risque détecté(s)")
                        report_lines.append("   Révision immédiate recommandée")

                    rejected_count = decision_distribution['REJECTED']
                    if rejected_count > 0:
                        report_lines.append(f"🚨 {rejected_count} script(s) rejeté(s) pour raisons de sécurité")
                        report_lines.append("   Ne pas exécuter sans correction majeure")

                    review_count = decision_distribution['REVIEW_REQUIRED']
                    if review_count > 0:
                        report_lines.append(f"🔍 {review_count} script(s) nécessitent une révision")
                        report_lines.append("   Validation manuelle recommandée")

                    report_lines.append("")
                    report_lines.append("Mesures de sécurité recommandées:")
                    report_lines.append("• Toujours tester en environnement isolé")
                    report_lines.append("• Effectuer des sauvegardes avant exécution")
                    report_lines.append("• Valider l'origine et l'intégrité des scripts")
                    report_lines.append("• Appliquer le principe du moindre privilège")
                    report_lines.append("• Maintenir une surveillance continue")

                    report_lines.append("")
                    report_lines.append("=" * 80)
                    report_lines.append("FIN DU RAPPORT")
                    report_lines.append("=" * 80)

                    return "\n".join(report_lines)

            # === FONCTIONS D'AIDE ===

            def get_default_security_manager() -> SecurityManager:
                """Retourne une instance par défaut du gestionnaire de sécurité"""
                return SecurityManager()

            def quick_script_validation(script_content: str, security_level: str = "MEDIUM") -> bool:
                """
                Validation rapide d'un script (fonction utilitaire)

                Args:
                    script_content: Contenu du script
                    security_level: Niveau de sécurité (LOW, MEDIUM, HIGH, CRITICAL)

                Returns:
                    bool: True si le script est considéré comme sûr
                """
                try:
                    security_mgr = get_default_security_manager()
                    level = SecurityLevel(security_level.lower())
                    result = security_mgr.comprehensive_security_check(script_content, security_level=level)

                    return result.get('final_decision') == ValidationResult.APPROVED.value

                except Exception:
                    return False

            def sanitize_user_input(user_input: str) -> str:
                """
                Nettoie un input utilisateur (fonction utilitaire)

                Args:
                    user_input: Input à nettoyer

                Returns:
                    str: Input nettoyé
                """
                sanitization = InputValidator.sanitize_shell_input(user_input)
                return sanitization.sanitized_input

            # === TESTS UNITAIRES INTÉGRÉS ===

            def run_security_tests():
                """Tests unitaires pour le module de sécurité"""
                print("Exécution des tests de sécurité...")

                # Test de validation d'IP
                print("\n1. Test validation IP:")
                test_ips = ["192.168.1.1", "invalid;rm -rf", "127.0.0.1", "example.com"]
                for ip in test_ips:
                    valid, msg = InputValidator.validate_ip_input(ip)
                    print(f"  {ip}: {'✓' if valid else '✗'} {msg}")

                # Test de validation de script
                print("\n2. Test validation script:")
                test_script = """#!/bin/bash
                set -e
                echo "Hello World"
                apt update && apt install -y curl
                """

                validator = ScriptValidator()
                result = validator.validate_bash_script(test_script)
                print(f"  Script test: {'✓' if result.is_safe else '✗'} ({result.threat_level.value})")
                print(f"  Issues: {len(result.issues)}")

                # Test de script malveillant
                print("\n3. Test script malveillant:")
                malicious_script = """#!/bin/bash
                rm -rf /*
                :(){ :|:& };:
                """

                result_mal = validator.validate_bash_script(malicious_script)
                print(
                    f"  Script malveillant: {'✗' if not result_mal.is_safe else '⚠️'} ({result_mal.threat_level.value})")
                print(f"  Issues: {len(result_mal.issues)}")

                # Test de chiffrement
                print("\n4. Test chiffrement:")
                password = "test123"
                hash_val, salt = CryptoUtils.hash_password(password)
                verify_result = CryptoUtils.verify_password(password, hash_val, salt)
                print(f"  Chiffrement/Vérification: {'✓' if verify_result else '✗'}")

                print("\nTests terminés.")

            if __name__ == "__main__":
                # Exécuter les tests si le module est lancé directement
                run_security_tests()