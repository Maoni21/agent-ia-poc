"""
Module Generator pour l'Agent IA de Cybersécurité

Ce module génère automatiquement des scripts de correction sécurisés
pour les vulnérabilités détectées. Il utilise l'IA pour créer des scripts
bash intelligents avec vérifications de sécurité, procédures de rollback
et validation automatique.

Fonctionnalités :
- Génération de scripts bash sécurisés
- Validation automatique des scripts (sécurité, syntaxe)
- Scripts de rollback automatiques
- Templates prédéfinis pour vulnérabilités courantes
- Analyse de risque avant exécution
- Support multi-OS (Linux, Ubuntu, CentOS, etc.)
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
import hashlib

from config import get_config, get_llm_config
from config.prompts import (
    format_script_generation_prompt,
    format_script_validation_prompt
)
from src.utils.logger import setup_logger
from src.database.database import Database
from .exceptions import GeneratorException, CoreErrorCodes, ERROR_MESSAGES

# Configuration du logging
logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class ScriptMetadata:
    """Métadonnées d'un script généré"""
    script_id: str
    vulnerability_id: str
    target_system: str
    script_type: str  # main, rollback, validation
    generated_at: datetime
    generated_by: str  # AI model used
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    estimated_duration: str
    requires_reboot: bool
    requires_sudo: bool

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['generated_at'] = self.generated_at.isoformat()
        return result


@dataclass
class ValidationResult:
    """Résultat de validation d'un script"""
    is_safe: bool
    overall_risk: str
    execution_recommendation: str  # APPROVE, REVIEW_REQUIRED, REJECT
    confidence_level: float
    identified_risks: List[Dict[str, Any]]
    security_checks: Dict[str, Any]
    improvements: List[str]
    alternative_approach: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScriptResult:
    """Résultat complet de génération de script"""
    script_id: str
    vulnerability_id: str
    metadata: ScriptMetadata

    # Scripts générés
    main_script: str
    rollback_script: Optional[str]
    validation_script: Optional[str]

    # Validation et sécurité
    validation_result: ValidationResult
    pre_checks: List[str]
    post_checks: List[str]
    warnings: List[str]

    # Métadonnées techniques
    script_hash: str
    dependencies: List[str]
    backup_commands: List[str]

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['metadata'] = self.metadata.to_dict()
        result['validation_result'] = self.validation_result.to_dict()
        return result


# === CLASSE PRINCIPALE ===

class Generator:
    """
    Générateur de scripts de correction IA

    Cette classe utilise l'IA pour générer des scripts de correction
    sécurisés et validés pour les vulnérabilités détectées.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialise le générateur

        Args:
            config: Configuration personnalisée (optionnel)
        """
        self.config = config or get_config()
        self.llm_config = get_llm_config("openai")

        # État du générateur
        self.is_ready = False
        self.ai_client = None

        # Base de données pour historique
        self.db = Database()

        # Templates de scripts prédéfinis
        self.script_templates = self._load_script_templates()

        # Commandes dangereuses à détecter
        self.dangerous_commands = {
            "destructive": [
                "rm -rf /", "rm -rf /*", ":(){ :|:& };:", "mkfs", "dd if=/dev/zero",
                "shred", "wipefs", "> /dev/sda", "fdisk", "parted"
            ],
            "network": [
                "iptables -F", "ufw --force reset", "systemctl stop networking",
                "ifconfig down", "ip link set down"
            ],
            "system": [
                "reboot", "shutdown", "halt", "init 0", "init 6", "systemctl reboot",
                "systemctl poweroff", "killall -9", "pkill -9"
            ],
            "permissions": [
                "chmod 777 /", "chmod -R 777", "chown -R root:root /",
                "usermod -aG sudo", "passwd", "su -"
            ]
        }

        # Statistiques
        self.stats = {
            "total_scripts_generated": 0,
            "safe_scripts": 0,
            "risky_scripts": 0,
            "rejected_scripts": 0,
            "average_generation_time": 0.0
        }

        # Initialiser l'IA
        self._initialize_ai_client()

    def _initialize_ai_client(self):
        """Initialise le client IA"""
        try:
            from openai import AsyncOpenAI

            api_key = self.config.openai_api_key
            if not api_key:
                raise GeneratorException(
                    "Clé API OpenAI manquante",
                    CoreErrorCodes.INVALID_CONFIGURATION
                )

            self.ai_client = AsyncOpenAI(api_key=api_key)
            self.is_ready = True
            logger.info("Client IA initialisé pour le générateur")

        except Exception as e:
            logger.error(f"Erreur initialisation IA Generator: {e}")
            raise GeneratorException(
                f"Impossible d'initialiser le client IA: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    def _load_script_templates(self) -> Dict[str, Dict[str, Any]]:
        """Charge les templates de scripts prédéfinis"""
        return {
            "apache_update": {
                "name": "Mise à jour Apache HTTP Server",
                "template": """#!/bin/bash
set -euo pipefail

# Sauvegarde de la configuration
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup.$(date +%Y%m%d_%H%M%S)

# Mise à jour Apache
apt update
apt install -y apache2

# Redémarrage sécurisé
apache2ctl configtest && systemctl restart apache2
""",
                "applicable_cves": ["CVE-2024-12345"],
                "risk_level": "MEDIUM"
            },
            "ssl_fix": {
                "name": "Correction configuration SSL",
                "template": """#!/bin/bash
set -euo pipefail

# Configuration SSL sécurisée
SSL_CONF="/etc/ssl/openssl.cnf"
cp "$SSL_CONF" "$SSL_CONF.backup.$(date +%Y%m%d_%H%M%S)"

# Désactiver protocoles faibles
sed -i 's/TLSv1.0/TLSv1.2/g' "$SSL_CONF"
sed -i 's/TLSv1.1/TLSv1.2/g' "$SSL_CONF"

# Redémarrer services SSL
systemctl restart apache2 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
""",
                "applicable_cves": ["CVE-2014-3566", "CVE-2014-0160"],
                "risk_level": "LOW"
            }
        }

    async def generate_fix_script(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str = "ubuntu",
            execution_context: str = "production",
            risk_tolerance: str = "low"
    ) -> ScriptResult:
        """
        Génère un script de correction pour une vulnérabilité

        Args:
            vulnerability_id: ID de la vulnérabilité
            vulnerability_details: Détails de la vulnérabilité
            target_system: Système cible (ubuntu, centos, etc.)
            execution_context: Contexte d'exécution (production, test)
            risk_tolerance: Tolérance au risque (low, medium, high)

        Returns:
            ScriptResult: Script généré avec métadonnées complètes

        Raises:
            GeneratorException: Si la génération échoue
        """
        if not self.is_ready:
            raise GeneratorException(
                "Générateur non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        script_id = f"script_{int(time.time())}_{vulnerability_id}"
        start_time = time.time()

        try:
            logger.info(f"Génération script {script_id} pour vulnérabilité {vulnerability_id}")

            # Vérifier si on a un template prédéfini
            template = self._find_applicable_template(vulnerability_details)

            if template:
                logger.info(f"Utilisation template prédéfini: {template['name']}")
                script_content = self._customize_template(template, vulnerability_details, target_system)
            else:
                # Génération IA
                script_content = await self._generate_script_with_ai(
                    vulnerability_id, vulnerability_details, target_system,
                    execution_context, risk_tolerance
                )

            # Générer le script de rollback
            rollback_script = await self._generate_rollback_script(
                script_content, vulnerability_details, target_system
            )

            # Générer les vérifications
            pre_checks, post_checks = self._generate_checks(vulnerability_details, target_system)

            # Valider le script
            validation_result = await self._validate_script(
                script_content, target_system, vulnerability_details
            )

            # Créer les métadonnées
            metadata = ScriptMetadata(
                script_id=script_id,
                vulnerability_id=vulnerability_id,
                target_system=target_system,
                script_type="main",
                generated_at=datetime.utcnow(),
                generated_by=self.llm_config.get("model", "gpt-4"),
                risk_level=validation_result.overall_risk,
                estimated_duration=self._estimate_execution_time(script_content),
                requires_reboot=self._requires_reboot(script_content),
                requires_sudo=self._requires_sudo(script_content)
            )

            # Calculer le hash du script
            script_hash = hashlib.sha256(script_content.encode()).hexdigest()[:16]

            # Générer les commandes de sauvegarde
            backup_commands = self._generate_backup_commands(vulnerability_details, target_system)

            # Générer les warnings
            warnings = self._generate_warnings(script_content, validation_result)

            # Créer le résultat final
            result = ScriptResult(
                script_id=script_id,
                vulnerability_id=vulnerability_id,
                metadata=metadata,
                main_script=script_content,
                rollback_script=rollback_script,
                validation_script=None,  # TODO: implémenter
                validation_result=validation_result,
                pre_checks=pre_checks,
                post_checks=post_checks,
                warnings=warnings,
                script_hash=script_hash,
                dependencies=self._extract_dependencies(script_content),
                backup_commands=backup_commands
            )

            # Sauvegarder le script
            await self._save_script_result(result)

            # Mettre à jour les statistiques
            processing_time = time.time() - start_time
            self._update_stats(validation_result.is_safe, processing_time)

            logger.info(f"Script généré: {script_id} ({validation_result.execution_recommendation})")
            return result

        except Exception as e:
            processing_time = time.time() - start_time
            self._update_stats(False, processing_time)
            logger.error(f"Erreur génération script {script_id}: {e}")

            if isinstance(e, GeneratorException):
                raise
            else:
                raise GeneratorException(
                    f"Erreur lors de la génération: {str(e)}",
                    CoreErrorCodes.SCRIPT_GENERATION_FAILED
                )

    def _find_applicable_template(self, vulnerability_details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Trouve un template applicable à la vulnérabilité"""
        cve_ids = vulnerability_details.get('cve_ids', [])
        vuln_name = vulnerability_details.get('name', '').lower()

        for template_name, template_data in self.script_templates.items():
            # Vérifier CVE match
            applicable_cves = template_data.get('applicable_cves', [])
            if any(cve in cve_ids for cve in applicable_cves):
                return template_data

            # Vérifier nom de vulnérabilité
            if any(keyword in vuln_name for keyword in ['apache', 'ssl', 'heartbleed', 'poodle']):
                if 'apache' in template_name and 'apache' in vuln_name:
                    return template_data
                elif 'ssl' in template_name and ('ssl' in vuln_name or 'tls' in vuln_name):
                    return template_data

        return None

    def _customize_template(
            self,
            template: Dict[str, Any],
            vulnerability_details: Dict[str, Any],
            target_system: str
    ) -> str:
        """Personnalise un template selon la vulnérabilité et le système"""
        script_content = template['template']

        # Adaptations par système
        if target_system in ['centos', 'rhel', 'fedora']:
            script_content = script_content.replace('apt update', 'yum update -y')
            script_content = script_content.replace('apt install -y', 'yum install -y')

        # Adaptations par vulnérabilité
        affected_service = vulnerability_details.get('affected_service', '')
        if affected_service:
            script_content = script_content.replace('apache2', affected_service.lower())

        # Ajouter en-tête personnalisé
        header = f"""#!/bin/bash
# Script de correction automatique
# Vulnérabilité: {vulnerability_details.get('name', 'Unknown')}
# CVE: {', '.join(vulnerability_details.get('cve_ids', []))}
# Système cible: {target_system}
# Généré le: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

set -euo pipefail

"""

        return header + script_content.strip()

    async def _generate_script_with_ai(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            execution_context: str,
            risk_tolerance: str
    ) -> str:
        """Génère un script via l'IA"""

        # Préparer le prompt
        prompt = format_script_generation_prompt(
            target_os=target_system,
            vulnerability_name=vulnerability_details.get('name', 'Unknown'),
            severity=vulnerability_details.get('severity', 'MEDIUM'),
            affected_service=vulnerability_details.get('affected_service', 'Unknown'),
            vulnerability_details=json.dumps(vulnerability_details, indent=2)
        )

        # Ajouter le contexte d'exécution
        prompt += f"""

CONTEXTE D'EXÉCUTION:
- Environnement: {execution_context}
- Tolérance au risque: {risk_tolerance}
- Système cible: {target_system}

CONTRAINTES SPÉCIALES:
- {'Mode production: sécurité maximale' if execution_context == 'production' else 'Mode test: plus de flexibilité'}
- {'Risque minimal autorisé' if risk_tolerance == 'low' else 'Risque modéré acceptable' if risk_tolerance == 'medium' else 'Risque élevé acceptable'}
"""

        try:
            response = await self.ai_client.chat.completions.create(
                model=self.llm_config.get("model", "gpt-4"),
                messages=[
                    {
                        "role": "system",
                        "content": "Tu es un expert en administration système et cybersécurité. Tu génères uniquement des scripts bash sécurisés. Réponds toujours en JSON valide."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.llm_config.get("max_tokens", 2000),
                temperature=self.llm_config.get("temperature", 0.3)
            )

            ai_response = response.choices[0].message.content

            # Parser la réponse JSON
            try:
                parsed_response = json.loads(ai_response)
                return parsed_response.get("main_script", "")
            except json.JSONDecodeError:
                # Fallback: extraire le script bash
                script_match = re.search(r'```bash\n(.*?)\n```', ai_response, re.DOTALL)
                if script_match:
                    return script_match.group(1)
                else:
                    raise GeneratorException(
                        "Impossible de parser la réponse IA",
                        CoreErrorCodes.SCRIPT_GENERATION_FAILED
                    )

        except Exception as e:
            logger.error(f"Erreur appel IA: {e}")
            raise GeneratorException(
                f"Erreur lors de l'appel IA: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    async def _generate_rollback_script(
            self,
            main_script: str,
            vulnerability_details: Dict[str, Any],
            target_system: str
    ) -> str:
        """Génère un script de rollback"""

        # Analyser le script principal pour détecter les actions
        actions = self._analyze_script_actions(main_script)

        rollback_commands = []
        rollback_commands.append("#!/bin/bash")
        rollback_commands.append("# Script de rollback automatique")
        rollback_commands.append(f"# Généré pour: {vulnerability_details.get('name', 'Unknown')}")
        rollback_commands.append(f"# Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
        rollback_commands.append("")
        rollback_commands.append("set -euo pipefail")
        rollback_commands.append("")
        rollback_commands.append("echo 'Début du rollback...'")
        rollback_commands.append("")

        # Générer les commandes de rollback selon les actions détectées
        if actions.get('package_updates'):
            rollback_commands.extend([
                "# Rollback des mises à jour de packages",
                "# ATTENTION: Le rollback de packages peut être complexe",
                "# Vérifiez manuellement les versions avant le rollback",
                "echo 'Rollback de packages détecté - intervention manuelle recommandée'"
            ])

        if actions.get('config_changes'):
            rollback_commands.extend([
                "# Restauration des fichiers de configuration",
                "for backup_file in /etc/*.backup.*; do",
                "    if [[ -f \"$backup_file\" ]]; then",
                "        original_file=$(echo \"$backup_file\" | sed 's/\\.backup\\.[0-9_]*$//')",
                "        echo \"Restauration: $original_file\"",
                "        cp \"$backup_file\" \"$original_file\"",
                "    fi",
                "done"
            ])

        if actions.get('service_restarts'):
            services = actions.get('services', [])
            for service in services:
                rollback_commands.append(f"systemctl restart {service} 2>/dev/null || true")

        rollback_commands.extend([
            "",
            "echo 'Rollback terminé'",
            "echo 'Vérifiez manuellement l\\'état du système'"
        ])

        return "\n".join(rollback_commands)

    def _analyze_script_actions(self, script_content: str) -> Dict[str, Any]:
        """Analyse les actions dans un script"""
        actions = {
            'package_updates': False,
            'config_changes': False,
            'service_restarts': False,
            'services': [],
            'config_files': []
        }

        lines = script_content.split('\n')

        for line in lines:
            line = line.strip()

            # Détection mise à jour packages
            if any(cmd in line for cmd in ['apt update', 'apt upgrade', 'yum update', 'dnf update']):
                actions['package_updates'] = True

            # Détection modifications config
            if any(pattern in line for pattern in ['cp ', 'sed -i', 'echo >', '>>']):
                actions['config_changes'] = True
                # Extraire les fichiers de config
                if '/etc/' in line:
                    config_match = re.search(r'/etc/[^\s]+', line)
                    if config_match:
                        actions['config_files'].append(config_match.group())

            # Détection redémarrage services
            if 'systemctl restart' in line or 'service ' in line:
                actions['service_restarts'] = True
                # Extraire le nom du service
                service_match = re.search(r'systemctl restart (\w+)', line)
                if service_match:
                    actions['services'].append(service_match.group(1))

        return actions

    def _generate_checks(
            self,
            vulnerability_details: Dict[str, Any],
            target_system: str
    ) -> Tuple[List[str], List[str]]:
        """Génère les vérifications pré/post exécution"""

        pre_checks = [
            "Vérifier les droits d'administration",
            "Créer une sauvegarde du système",
            "Vérifier l'espace disque disponible (>1GB)",
            "Tester la connectivité réseau",
            "Vérifier que les services critiques fonctionnent"
        ]

        post_checks = [
            "Vérifier que tous les services redémarrent correctement",
            "Tester l'accès aux applications critiques",
            "Vérifier les logs système pour détecter les erreurs",
            "Confirmer que la vulnérabilité est corrigée",
            "Documenter les modifications apportées"
        ]

        # Ajouts spécifiques selon la vulnérabilité
        affected_service = vulnerability_details.get('affected_service', '').lower()

        if 'apache' in affected_service or 'nginx' in affected_service:
            pre_checks.append("Vérifier la configuration du serveur web")
            post_checks.append("Tester l'accès aux sites web")

        if 'ssh' in affected_service:
            pre_checks.append("S'assurer d'avoir un accès alternatif au serveur")
            post_checks.append("Tester la connexion SSH")

        if 'database' in affected_service or any(db in affected_service for db in ['mysql', 'postgresql', 'oracle']):
            pre_checks.append("Créer une sauvegarde de la base de données")
            post_checks.append("Vérifier l'intégrité de la base de données")

        return pre_checks, post_checks

    async def _validate_script(
            self,
            script_content: str,
            target_system: str,
            vulnerability_details: Dict[str, Any]
    ) -> ValidationResult:
        """Valide un script généré"""

        # Validation automatique rapide
        quick_validation = self._quick_security_validation(script_content)

        if not quick_validation['is_safe']:
            return ValidationResult(
                is_safe=False,
                overall_risk="CRITICAL",
                execution_recommendation="REJECT",
                confidence_level=0.9,
                identified_risks=quick_validation['risks'],
                security_checks=quick_validation,
                improvements=[],
                alternative_approach="Révision manuelle requise"
            )

        # Validation IA approfondie
        try:
            prompt = format_script_validation_prompt(
                script_content=script_content,
                target_system=target_system,
                execution_user="root",
                vulnerability_info=json.dumps(vulnerability_details)
            )

            response = await self.ai_client.chat.completions.create(
                model=self.llm_config.get("model", "gpt-4"),
                messages=[
                    {
                        "role": "system",
                        "content": "Tu es un expert en sécurité système. Analyse ce script bash et évalue sa sécurité. Réponds en JSON valide."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500,
                temperature=0.2
            )

            ai_validation = json.loads(response.choices[0].message.content)

            return ValidationResult(
                is_safe=ai_validation["security_assessment"]["execution_recommendation"] == "APPROVE",
                overall_risk=ai_validation["security_assessment"]["overall_risk"],
                execution_recommendation=ai_validation["security_assessment"]["execution_recommendation"],
                confidence_level=float(ai_validation["security_assessment"]["confidence_level"]) / 100,
                identified_risks=ai_validation.get("identified_risks", []),
                security_checks=ai_validation.get("security_checks", {}),
                improvements=ai_validation.get("improvements", []),
                alternative_approach=ai_validation.get("alternative_approach")
            )

        except Exception as e:
            logger.warning(f"Erreur validation IA: {e}, utilisation validation basique")

            # Fallback: validation basique
            return ValidationResult(
                is_safe=quick_validation['is_safe'],
                overall_risk="MEDIUM" if quick_validation['is_safe'] else "HIGH",
                execution_recommendation="REVIEW_REQUIRED" if quick_validation['is_safe'] else "REJECT",
                confidence_level=0.7,
                identified_risks=quick_validation['risks'],
                security_checks=quick_validation,
                improvements=["Validation IA indisponible - révision manuelle recommandée"],
                alternative_approach=None
            )

    def _quick_security_validation(self, script_content: str) -> Dict[str, Any]:
        """Validation rapide de sécurité d'un script"""
        risks = []
        is_safe = True

        lines = script_content.lower().split('\n')

        # Vérifier les commandes dangereuses
        for category, commands in self.dangerous_commands.items():
            for command in commands:
                if any(command in line for line in lines):
                    risks.append({
                        "type": f"DANGEROUS_COMMAND_{category.upper()}",
                        "severity": "CRITICAL",
                        "description": f"Commande dangereuse détectée: {command}",
                        "recommendation": "Supprimer ou sécuriser cette commande"
                    })
                    is_safe = False

        # Vérifier l'absence de set -e
        has_error_handling = any('set -e' in line for line in lines)
        if not has_error_handling:
            risks.append({
                "type": "MISSING_ERROR_HANDLING",
                "severity": "MEDIUM",
                "description": "Gestion d'erreur manquante (set -e)",
                "recommendation": "Ajouter 'set -euo pipefail' au début du script"
            })

        # Vérifier les redirections dangereuses
        dangerous_redirections = ['> /dev/', '> /etc/', '> /bin/', '> /usr/']
        for line in lines:
            if any(redir in line for redir in dangerous_redirections):
                risks.append({
                    "type": "DANGEROUS_REDIRECTION",
                    "severity": "HIGH",
                    "description": f"Redirection potentiellement dangereuse: {line.strip()}",
                    "recommendation": "Vérifier la destination de la redirection"
                })
                is_safe = False

        # Vérifier les téléchargements
        download_patterns = ['wget ', 'curl ', 'git clone']
        for line in lines:
            if any(pattern in line for pattern in download_patterns):
                risks.append({
                    "type": "EXTERNAL_DOWNLOAD",
                    "severity": "MEDIUM",
                    "description": f"Téléchargement externe détecté: {line.strip()}",
                    "recommendation": "Vérifier la source et utiliser HTTPS"
                })

        return {
            "is_safe": is_safe,
            "risks": risks,
            "dangerous_commands": [cmd for cmd in self.dangerous_commands.get('destructive', [])
                                   if any(cmd in line for line in lines)],
            "external_downloads": len([line for line in lines
                                       if any(pattern in line for pattern in download_patterns)]) > 0,
            "has_error_handling": has_error_handling
        }

    def _estimate_execution_time(self, script_content: str) -> str:
        """Estime le temps d'exécution d'un script"""
        lines = script_content.split('\n')

        # Compteurs d'opérations
        package_ops = 0
        service_ops = 0
        file_ops = 0

        for line in lines:
            line = line.strip().lower()

            if any(cmd in line for cmd in ['apt update', 'apt install', 'yum install','dnf install', 'apt upgrade']):
                package_ops += 1
            elif any(cmd in line for cmd in ['systemctl', 'service ']):
                service_ops += 1
            elif any(cmd in line for cmd in ['cp ', 'mv ', 'sed -i', 'chmod', 'chown']):
                file_ops += 1

        # Estimation basée sur les opérations
        estimated_seconds = 0
        estimated_seconds += package_ops * 60  # 1 minute par opération package
        estimated_seconds += service_ops * 10   # 10 secondes par opération service
        estimated_seconds += file_ops * 5       # 5 secondes par opération fichier

        # Minimum 30 secondes
        estimated_seconds = max(30, estimated_seconds)

        if estimated_seconds < 120:
            return f"{estimated_seconds} secondes"
        elif estimated_seconds < 3600:
            return f"{estimated_seconds // 60} minutes"
        else:
            return f"{estimated_seconds // 3600}h {(estimated_seconds % 3600) // 60}m"

    def _requires_reboot(self, script_content: str) -> bool:
        """Détermine si le script nécessite un redémarrage"""
        reboot_indicators = [
            'kernel', 'reboot', 'init 6', 'systemctl reboot',
            'grub', 'initrd', 'vmlinuz'
        ]

        content_lower = script_content.lower()
        return any(indicator in content_lower for indicator in reboot_indicators)

    def _requires_sudo(self, script_content: str) -> bool:
        """Détermine si le script nécessite les privilèges sudo"""
        sudo_indicators = [
            'apt ', 'yum ', 'dnf ', 'systemctl', 'service ',
            'chown', 'chmod', '/etc/', '/var/', '/usr/',
            'iptables', 'ufw', 'firewall'
        ]

        content_lower = script_content.lower()
        return any(indicator in content_lower for indicator in sudo_indicators)

    def _generate_backup_commands(
        self,
        vulnerability_details: Dict[str, Any],
        target_system: str
    ) -> List[str]:
        """Génère les commandes de sauvegarde recommandées"""

        backup_commands = [
            "# Sauvegarde automatique avant corrections",
            f"BACKUP_DIR=\"/tmp/vuln_backup_$(date +%Y%m%d_%H%M%S)\"",
            "mkdir -p \"$BACKUP_DIR\"",
        ]

        affected_service = vulnerability_details.get('affected_service', '').lower()

        # Sauvegardes spécifiques par service
        if 'apache' in affected_service:
            backup_commands.extend([
                "cp -r /etc/apache2 \"$BACKUP_DIR/apache2_config\"",
                "systemctl status apache2 > \"$BACKUP_DIR/apache2_status.txt\""
            ])

        elif 'nginx' in affected_service:
            backup_commands.extend([
                "cp -r /etc/nginx \"$BACKUP_DIR/nginx_config\"",
                "nginx -t > \"$BACKUP_DIR/nginx_test.txt\" 2>&1"
            ])

        elif 'ssh' in affected_service:
            backup_commands.extend([
                "cp /etc/ssh/sshd_config \"$BACKUP_DIR/sshd_config\"",
                "systemctl status ssh > \"$BACKUP_DIR/ssh_status.txt\""
            ])

        elif any(db in affected_service for db in ['mysql', 'postgresql']):
            backup_commands.extend([
                "# ATTENTION: Sauvegarde de base de données requise",
                "# mysqldump ou pg_dump selon le SGBD",
                "echo 'Sauvegarde DB manuelle requise' > \"$BACKUP_DIR/db_backup_required.txt\""
            ])

        # Sauvegardes génériques
        backup_commands.extend([
            "# Sauvegarde des logs système",
            "cp /var/log/syslog \"$BACKUP_DIR/syslog.backup\" 2>/dev/null || true",
            "cp /var/log/auth.log \"$BACKUP_DIR/auth.log.backup\" 2>/dev/null || true",
            "echo \"Sauvegarde créée dans: $BACKUP_DIR\""
        ])

        return backup_commands

    def _generate_warnings(
        self,
        script_content: str,
        validation_result: ValidationResult
    ) -> List[str]:
        """Génère les avertissements pour le script"""

        warnings = []

        # Avertissements basés sur la validation
        if validation_result.overall_risk in ["HIGH", "CRITICAL"]:
            warnings.append("⚠️ Script à haut risque - révision manuelle fortement recommandée")

        if not validation_result.is_safe:
            warnings.append("🚨 Script potentiellement dangereux - NE PAS exécuter sans révision")

        # Avertissements basés sur le contenu
        content_lower = script_content.lower()

        if 'rm ' in content_lower:
            warnings.append("⚠️ Script contient des suppressions de fichiers")

        if any(cmd in content_lower for cmd in ['reboot', 'shutdown', 'halt']):
            warnings.append("🔄 Script nécessite un redémarrage du système")

        if any(net in content_lower for net in ['iptables', 'ufw', 'firewall']):
            warnings.append("🌐 Script modifie la configuration réseau/firewall")

        if 'passwd' in content_lower or 'user' in content_lower:
            warnings.append("👤 Script modifie les comptes utilisateur")

        # Avertissements spéciaux
        if validation_result.execution_recommendation == "REVIEW_REQUIRED":
            warnings.append("📋 Révision manuelle requise avant exécution")

        if validation_result.confidence_level < 0.8:
            warnings.append("❓ Niveau de confiance faible - validation supplémentaire recommandée")

        return warnings

    def _extract_dependencies(self, script_content: str) -> List[str]:
        """Extrait les dépendances du script"""
        dependencies = []
        lines = script_content.split('\n')

        for line in lines:
            line = line.strip()

            # Packages installés
            if 'apt install' in line or 'yum install' in line:
                # Extraire les noms de packages
                parts = line.split()
                if 'install' in parts:
                    install_idx = parts.index('install')
                    packages = [p for p in parts[install_idx+1:] if not p.startswith('-')]
                    dependencies.extend(packages)

            # Commandes utilisées
            if line.startswith(('systemctl', 'service', 'curl', 'wget', 'git')):
                command = line.split()[0]
                if command not in dependencies:
                    dependencies.append(command)

        return list(set(dependencies))  # Éliminer les doublons

    async def _save_script_result(self, result: ScriptResult):
        """Sauvegarde le résultat dans la base de données"""
        try:
            # TODO: Implémenter la sauvegarde complète en base
            logger.debug(f"Sauvegarde script: {result.script_id}")

            # Sauvegarder aussi le fichier script
            script_dir = Path("data/scripts")
            script_dir.mkdir(exist_ok=True)

            script_file = script_dir / f"{result.script_id}.sh"
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(result.main_script)

            # Sauvegarder le rollback
            if result.rollback_script:
                rollback_file = script_dir / f"{result.script_id}_rollback.sh"
                with open(rollback_file, 'w', encoding='utf-8') as f:
                    f.write(result.rollback_script)

            # Sauvegarder les métadonnées
            meta_file = script_dir / f"{result.script_id}_metadata.json"
            with open(meta_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.warning(f"Erreur sauvegarde script: {e}")

    def _update_stats(self, is_safe: bool, processing_time: float):
        """Met à jour les statistiques du générateur"""
        self.stats["total_scripts_generated"] += 1

        if is_safe:
            self.stats["safe_scripts"] += 1
        else:
            self.stats["risky_scripts"] += 1

        # Moyenne mobile simple
        current_avg = self.stats["average_generation_time"]
        total = self.stats["total_scripts_generated"]
        self.stats["average_generation_time"] = (current_avg * (total - 1) + processing_time) / total

    async def validate_existing_script(
        self,
        script_content: str,
        target_system: str = "ubuntu",
        execution_context: str = "production"
    ) -> ValidationResult:
        """
        Valide un script existant

        Args:
            script_content: Contenu du script à valider
            target_system: Système cible
            execution_context: Contexte d'exécution

        Returns:
            ValidationResult: Résultat de validation
        """
        if not self.is_ready:
            raise GeneratorException(
                "Générateur non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        try:
            vulnerability_details = {"name": "Script externe", "severity": "UNKNOWN"}

            validation_result = await self._validate_script(
                script_content, target_system, vulnerability_details
            )

            logger.info(f"Validation script externe: {validation_result.execution_recommendation}")
            return validation_result

        except Exception as e:
            logger.error(f"Erreur validation script externe: {e}")
            raise GeneratorException(
                f"Erreur lors de la validation: {str(e)}",
                CoreErrorCodes.SCRIPT_VALIDATION_FAILED
            )

    async def generate_custom_script(
        self,
        task_description: str,
        target_system: str = "ubuntu",
        risk_tolerance: str = "low"
    ) -> ScriptResult:
        """
        Génère un script personnalisé basé sur une description

        Args:
            task_description: Description de la tâche à automatiser
            target_system: Système cible
            risk_tolerance: Tolérance au risque

        Returns:
            ScriptResult: Script généré
        """
        # Créer une "vulnérabilité" fictive pour le workflow
        fake_vulnerability = {
            "name": f"Tâche personnalisée: {task_description}",
            "severity": "MEDIUM",
            "affected_service": "system",
            "description": task_description,
            "cve_ids": []
        }

        return await self.generate_fix_script(
            vulnerability_id=f"custom_{int(time.time())}",
            vulnerability_details=fake_vulnerability,
            target_system=target_system,
            execution_context="custom",
            risk_tolerance=risk_tolerance
        )

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du générateur"""
        return self.stats.copy()

    def is_healthy(self) -> bool:
        """Vérifie si le générateur est en bonne santé"""
        if not self.is_ready:
            return False

        try:
            # Test simple de l'IA
            return self.ai_client is not None
        except Exception:
            return False

    def get_supported_systems(self) -> List[str]:
        """Retourne la liste des systèmes supportés"""
        return [
            "ubuntu", "debian", "centos", "rhel",
            "fedora", "opensuse", "arch", "alpine"
        ]

    def get_script_templates(self) -> Dict[str, Dict[str, Any]]:
        """Retourne les templates de scripts disponibles"""
        return {
            name: {
                "name": template["name"],
                "applicable_cves": template["applicable_cves"],
                "risk_level": template["risk_level"]
            }
            for name, template in self.script_templates.items()
        }

# === FONCTIONS UTILITAIRES ===

async def quick_script_generation(
    vulnerability_id: str,
    vulnerability_name: str,
    target_system: str = "ubuntu"
) -> Dict[str, Any]:
    """
    Génération rapide de script (fonction utilitaire)

    Args:
        vulnerability_id: ID de la vulnérabilité
        vulnerability_name: Nom de la vulnérabilité
        target_system: Système cible

    Returns:
        Dict contenant le script et métadonnées
    """
    generator = Generator()

    try:
        vulnerability_details = {
            "name": vulnerability_name,
            "severity": "MEDIUM",
            "affected_service": "unknown",
            "description": f"Correction pour {vulnerability_name}"
        }

        result = await generator.generate_fix_script(
            vulnerability_id, vulnerability_details, target_system
        )

        return result.to_dict()

    except Exception as e:
        logger.error(f"Erreur génération rapide: {e}")
        return {
            "error": str(e),
            "vulnerability_id": vulnerability_id,
            "main_script": ""
        }

def create_generator(config: Optional[Dict[str, Any]] = None) -> Generator:
    """
    Factory pour créer un générateur avec configuration spécifique

    Args:
        config: Configuration personnalisée

    Returns:
        Generator: Instance configurée
    """
    return Generator(config)

def validate_bash_syntax(script_content: str) -> Dict[str, Any]:
    """
    Valide la syntaxe bash d'un script

    Args:
        script_content: Contenu du script

    Returns:
        Dict avec le résultat de validation
    """
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
            Path(tmp_file.name).unlink(missing_ok=True)

            return {
                "valid": result.returncode == 0,
                "error_message": result.stderr if result.returncode != 0 else None,
                "warnings": []
            }

    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "error_message": "Timeout lors de la validation syntaxique",
            "warnings": []
        }
    except Exception as e:
        return {
            "valid": False,
            "error_message": f"Erreur validation: {str(e)}",
            "warnings": []
        }

def extract_script_commands(script_content: str) -> Dict[str, List[str]]:
    """
    Extrait et catégorise les commandes d'un script

    Args:
        script_content: Contenu du script

    Returns:
        Dict avec les commandes par catégorie
    """
    commands = {
        "package_management": [],
        "service_management": [],
        "file_operations": [],
        "network_operations": [],
        "system_operations": [],
        "other": []
    }

    lines = script_content.split('\n')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Catégoriser les commandes
        if any(cmd in line for cmd in ['apt', 'yum', 'dnf', 'rpm', 'dpkg']):
            commands["package_management"].append(line)
        elif any(cmd in line for cmd in ['systemctl', 'service', 'chkconfig']):
            commands["service_management"].append(line)
        elif any(cmd in line for cmd in ['cp', 'mv', 'rm', 'chmod', 'chown', 'mkdir', 'ln']):
            commands["file_operations"].append(line)
        elif any(cmd in line for cmd in ['iptables', 'ufw', 'firewall-cmd', 'netstat', 'ss']):
            commands["network_operations"].append(line)
        elif any(cmd in line for cmd in ['mount', 'umount', 'crontab', 'sysctl']):
            commands["system_operations"].append(line)
        else:
            commands["other"].append(line)

    return commands

def estimate_script_risk(script_content: str) -> Dict[str, Any]:
    """
    Estime le niveau de risque d'un script

    Args:
        script_content: Contenu du script

    Returns:
        Dict avec l'évaluation de risque
    """
    risk_factors = {
        "destructive_commands": 0,
        "system_modifications": 0,
        "network_changes": 0,
        "privilege_operations": 0,
        "external_downloads": 0
    }

    content_lower = script_content.lower()

    # Commandes destructrices
    destructive_patterns = ['rm -rf', 'dd if=', 'mkfs', 'fdisk', 'parted']
    for pattern in destructive_patterns:
        if pattern in content_lower:
            risk_factors["destructive_commands"] += 1

    # Modifications système
    system_patterns = ['chmod 777', 'chown root', '/etc/', '/var/', '/usr/']
    for pattern in system_patterns:
        if pattern in content_lower:
            risk_factors["system_modifications"] += 1

    # Changements réseau
    network_patterns = ['iptables', 'ufw', 'firewall', 'route', 'ip route']
    for pattern in network_patterns:
        if pattern in content_lower:
            risk_factors["network_changes"] += 1

    # Opérations privilégiées
    privilege_patterns = ['sudo', 'su -', 'passwd', 'usermod', 'adduser']
    for pattern in privilege_patterns:
        if pattern in content_lower:
            risk_factors["privilege_operations"] += 1

    # Téléchargements externes
    download_patterns = ['wget', 'curl', 'git clone', 'pip install']
    for pattern in download_patterns:
        if pattern in content_lower:
            risk_factors["external_downloads"] += 1

    # Calculer le score de risque
    total_risk = sum(risk_factors.values())

    if total_risk == 0:
        risk_level = "LOW"
    elif total_risk <= 2:
        risk_level = "MEDIUM"
    elif total_risk <= 4:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "risk_level": risk_level,
        "risk_score": total_risk,
        "risk_factors": risk_factors,
        "recommendations": _get_risk_recommendations(risk_factors)
    }

def _get_risk_recommendations(risk_factors: Dict[str, int]) -> List[str]:
    """Génère des recommandations basées sur les facteurs de risque"""
    recommendations = []

    if risk_factors["destructive_commands"] > 0:
        recommendations.append("⚠️ Commandes destructrices détectées - sauvegarde obligatoire")

    if risk_factors["system_modifications"] > 0:
        recommendations.append("🔧 Modifications système - tester en environnement de développement")

    if risk_factors["network_changes"] > 0:
        recommendations.append("🌐 Changements réseau - vérifier la connectivité après exécution")

    if risk_factors["privilege_operations"] > 0:
        recommendations.append("👑 Opérations privilégiées - exécuter avec précaution")

    if risk_factors["external_downloads"] > 0:
        recommendations.append("📥 Téléchargements externes - vérifier les sources")

    return recommendations

# === CLASSE DE GESTION DE TEMPLATES ===

class ScriptTemplateManager:
    """
    Gestionnaire de templates de scripts

    Permet de créer, modifier et gérer des templates réutilisables
    pour les vulnérabilités courantes.
    """

    def __init__(self, templates_dir: str = "data/script_templates"):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(exist_ok=True)
        self.templates = {}
        self._load_templates()

    def _load_templates(self):
        """Charge tous les templates depuis le répertoire"""
        for template_file in self.templates_dir.glob("*.json"):
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    template_data = json.load(f)
                    self.templates[template_file.stem] = template_data
            except Exception as e:
                logger.warning(f"Erreur chargement template {template_file}: {e}")

    def create_template(
        self,
        name: str,
        script_content: str,
        applicable_cves: List[str],
        risk_level: str = "MEDIUM",
        description: str = ""
    ):
        """Crée un nouveau template"""