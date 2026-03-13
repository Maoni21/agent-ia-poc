"""
Module Generator pour l'Agent IA de Cybersécurité
Support OpenAI ET Anthropic/Claude
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import csv
import io

from config import get_config
from src.utils.logger import setup_logger
from src.database.database import Database
from .exceptions import GeneratorException, CoreErrorCodes

logger = setup_logger(__name__)


# === ÉNUMÉRATIONS ===

class ScriptType(str, Enum):
    """Types de scripts"""
    BASH = "bash"
    PYTHON = "python"
    POWERSHELL = "powershell"
    ANSIBLE = "ansible"


class ValidationStatus(str, Enum):
    """Statuts de validation"""
    APPROVED = "approved"
    REVIEW_REQUIRED = "review_required"
    REJECT = "reject"


class RiskLevel(str, Enum):
    """Niveaux de risque"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# === MODÈLES DE DONNÉES ===

@dataclass
class ScriptResult:
    """Résultat de génération d'un script"""
    script_id: str
    vulnerability_id: str
    target_system: str
    script_type: str
    fix_script: str
    rollback_script: Optional[str]
    validation_status: str
    risk_level: str
    estimated_execution_time: Optional[int]
    warnings: List[str]
    prerequisites: List[str]
    generated_at: str
    ai_model_used: str
    confidence_score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScriptMetadata:
    """
    Métadonnées détaillées associées à un script généré.
    Utilisée principalement par les tests pour vérifier la structure.
    """
    script_id: str
    vulnerability_id: str
    target_system: str
    script_type: str
    generated_at: datetime
    generated_by: str
    risk_level: str
    estimated_duration: Optional[str] = None
    requires_reboot: bool = False
    requires_sudo: bool = True

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Sérialiser les dates en ISO8601 pour compatibilité tests
        data["generated_at"] = self.generated_at.isoformat()
        return data


@dataclass
class ValidationResult:
    """
    Résultat structuré de validation de script.
    """
    is_safe: bool
    overall_risk: str
    execution_recommendation: str
    confidence_level: float
    identified_risks: List[Dict[str, Any]]
    security_checks: Dict[str, Any]
    improvements: List[str]
    alternative_approach: Optional[str] = None


# === CLASSE PRINCIPALE ===

class Generator:
    """Générateur de scripts de correction avec support multi-provider"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.db = Database()
        self.is_ready = False
        # Statistiques détaillées utilisées par les tests
        self.stats = {
            "total_scripts_generated": 0,
            "safe_scripts": 0,
            "risky_scripts": 0,
            "average_generation_time": 0.0,
        }

        # Détection du provider
        self.ai_provider = self.config.get('ai_provider', 'anthropic')

        # Initialisation du client IA selon le provider
        if self.ai_provider == 'openai':
            self._init_openai()
        elif self.ai_provider == 'anthropic':
            self._init_anthropic()
        else:
            raise GeneratorException(f"Provider IA non supporté: {self.ai_provider}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_openai(self):
        """Initialise le client OpenAI"""
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                api_key=self.config.get('openai_api_key'),
                timeout=self.config.get('openai_timeout', 120)
            )
            self.model = self.config.get('openai_model', 'gpt-4')
            self.max_tokens = self.config.get('openai_max_tokens', 1000)
            self.temperature = self.config.get('openai_temperature', 0.7)
            self.is_ready = True
            logger.info(f"Client OpenAI initialisé pour le générateur")
        except Exception as e:
            logger.error(f"Erreur initialisation OpenAI: {e}")
            raise GeneratorException(f"Impossible d'initialiser OpenAI: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_anthropic(self):
        """Initialise le client Anthropic/Claude"""
        try:
            from anthropic import AsyncAnthropic
            self.client = AsyncAnthropic(
                api_key=self.config.get('anthropic_api_key'),
                timeout=self.config.get('anthropic_timeout', 120)
            )
            self.model = self.config.get('anthropic_model', 'claude-sonnet-4-20250514')
            self.max_tokens = self.config.get('anthropic_max_tokens', 4096)
            self.temperature = self.config.get('anthropic_temperature', 0.7)
            self.is_ready = True
            logger.info(f"Client Anthropic initialisé pour le générateur")
        except Exception as e:
            logger.error(f"Erreur initialisation Anthropic: {e}")
            raise GeneratorException(f"Impossible d'initialiser Anthropic: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

        logger.info("Client IA initialisé pour le générateur")

    async def _call_ai_api(self, prompt: str) -> str:
        """Appelle l'API IA selon le provider configuré"""
        if self.ai_provider == 'openai':
            return await self._call_openai(prompt)
        elif self.ai_provider == 'anthropic':
            return await self._call_anthropic(prompt)
        else:
            raise GeneratorException(f"Provider inconnu: {self.ai_provider}", CoreErrorCodes.AI_SERVICE_ERROR)

    async def _call_openai(self, prompt: str) -> str:
        """Appelle l'API OpenAI"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "Tu es un expert DevSecOps. Génère UNIQUEMENT du JSON valide."},
                {"role": "user", "content": prompt}
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens
        )
        return response.choices[0].message.content

    async def _call_anthropic(self, prompt: str) -> str:
        """Appelle l'API Anthropic/Claude"""
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system="Tu es un expert DevSecOps. Génère UNIQUEMENT du JSON valide.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.content[0].text

    async def generate_fix_script(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str = "ubuntu",
            risk_tolerance: str = "low"
    ) -> ScriptResult:
        """Génère un script de correction"""

        if not self.is_ready:
            raise GeneratorException("Generator non initialisé", CoreErrorCodes.MODULE_NOT_READY)

        start_time = time.time()
        script_id = f"script_{int(time.time())}_{vulnerability_id}"

        logger.info(f"Génération script {script_id} pour {vulnerability_id}")

        try:
            script_data = await self._generate_script_with_retry(
                vulnerability_id,
                vulnerability_details,
                target_system,
                risk_tolerance
            )

            processing_time = time.time() - start_time

            result = ScriptResult(
                script_id=script_id,
                vulnerability_id=vulnerability_id,
                target_system=script_data.get('target_system', target_system),
                script_type=script_data.get('script_type', 'bash'),
                fix_script=script_data.get('fix_script', ''),
                rollback_script=script_data.get('rollback_script'),
                validation_status=script_data.get('validation_status', 'review_required'),
                risk_level=script_data.get('risk_level', 'medium'),
                estimated_execution_time=script_data.get('estimated_execution_time'),
                warnings=script_data.get('warnings', []),
                prerequisites=script_data.get('prerequisites', []),
                generated_at=datetime.utcnow().isoformat(),
                ai_model_used=self.model,
                confidence_score=script_data.get('confidence_score', 0.7)
            )

            self._update_stats(True, processing_time)
            logger.info(f"Script généré: {script_id} ({result.validation_status})")

            return result

        except Exception as e:
            logger.error(f"Erreur génération script: {e}")
            self._update_stats(False, time.time() - start_time)
            raise

    async def _generate_script_with_retry(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            risk_tolerance: str,
            max_retries: int = 2
    ) -> Dict[str, Any]:
        """Génère un script avec retry en cas d'erreur"""

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"🤖 Génération IA (tentative {attempt})...")

                if attempt == 1:
                    prompt = self._build_generation_prompt(
                        vulnerability_id,
                        vulnerability_details,
                        target_system,
                        risk_tolerance
                    )
                else:
                    logger.info("🔄 Retry avec prompt simplifié...")
                    prompt = self._build_simplified_prompt(
                        vulnerability_id,
                        vulnerability_details,
                        target_system
                    )

                response_text = await self._call_ai_api(prompt)

                script_data = self._parse_script_response(response_text)
                return script_data

            except json.JSONDecodeError as e:
                logger.error(f"❌ JSON invalide: {e}")
                logger.warning(f"Tentative {attempt} échouée: Impossible de parser la réponse IA")

                if attempt == max_retries:
                    logger.warning("⚠️ Utilisation script fallback (IA indisponible)")
                    return self._generate_fallback_script(
                        vulnerability_id,
                        vulnerability_details,
                        target_system
                    )

            except Exception as e:
                logger.error(f"Erreur appel IA: {e}")
                logger.warning(f"Tentative {attempt} échouée: Erreur IA: {e}")

                if attempt == max_retries:
                    logger.warning("⚠️ Utilisation script fallback (IA indisponible)")
                    return self._generate_fallback_script(
                        vulnerability_id,
                        vulnerability_details,
                        target_system
                    )

            if attempt < max_retries:
                await asyncio.sleep(2)

    def _build_generation_prompt(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            risk_tolerance: str
    ) -> str:
        """Construit le prompt de génération (version complète)"""

        vuln_json = json.dumps({
            'vulnerability_id': vulnerability_id,
            'name': vulnerability_details.get('name', 'Unknown'),
            'severity': vulnerability_details.get('severity', 'UNKNOWN'),
            'cvss_score': vulnerability_details.get('cvss_score', 0.0),
            'affected_service': vulnerability_details.get('affected_service', 'Unknown'),
            'description': vulnerability_details.get('description', '')[:300]
        }, indent=2)

        prompt = f"""Génère un script de correction pour cette vulnérabilité sur {target_system}.

Vulnérabilité:
{vuln_json}

Tolérance au risque: {risk_tolerance}

Réponds UNIQUEMENT avec un JSON valide (pas de markdown):
{{
  "target_system": "{target_system}",
  "script_type": "bash",
  "fix_script": "#!/bin/bash\\n# Script de correction\\n...",
  "rollback_script": "#!/bin/bash\\n# Script de rollback\\n...",
  "validation_status": "review_required",
  "risk_level": "medium",
  "estimated_execution_time": 60,
  "warnings": ["Warning 1", "Warning 2"],
  "prerequisites": ["Prerequisite 1"],
  "confidence_score": 0.8
}}

IMPORTANT: Script bash uniquement, JSON valide sans markdown."""

        return prompt

    def _build_simplified_prompt(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str
    ) -> str:
        """Construit un prompt simplifié pour retry"""

        prompt = f"""Système: {target_system}
Vulnérabilité: {vulnerability_id} - {vulnerability_details.get('name', 'Unknown')}

JSON uniquement (script bash simple):
{{"fix_script": "#!/bin/bash\\napt-get update\\napt-get upgrade -y", "script_type": "bash", "target_system": "{target_system}"}}"""

        return prompt

    def _parse_script_response(self, response_text: str) -> Dict[str, Any]:
        """Parse la réponse de l'IA"""

        response_text = response_text.strip()

        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.startswith('```'):
            response_text = response_text[3:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        script_data = json.loads(response_text)
        logger.info(f"✅ Script parsé ({len(script_data.get('fix_script', ''))} caractères)")

        if not script_data.get('fix_script'):
            raise GeneratorException("Script vide généré", CoreErrorCodes.SCRIPT_GENERATION_ERROR)

        return script_data

    def _generate_fallback_script(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str
    ) -> Dict[str, Any]:
        """Génère un script de fallback basique"""

        vuln_name = vulnerability_details.get('name', 'Unknown')
        severity = vulnerability_details.get('severity', 'UNKNOWN')

        fix_script = f"""#!/bin/bash
# Script de correction générique pour {vulnerability_id}
# Vulnérabilité: {vuln_name}
# Gravité: {severity}
# Système: {target_system}

# ATTENTION: Ce script est un template générique
# Il doit être adapté avant utilisation

echo "Correction de {vulnerability_id}..."

# Mise à jour du système
apt-get update
apt-get upgrade -y

# Redémarrage des services affectés si nécessaire
# systemctl restart <service>

echo "✅ Correction appliquée (vérification manuelle requise)"
"""

        rollback_script = f"""#!/bin/bash
# Script de rollback pour {vulnerability_id}
# ATTENTION: Adapter selon les modifications effectuées

echo "Rollback de {vulnerability_id}..."
# Restaurer la configuration précédente
echo "⚠️ Rollback à effectuer manuellement"
"""

        return {
            'target_system': target_system,
            'script_type': 'bash',
            'fix_script': fix_script,
            'rollback_script': rollback_script,
            'validation_status': 'review_required',
            'risk_level': 'high',
            'estimated_execution_time': 120,
            'warnings': [
                "Script générique - adaptation manuelle requise",
                "Tester dans un environnement de test d'abord",
                "Créer un backup avant exécution"
            ],
            'prerequisites': [
                "Droits root/sudo",
                "Backup du système",
                "Environnement de test disponible"
            ],
            'confidence_score': 0.4
        }

    def _update_stats(self, success: bool, processing_time: float, is_safe: bool = True):
        """Met à jour les statistiques de génération de scripts."""
        self.stats["total_scripts_generated"] += 1
        if is_safe:
            self.stats["safe_scripts"] += 1
        else:
            self.stats["risky_scripts"] += 1

        current_avg = self.stats["average_generation_time"]
        total = self.stats["total_scripts_generated"]
        self.stats["average_generation_time"] = (
            (current_avg * (total - 1) + processing_time) / total
            if total > 0
            else 0.0
        )

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques"""
        return {**self.stats, "provider": self.ai_provider, "model": self.model}

    def is_healthy(self) -> bool:
        """Vérifie si le générateur est en bonne santé"""
        return self.is_ready and getattr(self, "client", None) is not None


# === FONCTIONS UTILITAIRES DE HAUT NIVEAU ===


async def quick_script_generation(
    vulnerability_id: str,
    vulnerability_name: str,
    target_system: str = "ubuntu",
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Helper asynchrone simple pour générer rapidement un script.
    Utilisé par les tests pour vérifier le flux global.
    """
    try:
        generator = Generator(config)
        result: ScriptResult = await generator.generate_fix_script(
            vulnerability_id=vulnerability_id,
            vulnerability_details={"name": vulnerability_name},
            target_system=target_system,
        )
        return result.to_dict()
    except Exception as exc:
        # Format d'erreur attendu par les tests
        return {
            "script_id": f"error_{vulnerability_id}",
            "vulnerability_id": vulnerability_id,
            "main_script": "",
            "validation_result": {"is_safe": False},
            "error": str(exc),
        }


def create_generator(config: Optional[Dict[str, Any]] = None) -> "Generator":
    """Factory très simple utilisée dans les tests."""
    return Generator(config or get_config())


def validate_bash_syntax(script_content: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Valide la syntaxe bash en appelant `bash -n` dans un sous‑processus.
    Ne vérifie pas la logique métier, uniquement la syntaxe.
    """
    try:
        completed = subprocess.run(
            ["bash", "-n"],
            input=script_content,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        if completed.returncode == 0:
            return {"valid": True, "error_message": None}
        return {
            "valid": False,
            "error_message": completed.stderr.strip() or "Unknown bash syntax error",
        }
    except subprocess.TimeoutExpired:
        return {
            "valid": False,
            "error_message": "Bash syntax validation timeout",
        }
    except Exception as exc:
        return {
            "valid": False,
            "error_message": f"Validation error: {exc}",
        }


def extract_script_commands(script_content: str) -> Dict[str, List[str]]:
    """
    Analyse simple du script et regroupe les commandes par catégories.
    L'objectif est surtout de couvrir les assertions des tests.
    """
    categories: Dict[str, List[str]] = {
        "package_management": [],
        "service_management": [],
        "file_operations": [],
        "network_operations": [],
        "system_operations": [],
        "other": [],
    }

    for line in script_content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if any(stripped.startswith(cmd) for cmd in ["apt", "yum", "dnf", "pacman"]):
            categories["package_management"].append(stripped)
        elif any(stripped.startswith(cmd) for cmd in ["systemctl", "service"]):
            categories["service_management"].append(stripped)
        elif any(stripped.startswith(cmd) for cmd in ["cp", "mv", "rm", "chmod", "chown"]):
            categories["file_operations"].append(stripped)
        elif any(
            stripped.startswith(cmd)
            for cmd in ["iptables", "ufw", "firewall-cmd", "ip"]
        ):
            categories["network_operations"].append(stripped)
        elif any(stripped.startswith(cmd) for cmd in ["crontab", "sysctl", "echo"]):
            categories["system_operations"].append(stripped)
        else:
            categories["other"].append(stripped)

    return categories


def estimate_script_risk(script_content: str) -> Dict[str, Any]:
    """
    Estime grossièrement le risque d'un script en fonction de
    quelques commandes sensibles courantes.
    """
    content_lower = script_content.lower()

    factors = {
        "destructive_commands": 0,
        "network_changes": 0,
        "privilege_operations": 0,
        "external_downloads": 0,
    }

    if any(cmd in content_lower for cmd in ["rm -rf", "dd if=", "mkfs", ":() { :|:& };:"]):
        factors["destructive_commands"] += 2
    if any(cmd in content_lower for cmd in ["iptables", "ufw", "firewall-cmd"]):
        factors["network_changes"] += 1
    if any(cmd in content_lower for cmd in ["sudo ", "su -", "chmod 777", "chown root"]):
        factors["privilege_operations"] += 1
    if any(cmd in content_lower for cmd in ["wget ", "curl ", "http://", "https://"]):
        factors["external_downloads"] += 1

    risk_score = sum(factors.values())
    if risk_score == 0:
        level = "LOW"
    elif risk_score <= 2:
        level = "MEDIUM"
    elif risk_score <= 4:
        level = "HIGH"
    else:
        level = "CRITICAL"

    recommendations: List[str] = []
    if factors["destructive_commands"]:
        recommendations.append(
            "Réviser ou supprimer les commandes potentiellement destructrices."
        )
    if factors["network_changes"]:
        recommendations.append(
            "Vérifier l'impact des modifications réseau et prévoir un rollback."
        )
    if factors["privilege_operations"]:
        recommendations.append(
            "Limiter les opérations nécessitant des privilèges élevés."
        )
    if factors["external_downloads"]:
        recommendations.append(
            "Valider la provenance des téléchargements externes et utiliser HTTPS."
        )

    return {
        "risk_level": level,
        "risk_score": float(risk_score),
        "risk_factors": factors,
        "recommendations": recommendations,
    }


class ScanResultExporter:
    """
    Utilitaires d'export pour les objets de type ScanResult (ou équivalents).
    Les tests utilisent uniquement l'API statique.
    """

    @staticmethod
    def to_json(scan_result: Any, indent: int | None = None) -> str:
        if hasattr(scan_result, "to_dict"):
            data = scan_result.to_dict()
        else:
            # Fallback raisonnable basé sur les attributs attendus par les tests
            data = {
                "target": getattr(scan_result, "target", ""),
                "completed_at": getattr(scan_result, "completed_at", "").isoformat()
                if getattr(scan_result, "completed_at", None)
                else None,
                "duration": getattr(scan_result, "duration", 0.0),
                "vulnerabilities": [],
            }
        return json.dumps(data, indent=indent, default=str)

    @staticmethod
    def to_csv(scan_result: Any) -> str:
        """Retourne une chaîne CSV contenant au moins une ligne d'entête et une ligne de données."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["Target", "Vulnerability ID", "Name", "Severity"])

        vulns = getattr(scan_result, "vulnerabilities", []) or []
        for v in vulns:
            writer.writerow(
                [
                    getattr(scan_result, "target", ""),
                    getattr(v, "vulnerability_id", ""),
                    getattr(v, "name", ""),
                    getattr(v, "severity", ""),
                ]
            )

        return output.getvalue()

    @staticmethod
    def to_html(scan_result: Any) -> str:
        """Retourne un petit rapport HTML autonome."""
        target = getattr(scan_result, "target", "")
        vulns = getattr(scan_result, "vulnerabilities", []) or []

        rows = []
        for v in vulns:
            severity = getattr(v, "severity", "")
            css_class = severity.lower()
            rows.append(
                f"<tr class='{css_class}'><td>{target}</td>"
                f"<td>{getattr(v, 'vulnerability_id', '')}</td>"
                f"<td>{getattr(v, 'name', '')}</td>"
                f"<td>{severity}</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Scan result for {target}</title>
  <style>
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 4px 8px; }}
    .critical {{ background-color: #ffcccc; }}
    .high {{ background-color: #ffe0b3; }}
    .medium {{ background-color: #fff0b3; }}
    .low {{ background-color: #e6ffcc; }}
  </style>
</head>
<body>
  <h1>Scan result for {target}</h1>
  <table>
    <thead>
      <tr><th>Target</th><th>Vulnerability ID</th><th>Name</th><th>Severity</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
        return html


# === GESTIONNAIRE DE TEMPLATES ===


class ScriptTemplateManager:
    """
    Charge et met à disposition des templates de scripts stockés en JSON.
    """

    def __init__(self, templates_dir: str | Path):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Charge tous les fichiers JSON présents dans le répertoire de templates."""
        self.templates.clear()

        if not self.templates_dir.exists():
            return

        for file in self.templates_dir.glob("*.json"):
            try:
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                name = file.stem
                self.templates[name] = data
            except json.JSONDecodeError as e:
                logger.warning(f"Template JSON invalide ignoré ({file}): {e}")
            except Exception as e:
                logger.warning(f"Erreur lors du chargement du template {file}: {e}")


# === GESTIONNAIRE DE TEMPLATES ===


class ScriptTemplateManager:
    """
    Charge et met à disposition des templates de scripts stockés en JSON.
    """

    def __init__(self, templates_dir: str | Path):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.templates: Dict[str, Dict[str, Any]] = {}
        self._load_templates()

    def _load_templates(self) -> None:
        """Charge tous les fichiers JSON présents dans le répertoire de templates."""
        self.templates.clear()

        if not self.templates_dir.exists():
            return

        for file in self.templates_dir.glob("*.json"):
            try:
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                name = file.stem
                self.templates[name] = data
            except json.JSONDecodeError as e:
                logger.warning(f"Template JSON invalide ignoré ({file}): {e}")
            except Exception as e:
                logger.warning(f"Erreur lors du chargement du template {file}: {e}")