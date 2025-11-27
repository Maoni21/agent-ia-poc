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
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

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


# === CLASSE PRINCIPALE ===

class Generator:
    """Générateur de scripts de correction avec support multi-provider"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.db = Database()
        self.is_ready = False
        self.stats = {
            "total_scripts": 0,
            "successful_scripts": 0,
            "failed_scripts": 0,
            "average_generation_time": 0.0
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

    def _update_stats(self, success: bool, processing_time: float):
        """Met à jour les statistiques"""
        self.stats["total_scripts"] += 1
        if success:
            self.stats["successful_scripts"] += 1
        else:
            self.stats["failed_scripts"] += 1

        current_avg = self.stats["average_generation_time"]
        total = self.stats["total_scripts"]
        self.stats["average_generation_time"] = (current_avg * (total - 1) + processing_time) / total

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques"""
        return {**self.stats, "provider": self.ai_provider, "model": self.model}

    def is_healthy(self) -> bool:
        """Vérifie si le générateur est en bonne santé"""
        return self.is_ready