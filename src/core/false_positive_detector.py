"""
Module FalsePositiveDetector pour l'Agent IA de Cybersécurité
Détecte les faux positifs avec l'aide de Claude/OpenAI
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from config import get_config
from src.utils.logger import setup_logger
from .exceptions import AnalyzerException, CoreErrorCodes

logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class FalsePositiveAnalysis:
    """Analyse d'une vulnérabilité pour détecter les faux positifs"""
    vulnerability_id: str
    is_false_positive: bool
    confidence: float  # 0.0 à 1.0
    reasoning: str
    real_risk_score: int  # 0 à 10
    recommendations: List[str]
    indicators: Dict[str, Any]  # Indicateurs utilisés pour la détection

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# === CLASSE PRINCIPALE ===

class FalsePositiveDetector:
    """Détecte les faux positifs avec l'aide de l'IA"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.is_ready = False
        self.stats = {
            "total_analyses": 0,
            "false_positives_detected": 0,
            "true_positives_confirmed": 0,
            "average_confidence": 0.0
        }

        # Détection du provider
        self.ai_provider = self.config.get('ai_provider', 'anthropic')

        # Initialisation du client IA selon le provider
        if self.ai_provider == 'openai':
            self._init_openai()
        elif self.ai_provider == 'anthropic':
            self._init_anthropic()
        else:
            raise AnalyzerException(f"Provider IA non supporté: {self.ai_provider}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_openai(self):
        """Initialise le client OpenAI"""
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                api_key=self.config.get('openai_api_key'),
                timeout=self.config.get('openai_timeout', 120)
            )
            self.model = self.config.get('openai_model', 'gpt-4')
            self.max_tokens = self.config.get('openai_max_tokens', 1500)
            self.temperature = self.config.get('openai_temperature', 0.3)
            self.is_ready = True
            logger.info("Client OpenAI initialisé pour FalsePositiveDetector")
        except Exception as e:
            logger.error(f"Erreur initialisation OpenAI: {e}")
            raise AnalyzerException(f"Impossible d'initialiser OpenAI: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_anthropic(self):
        """Initialise le client Anthropic/Claude"""
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(
                api_key=self.config.get('anthropic_api_key')
            )
            self.model = self.config.get('anthropic_model', 'claude-sonnet-4-20250514')
            self.max_tokens = self.config.get('anthropic_max_tokens', 1500)
            self.temperature = self.config.get('anthropic_temperature', 0.3)
            self.is_ready = True
            logger.info("Client Anthropic initialisé pour FalsePositiveDetector")
        except Exception as e:
            logger.error(f"Erreur initialisation Anthropic: {e}")
            raise AnalyzerException(f"Impossible d'initialiser Anthropic: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    async def analyze_vulnerability(
            self,
            vuln: Dict[str, Any],
            scan_context: Dict[str, Any]
    ) -> FalsePositiveAnalysis:
        """
        Analyse si une vulnérabilité est un faux positif
        
        Args:
            vuln: Dictionnaire contenant les détails de la vulnérabilité
            scan_context: Contexte du scan (type, ports, bannières, OS, etc.)
            
        Returns:
            FalsePositiveAnalysis: Résultat de l'analyse
        """
        if not self.is_ready:
            raise AnalyzerException("FalsePositiveDetector non initialisé", CoreErrorCodes.MODULE_NOT_READY)

        logger.info(f"Analyse faux positif pour {vuln.get('vulnerability_id', 'unknown')}")

        try:
            # Construire le prompt
            prompt = self._build_analysis_prompt(vuln, scan_context)

            # Appeler l'IA
            if self.ai_provider == 'anthropic':
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                response_text = response.content[0].text
            else:  # OpenAI
                response = await self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )
                response_text = response.choices[0].message.content

            # Parser la réponse
            analysis_data = self._parse_ai_response(response_text, vuln.get('vulnerability_id', 'unknown'))

            # Mettre à jour les stats
            self.stats["total_analyses"] += 1
            if analysis_data["is_false_positive"]:
                self.stats["false_positives_detected"] += 1
            else:
                self.stats["true_positives_confirmed"] += 1
            
            current_avg = self.stats["average_confidence"]
            total = self.stats["total_analyses"]
            self.stats["average_confidence"] = (current_avg * (total - 1) + analysis_data["confidence"]) / total

            return FalsePositiveAnalysis(**analysis_data)

        except Exception as e:
            logger.error(f"Erreur analyse faux positif: {e}")
            # Retourner une analyse par défaut (vrai positif)
            return FalsePositiveAnalysis(
                vulnerability_id=vuln.get('vulnerability_id', 'unknown'),
                is_false_positive=False,
                confidence=0.5,
                reasoning=f"Erreur lors de l'analyse: {str(e)}",
                real_risk_score=int(vuln.get('cvss_score', 0) or 0),
                recommendations=["Vérifier manuellement"],
                indicators={}
            )

    def _build_analysis_prompt(
            self,
            vuln: Dict[str, Any],
            scan_context: Dict[str, Any]
    ) -> str:
        """Construit le prompt pour l'analyse de faux positif"""
        
        cve_id = vuln.get('vulnerability_id', 'N/A')
        service = vuln.get('affected_service', 'Unknown')
        version = vuln.get('version', 'Unknown')
        cvss_score = vuln.get('cvss_score', 0)
        severity = vuln.get('severity', 'UNKNOWN')
        description = vuln.get('description', 'No description')
        
        scan_type = scan_context.get('scan_type', 'unknown')
        open_ports = scan_context.get('open_ports', [])
        banners = scan_context.get('banners', {})
        os_detected = scan_context.get('os', 'Unknown')
        
        prompt = f"""Analyse cette vulnérabilité détectée pour déterminer si c'est un vrai ou faux positif.

INFORMATIONS SUR LA VULNÉRABILITÉ:
- CVE ID: {cve_id}
- Service détecté: {service}
- Version détectée: {version}
- Sévérité: {severity}
- Score CVSS: {cvss_score}
- Description: {description}

CONTEXTE DU SCAN:
- Type de scan: {scan_type}
- Ports ouverts: {open_ports}
- Bannières de service: {banners}
- OS détecté: {os_detected}

QUESTIONS CRITIQUES À ANALYSER:
1. La version détectée est-elle vraiment vulnérable à ce CVE spécifique?
2. Y a-t-il des signes que le service est déjà patché/mitigé?
3. Le contexte du scan est-il fiable (bannières cohérentes, ports corrects)?
4. Y a-t-il des incohérences dans les données (version vs CVE, OS vs service)?
5. Le CVE s'applique-t-il vraiment à cette configuration?
6. Y a-t-il des mitigations en place qui réduisent le risque réel?

FORMAT DE SORTIE (JSON uniquement):
{{
    "is_false_positive": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "explication détaillée de la décision",
    "real_risk_score": 0-10,
    "recommendations": ["action1", "action2"],
    "indicators": {{
        "version_match": true/false,
        "banner_consistent": true/false,
        "cve_applicable": true/false,
        "mitigations_present": true/false
    }}
}}

IMPORTANT:
- confidence > 0.8 = très sûr de la décision
- confidence 0.5-0.8 = modérément sûr
- confidence < 0.5 = incertain, nécessite vérification manuelle
- real_risk_score doit refléter le risque réel si ce n'est pas un faux positif

Génère uniquement le JSON, sans texte supplémentaire."""

        return prompt

    def _parse_ai_response(self, ai_response: str, vulnerability_id: str) -> Dict[str, Any]:
        """Parse la réponse de l'IA"""
        try:
            # Essayer de parser directement le JSON
            if ai_response.strip().startswith('{'):
                parsed = json.loads(ai_response)
            else:
                # Essayer d'extraire le JSON du texte
                import re
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                else:
                    raise ValueError("Aucun JSON trouvé dans la réponse")
            
            # Valider et compléter les champs
            return {
                "vulnerability_id": vulnerability_id,
                "is_false_positive": parsed.get("is_false_positive", False),
                "confidence": max(0.0, min(1.0, float(parsed.get("confidence", 0.5)))),
                "reasoning": parsed.get("reasoning", "Analyse effectuée"),
                "real_risk_score": max(0, min(10, int(parsed.get("real_risk_score", 5)))),
                "recommendations": parsed.get("recommendations", []),
                "indicators": parsed.get("indicators", {})
            }
            
        except Exception as e:
            logger.error(f"Erreur parsing réponse IA: {e}")
            # Retourner une analyse par défaut
            return {
                "vulnerability_id": vulnerability_id,
                "is_false_positive": False,
                "confidence": 0.3,
                "reasoning": f"Erreur parsing: {str(e)}",
                "real_risk_score": 5,
                "recommendations": ["Vérification manuelle requise"],
                "indicators": {}
            }

    async def analyze_batch(
            self,
            vulnerabilities: List[Dict[str, Any]],
            scan_context: Dict[str, Any]
    ) -> List[FalsePositiveAnalysis]:
        """Analyse plusieurs vulnérabilités en batch"""
        results = []
        
        for vuln in vulnerabilities:
            try:
                analysis = await self.analyze_vulnerability(vuln, scan_context)
                results.append(analysis)
                # Petite pause pour éviter le rate limiting
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Erreur analyse batch pour {vuln.get('vulnerability_id')}: {e}")
                continue
        
        return results

