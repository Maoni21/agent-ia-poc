"""
Module Analyzer pour l'Agent IA de Cybersécurité
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

from config import get_config
from src.utils.logger import setup_logger
from src.database.database import Database
from .exceptions import AnalyzerException, CoreErrorCodes
from .false_positive_detector import FalsePositiveDetector

logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class VulnerabilityAnalysis:
    """Analyse complète d'une vulnérabilité"""
    vulnerability_id: str
    name: str
    severity: str
    cvss_score: float
    impact_analysis: str
    exploitability: str
    priority_score: int
    affected_service: str
    recommended_actions: List[str]
    dependencies: List[str]
    references: List[str]
    cvss_vector: Optional[str] = None
    nist_verified: bool = False
    nist_url: Optional[str] = None
    solution_links: List[str] = None
    ai_explanation: Optional[str] = None
    correction_script: Optional[str] = None
    rollback_script: Optional[str] = None
    business_impact: Optional[str] = None
    is_false_positive: bool = False
    false_positive_confidence: Optional[float] = None
    false_positive_reasoning: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    """Résultat complet d'une analyse"""
    analysis_id: str
    target_system: str
    analyzed_at: datetime
    analysis_summary: Dict[str, Any]
    vulnerabilities: List[VulnerabilityAnalysis]
    remediation_plan: Dict[str, Any]
    ai_model_used: str
    confidence_score: float
    processing_time: float
    business_context: Optional[str] = None
    nist_enriched: bool = False
    nist_call_count: int = 0
    nist_cache_hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['analyzed_at'] = self.analyzed_at.isoformat()
        result['vulnerabilities'] = [vuln.to_dict() for vuln in self.vulnerabilities]
        return result


# === CLASSE PRINCIPALE ===

class Analyzer:
    """Analyseur IA de vulnérabilités avec support multi-provider"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Accepter soit un dict, soit l'objet Config retourné par get_config()
        raw_config: Any = config or get_config()
        if isinstance(raw_config, dict):
            self.config: Dict[str, Any] = raw_config
        else:
            self.config = raw_config.__dict__.copy()

        # Validation minimale de la configuration pour les tests
        if self.config.get("openai_api_key") is None:
            raise AnalyzerException(
                "Configuration OpenAI invalide (clé manquante)",
                CoreErrorCodes.INVALID_CONFIGURATION,
            )

        self.db = Database()
        self.is_ready = False
        self.stats = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_processing_time": 0.0,
            "nist_api_calls": 0,
            "nist_cache_hits": 0,
            "false_positives_detected": 0,
        }

        # Configuration LLM de base pour les tests
        self.llm_config: Dict[str, Any] = {
            "provider": self.config.get("ai_provider", "anthropic"),
            "model": self.config.get("openai_model", "gpt-4"),
            "timeout": self.config.get("timeout", 60),
        }

        # Détection du provider
        self.ai_provider = self.llm_config["provider"]
        # Alias attendu par certains tests
        self.current_provider = self.ai_provider

        # Initialisation du client IA selon le provider
        if self.ai_provider == 'openai':
            self._init_openai()
        elif self.ai_provider == 'anthropic':
            self._init_anthropic()
        else:
            raise AnalyzerException(f"Provider IA non supporté: {self.ai_provider}", CoreErrorCodes.CORE_INIT_ERROR)
        
        # Initialiser le détecteur de faux positifs
        try:
            self.false_positive_detector = FalsePositiveDetector(self.config)
            logger.info("✅ FalsePositiveDetector initialisé")
        except Exception as e:
            logger.warning(f"⚠️ FalsePositiveDetector non disponible: {e}")
            self.false_positive_detector = None

    def _init_openai(self):
        """Initialise le client OpenAI"""
        try:
            # Import localisé pour faciliter le patch dans les tests
            from openai import AsyncOpenAI  # type: ignore[import-not-found]
            self.client = AsyncOpenAI(
                api_key=self.config.get('openai_api_key'),
                timeout=self.config.get('openai_timeout', 120)
            )
            self.model = self.config.get('openai_model', 'gpt-4')
            self.max_tokens = self.config.get('openai_max_tokens', 1000)
            self.temperature = self.config.get('openai_temperature', 0.7)
            self.is_ready = True
            logger.info(f"Client OpenAI initialisé (modèle: {self.model})")
        except Exception as e:
            logger.error(f"Erreur initialisation OpenAI: {e}")
            raise AnalyzerException(f"Impossible d'initialiser OpenAI: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_anthropic(self):
        """Initialise le client Anthropic/Claude"""
        try:
            from anthropic import AsyncAnthropic  # type: ignore[import-not-found]
            self.client = AsyncAnthropic(
                api_key=self.config.get('anthropic_api_key'),
                timeout=self.config.get('anthropic_timeout', 120)
            )
            self.model = self.config.get('anthropic_model', 'claude-sonnet-4-20250514')
            self.max_tokens = self.config.get('anthropic_max_tokens', 4096)
            self.temperature = self.config.get('anthropic_temperature', 0.7)
            self.is_ready = True
            logger.info(f"Client Anthropic initialisé (modèle: {self.model})")
        except Exception as e:
            logger.error(f"Erreur initialisation Anthropic: {e}")
            raise AnalyzerException(f"Impossible d'initialiser Anthropic: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

        logger.info("✅ Analyzer initialisé (NIST + IA + Parser robuste)")

    async def _call_ai_api(self, prompt: str) -> str:
        """Appelle l'API IA selon le provider configuré"""
        if self.ai_provider == 'openai':
            return await self._call_openai(prompt)
        elif self.ai_provider == 'anthropic':
            return await self._call_anthropic(prompt)
        else:
            raise AnalyzerException(f"Provider inconnu: {self.ai_provider}", CoreErrorCodes.AI_SERVICE_ERROR)

    async def _call_openai(self, prompt: str) -> str:
        """Appelle l'API OpenAI"""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "Tu es un expert en cybersécurité. Réponds UNIQUEMENT en JSON valide."},
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
            system="Tu es un expert en cybersécurité. Réponds UNIQUEMENT en JSON valide.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.content[0].text

    async def analyze_vulnerabilities_batch(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System",
            business_context: Optional[str] = None,
            batch_size: int = 10
    ) -> AnalysisResult:
        """Analyse un batch de vulnérabilités"""

        if not vulnerabilities_data:
            raise AnalyzerException("Aucune vulnérabilité à analyser", CoreErrorCodes.INVALID_VULNERABILITY_DATA)

        start_time = time.time()
        analysis_id = f"analysis_batch_{int(time.time())}"

        logger.info("🔧 Normalisation des clés...")
        vulnerabilities_data = self._normalize_vulnerability_keys(vulnerabilities_data)

        logger.info(f"🔍 Analyse par batch: {len(vulnerabilities_data)} vulns, batch_size={batch_size}")

        batches = [vulnerabilities_data[i:i + batch_size]
                   for i in range(0, len(vulnerabilities_data), batch_size)]

        logger.info(f"📦 {len(batches)} batches à traiter")

        all_analyzed_vulns = []

        for i, batch in enumerate(batches, 1):
            logger.info(f"🔄 Batch {i}/{len(batches)} ({len(batch)} vulns)")

            analyzed_vulns = await self._analyze_batch(
                batch,
                target_system,
                business_context
            )

            all_analyzed_vulns.extend(analyzed_vulns)
            logger.info(f"✅ Batch {i}/{len(batches)} terminé")

            if i < len(batches):
                await asyncio.sleep(1)

        logger.info("📋 Plan de remédiation global...")
        remediation_plan = self._create_remediation_plan(all_analyzed_vulns)

        processing_time = time.time() - start_time
        logger.info(f"✅ Analyse batch terminée en {processing_time:.2f}s")

        analysis_summary = self._create_analysis_summary(all_analyzed_vulns)

        result = AnalysisResult(
            analysis_id=analysis_id,
            target_system=target_system,
            analyzed_at=datetime.utcnow(),
            analysis_summary=analysis_summary,
            vulnerabilities=all_analyzed_vulns,
            remediation_plan=remediation_plan,
            ai_model_used=self.model,
            confidence_score=self._calculate_confidence_score(all_analyzed_vulns),
            processing_time=processing_time,
            business_context=business_context,
            nist_enriched=True,
            nist_call_count=self.stats["nist_api_calls"],
            nist_cache_hits=self.stats["nist_cache_hits"]
        )

        self._update_stats(True, processing_time)
        return result

    async def analyze_vulnerabilities(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System",
            business_context: Optional[str] = None,
    ) -> AnalysisResult:
        """
        Compatibilité avec l'ancienne API `analyze_vulnerabilities` utilisée dans les tests.

        Délègue à `analyze_vulnerabilities_batch` avec un batch unique.
        """
        batch_size = len(vulnerabilities_data) or 1
        return await self.analyze_vulnerabilities_batch(
            vulnerabilities_data=vulnerabilities_data,
            target_system=target_system,
            business_context=business_context,
            batch_size=batch_size,
        )

    async def _analyze_batch(
            self,
            vulnerabilities: List[Dict[str, Any]],
            target_system: str,
            business_context: Optional[str]
    ) -> List[VulnerabilityAnalysis]:
        """Analyse un batch de vulnérabilités"""

        logger.info(f"🔍 Analyse: {len(vulnerabilities)} vulnérabilités")

        logger.info("📊 Enrichissement NIST...")
        enriched_vulns = await self._enrich_with_nist_batch(vulnerabilities)

        logger.info("🤖 Analyse IA...")
        analyzed_vulns = await self._ai_analysis(enriched_vulns, target_system, business_context)

        # Détection de faux positifs (si activé)
        if self.false_positive_detector and self.config.get('enable_false_positive_detection', True):
            logger.info("🔍 Détection de faux positifs...")
            analyzed_vulns = await self._detect_false_positives(analyzed_vulns, target_system)

        return analyzed_vulns

    async def _enrich_with_nist_batch(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:

        from src.core.nist_enricher import NISTEnricher

        nist_client = NISTEnricher()
        enriched = []

        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id') or vuln.get('vulnerability_id', '')

            if cve_id and cve_id.startswith('CVE-'):
                nist_data = await nist_client.enrich_cve(cve_id)

                if nist_data:
                    self.stats["nist_cache_hits"] += 1
                    vuln['nist_data'] = nist_data
                    vuln['nist_verified'] = True
                    vuln['nist_url'] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                    if 'cvss_v3' in nist_data.get('metrics', {}):
                        cvss_data = nist_data['metrics']['cvss_v3'][0]['cvssData']
                        vuln['cvss_score'] = cvss_data.get('baseScore', vuln.get('cvss_score', 0.0))
                        vuln['cvss_vector'] = cvss_data.get('vectorString')
                        vuln['severity'] = cvss_data.get('baseSeverity', vuln.get('severity', 'UNKNOWN'))

                    if 'references' in nist_data:
                        vuln['solution_links'] = [
                            ref['url'] for ref in nist_data['references'][:3]
                            if 'url' in ref
                        ]

            enriched.append(vuln)

        return enriched

    async def _ai_analysis(
            self,
            vulnerabilities: List[Dict[str, Any]],
            target_system: str,
            business_context: Optional[str]
    ) -> List[VulnerabilityAnalysis]:
        """Analyse IA des vulnérabilités avec retry"""

        max_retries = 2

        for attempt in range(1, max_retries + 1):
            try:
                if attempt == 1:
                    prompt = self._build_analysis_prompt(vulnerabilities, target_system, business_context)
                else:
                    logger.info("🔄 Retry avec prompt simplifié...")
                    prompt = self._build_simplified_prompt(vulnerabilities, target_system)

                response_text = await self._call_ai_api(prompt)

                response_text = response_text.strip()
                if response_text.startswith('```json'):
                    response_text = response_text[7:]
                if response_text.startswith('```'):
                    response_text = response_text[3:]
                if response_text.endswith('```'):
                    response_text = response_text[:-3]
                response_text = response_text.strip()

                try:
                    analysis_data = json.loads(response_text)
                    logger.info(f"✅ JSON parsé: {len(analysis_data.get('vulnerabilities', []))} vulnérabilités")
                except json.JSONDecodeError as e:
                    logger.error(f"❌ JSON invalide: {e}")
                    raise

                analyzed_vulns = []
                for vuln_data in analysis_data.get('vulnerabilities', []):
                    original_vuln = next(
                        (v for v in vulnerabilities
                         if v.get('vulnerability_id') == vuln_data.get('vulnerability_id')),
                        {}
                    )

                    vuln = VulnerabilityAnalysis(
                        vulnerability_id=vuln_data.get('vulnerability_id', 'UNKNOWN'),
                        name=vuln_data.get('name', 'Unknown'),
                        severity=vuln_data.get('severity', 'UNKNOWN'),
                        cvss_score=float(vuln_data.get('cvss_score', 0.0)),
                        impact_analysis=vuln_data.get('impact_analysis', ''),
                        exploitability=vuln_data.get('exploitability', 'UNKNOWN'),
                        priority_score=int(vuln_data.get('priority_score', 5)),
                        affected_service=vuln_data.get('affected_service', 'Unknown'),
                        recommended_actions=vuln_data.get('recommended_actions', []),
                        dependencies=vuln_data.get('dependencies', []),
                        references=vuln_data.get('references', []),
                        cvss_vector=original_vuln.get('cvss_vector'),
                        nist_verified=original_vuln.get('nist_verified', False),
                        nist_url=original_vuln.get('nist_url'),
                        solution_links=original_vuln.get('solution_links', []),
                        ai_explanation=vuln_data.get('ai_explanation'),
                        business_impact=vuln_data.get('business_impact')
                    )
                    analyzed_vulns.append(vuln)

                logger.info(f"✅ Analyse terminée en {time.time():.2f}s")
                return analyzed_vulns

            except json.JSONDecodeError as e:
                logger.warning(f"Tentative {attempt} échouée: {e}")
                if attempt == max_retries:
                    raise AnalyzerException(f"JSON invalide après {max_retries} tentatives",
                                            CoreErrorCodes.AI_RESPONSE_PARSE_ERROR)
            except Exception as e:
                logger.error(f"Erreur tentative {attempt}: {e}")
                if attempt == max_retries:
                    raise

    def _build_analysis_prompt(self, vulnerabilities: List[Dict], target_system: str,
                               business_context: Optional[str]) -> str:
        """Construit le prompt d'analyse amélioré pour contextualisation"""
        vulns_json = json.dumps([{
            'vulnerability_id': v.get('vulnerability_id', v.get('cve_id', 'UNKNOWN')),
            'name': v.get('name', v.get('vulnerability_name', 'Unknown')),
            'severity': v.get('severity', 'UNKNOWN'),
            'cvss_score': v.get('cvss_score', 0.0),
            'affected_service': v.get('service', v.get('affected_service', 'Unknown')),
            'description': v.get('description', '')[:200]
        } for v in vulnerabilities], indent=2)

        context_note = f"\nContexte business: {business_context}" if business_context else ""

        prompt = f"""Analyse et CONTEXTUALISE ces vulnérabilités pour le système: {target_system}{context_note}

Vulnérabilités à analyser:
{vulns_json}

Pour CHAQUE vulnérabilité, fournis une analyse complète et contextualisée:

1. **impact_analysis**: Impact technique concret et spécifique (ex: "Permet l'exécution de code à distance sur le serveur web exposé via injection de commandes")
2. **exploitability**: Facilité d'exploitation (HIGH/MEDIUM/LOW) avec justification courte (ex: "HIGH - Exploit public disponible, pas d'authentification requise")
3. **business_impact**: Impact business concret et mesurable (ex: "Exposition des données clients, violation RGPD possible, perte de confiance, arrêt de service")
4. **ai_explanation**: Explication claire et accessible pour l'utilisateur (2-3 phrases max, en français, sans jargon technique excessif)
5. **recommended_actions**: Actions concrètes et SPÉCIFIQUES (ex: "Mettre à jour Apache vers version 2.4.58" PAS juste "mettre à jour vers version stable")

Réponds UNIQUEMENT avec un JSON valide (pas de markdown, pas de texte) au format:
{{
  "vulnerabilities": [
    {{
      "vulnerability_id": "CVE-XXXX-XXXX",
      "name": "Nom de la vulnérabilité",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "cvss_score": 9.8,
      "impact_analysis": "Impact technique concret et spécifique",
      "exploitability": "HIGH|MEDIUM|LOW",
      "priority_score": 10,
      "affected_service": "nom_du_service",
      "recommended_actions": ["Action spécifique 1", "Action spécifique 2"],
      "dependencies": [],
      "references": [],
      "ai_explanation": "Explication claire pour l'utilisateur (2-3 phrases)",
      "business_impact": "Impact business concret et mesurable"
    }}
  ]
}}

IMPORTANT: 
- recommended_actions doit être SPÉCIFIQUE (ex: "Mettre à jour Apache vers 2.4.58" pas "mettre à jour")
- ai_explanation doit aider l'utilisateur à comprendre le risque réel
- business_impact doit être concret (RGPD, disponibilité, réputation, coûts)
- Réponds UNIQUEMENT avec le JSON, sans texte avant ou après."""

        return prompt

    def _build_simplified_prompt(self, vulnerabilities: List[Dict], target_system: str) -> str:
        """Construit un prompt simplifié pour retry"""
        vulns_simple = [
            f"- {v.get('vulnerability_id', 'UNKNOWN')}: {v.get('name', 'Unknown')} (Gravité: {v.get('severity', 'UNKNOWN')})"
            for v in vulnerabilities
        ]

        prompt = f"""Système: {target_system}

Vulnérabilités:
{chr(10).join(vulns_simple)}

JSON uniquement:
{{"vulnerabilities": [...]}}"""

        return prompt

    def _normalize_vulnerability_keys(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Normalise les clés des vulnérabilités"""
        normalized = []

        for vuln in vulnerabilities:
            normalized_vuln = {
                'vulnerability_id': vuln.get('vulnerability_id') or vuln.get('cve_id', 'UNKNOWN'),
                'name': vuln.get('name') or vuln.get('vulnerability_name', 'Unknown'),
                'severity': vuln.get('severity', 'UNKNOWN'),
                'cvss_score': vuln.get('cvss_score', 0.0),
                'service': vuln.get('service') or vuln.get('affected_service', 'Unknown'),
                'description': vuln.get('description', ''),
                'port': vuln.get('port'),
                'protocol': vuln.get('protocol')
            }
            normalized.append(normalized_vuln)

        return normalized

    def _create_remediation_plan(self, vulnerabilities: List[VulnerabilityAnalysis]) -> Dict[str, Any]:
        """Crée un plan de remédiation optimisé (sans appel IA supplémentaire)"""
        critical_vulns = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high_vulns = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium_vulns = [v for v in vulnerabilities if v.severity == "MEDIUM"]

        # Actions immédiates (CRITICAL + HIGH) - Utiliser TOUTES les actions recommandées
        immediate_actions = []
        for vuln in sorted(critical_vulns + high_vulns, key=lambda x: x.priority_score, reverse=True):
            if vuln.recommended_actions:
                # Prendre toutes les actions recommandées (max 3 par vulnérabilité pour éviter la surcharge)
                for action in vuln.recommended_actions[:3]:
                    immediate_actions.append({
                        "vulnerability_id": vuln.vulnerability_id,
                        "vulnerability_name": vuln.name,
                        "action": action,
                        "priority": vuln.priority_score,
                        "estimated_time": self._estimate_fix_time(vuln),
                        "service": vuln.affected_service,
                        "cvss_score": vuln.cvss_score,
                        "severity": vuln.severity
                    })

        # Actions court terme (MEDIUM) - Utiliser toutes les actions recommandées
        short_term_actions = []
        for vuln in sorted(medium_vulns, key=lambda x: x.priority_score, reverse=True):
            if vuln.recommended_actions:
                # Max 2 actions par vulnérabilité MEDIUM
                for action in vuln.recommended_actions[:2]:
                    short_term_actions.append({
                        "vulnerability_id": vuln.vulnerability_id,
                        "vulnerability_name": vuln.name,
                        "action": action,
                        "priority": vuln.priority_score,
                        "service": vuln.affected_service,
                        "cvss_score": vuln.cvss_score,
                        "severity": vuln.severity
                    })

        # Grouper par service pour optimisation et meilleure visualisation
        actions_by_service = {}
        for action in immediate_actions + short_term_actions:
            service = action["service"]
            if service not in actions_by_service:
                actions_by_service[service] = []
            actions_by_service[service].append(action)

        # Limiter le nombre d'actions par service (top 5 par service)
        for service in actions_by_service:
            actions_by_service[service] = sorted(
                actions_by_service[service],
                key=lambda x: (x.get("priority", 0), x.get("cvss_score", 0)),
                reverse=True
            )[:5]

        return {
            "immediate_actions": immediate_actions[:15],  # Top 15 actions immédiates
            "short_term_actions": short_term_actions[:10],  # Top 10 actions court terme
            "actions_by_service": {k: v for k, v in actions_by_service.items()},  # Regroupement par service
            "estimated_total_time_hours": sum(a.get('estimated_time', 1) for a in immediate_actions),
            "critical_count": len(critical_vulns),
            "high_count": len(high_vulns),
            "medium_count": len(medium_vulns),
            "priority_order": [v.vulnerability_id for v in
                               sorted(vulnerabilities, key=lambda x: x.priority_score, reverse=True)],
            "summary": {
                "total_actions": len(immediate_actions) + len(short_term_actions),
                "services_affected": len(actions_by_service),
                "top_priority_vuln": immediate_actions[0]["vulnerability_id"] if immediate_actions else None,
                "top_priority_service": max(actions_by_service.items(), key=lambda x: len(x[1]))[0] if actions_by_service else None
            }
        }

    def _estimate_fix_time(self, vuln: VulnerabilityAnalysis) -> float:
        """Estime le temps de correction"""
        base_times = {
            "CRITICAL": 4.0,
            "HIGH": 2.0,
            "MEDIUM": 1.0,
            "LOW": 0.5
        }
        return base_times.get(vuln.severity, 1.0)

    def _create_analysis_summary(self, vulnerabilities: List[VulnerabilityAnalysis]) -> Dict[str, Any]:
        """Crée un résumé de l'analyse"""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        cvss_scores = [v.cvss_score for v in vulnerabilities if v.cvss_score > 0]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

        priorities = [v.priority_score for v in vulnerabilities]
        max_priority = max(priorities) if priorities else 0

        nist_verified = sum(1 for v in vulnerabilities if v.nist_verified)

        risk_score = (
                             severity_counts["CRITICAL"] * 10 +
                             severity_counts["HIGH"] * 5 +
                             severity_counts["MEDIUM"] * 2 +
                             severity_counts["LOW"] * 1
                     ) / max(len(vulnerabilities), 1)

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "medium_count": severity_counts["MEDIUM"],
            "low_count": severity_counts["LOW"],
            "unknown_count": severity_counts["UNKNOWN"],
            "overall_risk_score": round(risk_score, 1),
            "average_cvss": round(avg_cvss, 1),
            "highest_priority": max_priority,
            "nist_verified_count": nist_verified
        }

    def _calculate_confidence_score(self, vulnerabilities: List[VulnerabilityAnalysis]) -> float:
        """Calcule un score de confiance"""
        if not vulnerabilities:
            return 0.0

        nist_verified_count = sum(1 for v in vulnerabilities if v.nist_verified)
        nist_ratio = nist_verified_count / len(vulnerabilities)

        has_recommendations = sum(1 for v in vulnerabilities if v.recommended_actions)
        recommendations_ratio = has_recommendations / len(vulnerabilities)

        confidence = (nist_ratio * 0.6) + (recommendations_ratio * 0.4)
        return round(confidence, 2)

    def _update_stats(self, success: bool, processing_time: float):
        """Met à jour les statistiques"""
        self.stats["total_analyses"] += 1
        if success:
            self.stats["successful_analyses"] += 1
        else:
            self.stats["failed_analyses"] += 1

        current_avg = self.stats["average_processing_time"]
        total = self.stats["total_analyses"]
        self.stats["average_processing_time"] = (current_avg * (total - 1) + processing_time) / total

    # === MÉTHODES UTILITAIRES ATTENDUES PAR LES TESTS ===

    def _get_model_name(self) -> str:
        """
        Retourne le nom du modèle IA actuellement configuré.
        Utilisée uniquement dans les tests.
        """
        return getattr(self, "model", "unknown-model")

    async def _detect_false_positives(
            self,
            analyzed_vulns: List[VulnerabilityAnalysis],
            target_system: str
    ) -> List[VulnerabilityAnalysis]:
        """Détecte les faux positifs dans les vulnérabilités analysées"""
        if not self.false_positive_detector:
            return analyzed_vulns
        
        # Construire le contexte de scan (basique pour l'instant)
        scan_context = {
            "scan_type": "full",
            "open_ports": [],
            "banners": {},
            "os": target_system
        }
        
        # Analyser chaque vulnérabilité
        for vuln in analyzed_vulns:
            try:
                vuln_dict = vuln.to_dict()
                fp_analysis = await self.false_positive_detector.analyze_vulnerability(
                    vuln_dict,
                    scan_context
                )
                
                # Mettre à jour la vulnérabilité avec les résultats
                vuln.is_false_positive = fp_analysis.is_false_positive
                vuln.false_positive_confidence = fp_analysis.confidence
                vuln.false_positive_reasoning = fp_analysis.reasoning
                
                # Mettre à jour les stats
                if fp_analysis.is_false_positive:
                    self.stats["false_positives_detected"] += 1
                    logger.info(f"⚠️ Faux positif détecté: {vuln.vulnerability_id} (confiance: {fp_analysis.confidence:.2f})")
                
                # Petite pause pour éviter le rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.warning(f"Erreur détection faux positif pour {vuln.vulnerability_id}: {e}")
                continue
        
        return analyzed_vulns

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques"""
        return {**self.stats, "provider": self.ai_provider, "model": self.model}

    def is_healthy(self) -> bool:
        """Vérifie si l'analyseur est en bonne santé"""
        return self.is_ready


# === FONCTIONS DE HAUT NIVEAU (API UTILISÉE PAR LES TESTS) ===

async def quick_vulnerability_analysis(
    vulnerabilities: List[Dict[str, Any]],
    target_system: str = "quick-system",
    business_context: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fonction utilitaire de haut niveau utilisée par les tests.

    - Instancie un Analyzer
    - Lance une analyse sur la liste de vulnérabilités
    - Retourne le résultat au format dict sérialisable.
    """
    import inspect

    analyzer = Analyzer()
    maybe_coro = analyzer.analyze_vulnerabilities(
        vulnerabilities_data=vulnerabilities,
        target_system=target_system,
        business_context=business_context,
    )

    # Dans les tests, analyze_vulnerabilities peut être mocké en fonction synchrone
    if inspect.isawaitable(maybe_coro):
        result = await maybe_coro
    else:
        result = maybe_coro

    return result.to_dict() if hasattr(result, "to_dict") else result


def create_analyzer(provider: str = "anthropic", config: Optional[Dict[str, Any]] = None) -> Analyzer:
    """
    Factory simple pour créer un Analyzer avec le provider demandé.

    Les tests s'attendent à ce que:
    - l'instance soit créée
    - l'attribut current_provider reflète le provider demandé
    """
    # Accepter soit un dict de configuration, soit l'objet Config retourné par get_config()
    raw_config: Any = config or get_config()
    if isinstance(raw_config, dict):
        base_config: Dict[str, Any] = raw_config.copy()
    else:
        # Dataclass Config → dictionnaire
        base_config = raw_config.__dict__.copy()

    base_config["ai_provider"] = provider
    analyzer = Analyzer(base_config)
    analyzer.current_provider = provider
    return analyzer


#
# Ancienne API conservée pour compatibilité : Analyzer.analyze_vulnerabilities(...)
#