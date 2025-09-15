"""
Module d'analyse IA pour l'Agent de Cybersécurité

Ce module utilise des modèles d'IA (OpenAI GPT, Ollama, etc.) pour analyser
les vulnérabilités détectées et fournir des recommandations de remédiation
intelligentes et priorisées.

Fonctionnalités :
- Analyse contextuelle des vulnérabilités
- Évaluation des risques et impacts business
- Priorisation automatique basée sur CVSS et contexte
- Génération de plans de remédiation
- Support multi-modèles IA (OpenAI, Ollama, Anthropic)
"""

import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

import openai
import requests
from openai import AsyncOpenAI

from config import get_config, get_llm_config
from config.prompts import (
    format_vulnerability_prompt,
    format_priority_assessment_prompt,
    format_executive_report_prompt
)
from src.utils.logger import setup_logger
from src.database.database import Database
from . import AnalyzerException, CoreErrorCodes, ERROR_MESSAGES

# Configuration du logging
logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class VulnerabilityAnalysis:
    """Analyse d'une vulnérabilité individuelle"""
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
    business_impact: Optional[str] = None
    remediation_effort: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire"""
        return asdict(self)


@dataclass
class AnalysisResult:
    """Résultat complet d'une analyse IA"""
    analysis_id: str
    target_system: str
    analyzed_at: datetime

    # Résumé de l'analyse
    analysis_summary: Dict[str, Any]

    # Vulnérabilités analysées
    vulnerabilities: List[VulnerabilityAnalysis]

    # Plan de remédiation
    remediation_plan: Dict[str, Any]

    # Métadonnées
    ai_model_used: str
    confidence_score: float
    processing_time: float

    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire"""
        result = asdict(self)
        result['vulnerabilities'] = [vuln.to_dict() for vuln in self.vulnerabilities]
        result['analyzed_at'] = self.analyzed_at.isoformat()
        return result


# === CLASSE PRINCIPALE ===

class Analyzer:
    """
    Analyseur IA de vulnérabilités

    Cette classe orchestre l'analyse des vulnérabilités en utilisant
    des modèles d'IA pour fournir des insights contextuels et des
    recommandations de remédiation priorisées.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialise l'analyseur IA

        Args:
            config: Configuration personnalisée (optionnel)
        """
        self.config = config or get_config()
        self.llm_config = get_llm_config("openai")  # Par défaut OpenAI

        # État de l'analyseur
        self.is_ready = False
        self.current_provider = None
        self.client = None

        # Base de données pour historique
        self.db = Database()

        # Statistiques
        self.stats = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_processing_time": 0.0
        }

        # Initialiser le client IA
        self._initialize_ai_client()

    def _initialize_ai_client(self):
        """Initialise le client IA selon la configuration"""
        try:
            provider = self.llm_config.get("provider", "openai")

            if provider == "openai":
                self._setup_openai_client()
            elif provider == "ollama":
                self._setup_ollama_client()
            elif provider == "anthropic":
                self._setup_anthropic_client()
            else:
                raise AnalyzerException(
                    f"Fournisseur IA non supporté: {provider}",
                    CoreErrorCodes.INVALID_CONFIGURATION
                )

            self.current_provider = provider
            self.is_ready = True
            logger.info(f"Client IA initialisé: {provider}")

        except Exception as e:
            logger.error(f"Erreur initialisation client IA: {e}")
            raise AnalyzerException(
                f"Impossible d'initialiser le client IA: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    def _setup_openai_client(self):
        """Configure le client OpenAI"""
        api_key = self.config.openai_api_key
        if not api_key:
            raise AnalyzerException(
                "Clé API OpenAI manquante",
                CoreErrorCodes.INVALID_CONFIGURATION
            )

        self.client = AsyncOpenAI(api_key=api_key)
        logger.debug("Client OpenAI configuré")

    def _setup_ollama_client(self):
        """Configure le client Ollama"""
        base_url = self.llm_config.get("base_url", "http://localhost:11434")

        # Vérifier que Ollama est accessible
        try:
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise AnalyzerException(
                f"Ollama non accessible à {base_url}: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

        self.client = {"base_url": base_url, "type": "ollama"}
        logger.debug(f"Client Ollama configuré: {base_url}")

    def _setup_anthropic_client(self):
        """Configure le client Anthropic"""
        # TODO: Implémenter le support Anthropic Claude
        raise AnalyzerException(
            "Support Anthropic pas encore implémenté",
            CoreErrorCodes.AI_SERVICE_ERROR
        )

    async def analyze_vulnerabilities(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System",
            business_context: Optional[Dict[str, Any]] = None
    ) -> AnalysisResult:
        """
        Analyse des vulnérabilités avec l'IA

        Args:
            vulnerabilities_data: Liste des vulnérabilités à analyser
            target_system: Système cible pour le contexte
            business_context: Contexte business optionnel

        Returns:
            AnalysisResult: Résultats d'analyse complets

        Raises:
            AnalyzerException: Si l'analyse échoue
        """
        if not self.is_ready:
            raise AnalyzerException(
                "Analyseur non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        if not vulnerabilities_data:
            raise AnalyzerException(
                "Aucune donnée de vulnérabilité fournie",
                CoreErrorCodes.INVALID_VULNERABILITY_DATA
            )

        start_time = time.time()
        analysis_id = f"analysis_{int(time.time())}"

        try:
            logger.info(f"Début analyse {analysis_id} - {len(vulnerabilities_data)} vulnérabilités")

            # Préparer les données pour l'IA
            formatted_data = self._format_vulnerabilities_for_ai(vulnerabilities_data)

            # Étape 1: Analyse détaillée des vulnérabilités
            analyzed_vulnerabilities = await self._analyze_individual_vulnerabilities(
                formatted_data, target_system
            )

            # Étape 2: Évaluation de priorité globale
            remediation_plan = await self._generate_remediation_plan(
                analyzed_vulnerabilities, business_context
            )

            # Étape 3: Génération du résumé exécutif
            analysis_summary = await self._generate_analysis_summary(
                analyzed_vulnerabilities, remediation_plan
            )

            # Calculer les métrics
            processing_time = time.time() - start_time
            confidence_score = self._calculate_confidence_score(analyzed_vulnerabilities)

            # Créer le résultat
            result = AnalysisResult(
                analysis_id=analysis_id,
                target_system=target_system,
                analyzed_at=datetime.utcnow(),
                analysis_summary=analysis_summary,
                vulnerabilities=analyzed_vulnerabilities,
                remediation_plan=remediation_plan,
                ai_model_used=self._get_model_name(),
                confidence_score=confidence_score,
                processing_time=processing_time
            )

            # Sauvegarder dans la base de données
            await self._save_analysis_result(result)

            # Mettre à jour les statistiques
            self._update_stats(True, processing_time)

            logger.info(f"Analyse terminée: {analysis_id} ({processing_time:.2f}s)")
            return result

        except Exception as e:
            self._update_stats(False, time.time() - start_time)
            logger.error(f"Erreur analyse {analysis_id}: {e}")

            if isinstance(e, AnalyzerException):
                raise
            else:
                raise AnalyzerException(
                    f"Erreur lors de l'analyse: {str(e)}",
                    CoreErrorCodes.ANALYSIS_FAILED
                )

    def _format_vulnerabilities_for_ai(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Formate les vulnérabilités pour l'IA"""
        formatted = []

        for vuln in vulnerabilities:
            vuln_text = f"""
Vulnérabilité: {vuln.get('name', 'Unknown')}
CVE: {vuln.get('cve_id', 'N/A')}
Gravité: {vuln.get('severity', 'Unknown')}
Score CVSS: {vuln.get('cvss_score', 'N/A')}
Service: {vuln.get('affected_service', 'Unknown')}
Ports: {', '.join(map(str, vuln.get('ports', [])))}
Description: {vuln.get('description', 'Pas de description')}
"""
            formatted.append(vuln_text.strip())

        return "\n\n---\n\n".join(formatted)

    async def _analyze_individual_vulnerabilities(
            self,
            vulnerabilities_data: str,
            target_system: str
    ) -> List[VulnerabilityAnalysis]:
        """Analyse détaillée de chaque vulnérabilité"""

        # Préparer le prompt
        prompt = format_vulnerability_prompt(
            os_info=target_system,
            services="Services détectés lors du scan",
            open_ports="Ports ouverts détectés",
            vulnerabilities_data=vulnerabilities_data
        )

        # Analyser avec l'IA
        ai_response = await self._call_ai_model(prompt)

        # Parser la réponse JSON
        try:
            analysis_data = json.loads(ai_response)
            return self._parse_vulnerability_analysis(analysis_data)
        except json.JSONDecodeError as e:
            logger.error(f"Erreur parsing réponse IA: {e}")
            raise AnalyzerException(
                "Réponse IA invalide",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    def _parse_vulnerability_analysis(self, analysis_data: Dict[str, Any]) -> List[VulnerabilityAnalysis]:
        """Parse les données d'analyse en objets VulnerabilityAnalysis"""
        vulnerabilities = []

        for vuln_data in analysis_data.get("vulnerabilities", []):
            vulnerability = VulnerabilityAnalysis(
                vulnerability_id=vuln_data.get("id", "unknown"),
                name=vuln_data.get("name", "Unknown"),
                severity=vuln_data.get("severity", "UNKNOWN"),
                cvss_score=float(vuln_data.get("cvss_score", 0.0)),
                impact_analysis=vuln_data.get("impact_analysis", ""),
                exploitability=vuln_data.get("exploitability", "UNKNOWN"),
                priority_score=int(vuln_data.get("priority_score", 5)),
                affected_service=vuln_data.get("affected_service", "Unknown"),
                recommended_actions=vuln_data.get("recommended_actions", []),
                dependencies=vuln_data.get("dependencies", []),
                references=vuln_data.get("references", [])
            )
            vulnerabilities.append(vulnerability)

        return vulnerabilities

    async def _generate_remediation_plan(
            self,
            vulnerabilities: List[VulnerabilityAnalysis],
            business_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Génère un plan de remédiation priorisé"""

        # Préparer les données des vulnérabilités
        vulns_summary = []
        for vuln in vulnerabilities:
            vulns_summary.append({
                "id": vuln.vulnerability_id,
                "name": vuln.name,
                "severity": vuln.severity,
                "priority_score": vuln.priority_score,
                "recommended_actions": vuln.recommended_actions
            })

        # Contexte business par défaut
        if not business_context:
            business_context = {
                "budget_constraints": "Budget limité",
                "maintenance_window": "Week-end uniquement",
                "critical_services": "Services web",
                "risk_tolerance": "Faible"
            }

        # Préparer le prompt de priorisation
        prompt = format_priority_assessment_prompt(
            vulnerabilities_list=json.dumps(vulns_summary, indent=2),
            **business_context
        )

        # Analyser avec l'IA
        ai_response = await self._call_ai_model(prompt)

        try:
            return json.loads(ai_response)
        except json.JSONDecodeError:
            logger.warning("Erreur parsing plan remédiation, utilisation du plan par défaut")
            return self._generate_default_remediation_plan(vulnerabilities)

    def _generate_default_remediation_plan(
            self,
            vulnerabilities: List[VulnerabilityAnalysis]
    ) -> Dict[str, Any]:
        """Génère un plan de remédiation par défaut"""

        # Trier par priorité
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.priority_score, reverse=True)

        immediate = [v.vulnerability_id for v in sorted_vulns if v.priority_score >= 8]
        short_term = [v.vulnerability_id for v in sorted_vulns if 5 <= v.priority_score < 8]
        long_term = [v.vulnerability_id for v in sorted_vulns if v.priority_score < 5]

        return {
            "executive_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "immediate_action_required": len(immediate),
                "estimated_total_effort": f"{len(vulnerabilities) * 2} heures",
                "business_risk_level": "MEDIUM"
            },
            "implementation_roadmap": {
                "phase_1_immediate": {
                    "vulnerabilities": immediate,
                    "duration": "24-48h",
                    "resources_needed": ["Administrateur système"]
                },
                "phase_2_short_term": {
                    "vulnerabilities": short_term,
                    "duration": "1-2 semaines",
                    "resources_needed": ["Équipe technique"]
                },
                "phase_3_long_term": {
                    "vulnerabilities": long_term,
                    "duration": "1+ mois",
                    "resources_needed": ["Planification stratégique"]
                }
            },
            "recommendations": [
                "Commencer par les vulnérabilités critiques",
                "Planifier les fenêtres de maintenance",
                "Tester les correctifs en environnement de développement"
            ]
        }

    async def _generate_analysis_summary(
            self,
            vulnerabilities: List[VulnerabilityAnalysis],
            remediation_plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Génère un résumé exécutif de l'analyse"""

        # Calculs de base
        total_vulns = len(vulnerabilities)
        severity_counts = {
            "critical": len([v for v in vulnerabilities if v.severity == "CRITICAL"]),
            "high": len([v for v in vulnerabilities if v.severity == "HIGH"]),
            "medium": len([v for v in vulnerabilities if v.severity == "MEDIUM"]),
            "low": len([v for v in vulnerabilities if v.severity == "LOW"])
        }

        # Score de risque global (moyenne pondérée)
        if vulnerabilities:
            risk_scores = [v.cvss_score for v in vulnerabilities if v.cvss_score > 0]
            overall_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        else:
            overall_risk = 0.0

        return {
            "total_vulnerabilities": total_vulns,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "overall_risk_score": round(overall_risk, 1),
            "immediate_actions_required": remediation_plan.get("executive_summary", {}).get("immediate_action_required",
                                                                                            0),
            "estimated_remediation_time": remediation_plan.get("executive_summary", {}).get("estimated_total_effort",
                                                                                            "Unknown"),
            "top_priority_vulnerabilities": [
                v.vulnerability_id for v in sorted(vulnerabilities, key=lambda x: x.priority_score, reverse=True)[:3]
            ]
        }

    async def _call_ai_model(self, prompt: str) -> str:
        """Appelle le modèle IA avec le prompt donné"""

        if self.current_provider == "openai":
            return await self._call_openai(prompt)
        elif self.current_provider == "ollama":
            return await self._call_ollama(prompt)
        else:
            raise AnalyzerException(
                f"Fournisseur non supporté: {self.current_provider}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    async def _call_openai(self, prompt: str) -> str:
        """Appelle l'API OpenAI"""
        try:
            response = await self.client.chat.completions.create(
                model=self.llm_config.get("model", "gpt-4"),
                messages=[
                    {
                        "role": "system",
                        "content": "Tu es un expert en cybersécurité spécialisé dans l'analyse de vulnérabilités. Réponds toujours en JSON valide."
                    },
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.llm_config.get("max_tokens", 2000),
                temperature=self.llm_config.get("temperature", 0.3),
                timeout=self.llm_config.get("timeout", 60)
            )

            return response.choices[0].message.content

        except openai.APITimeoutError:
            raise AnalyzerException(
                "Timeout de l'API OpenAI",
                CoreErrorCodes.ANALYSIS_TIMEOUT
            )
        except openai.RateLimitError:
            raise AnalyzerException(
                "Quota API OpenAI dépassé",
                CoreErrorCodes.AI_QUOTA_EXCEEDED
            )
        except Exception as e:
            logger.error(f"Erreur API OpenAI: {e}")
            raise AnalyzerException(
                f"Erreur API OpenAI: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    async def _call_ollama(self, prompt: str) -> str:
        """Appelle l'API Ollama"""
        try:
            base_url = self.client["base_url"]
            model = self.llm_config.get("model", "llama3")

            data = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.llm_config.get("temperature", 0.3),
                    "num_predict": self.llm_config.get("max_tokens", 2000)
                }
            }

            async with asyncio.timeout(self.llm_config.get("timeout", 60)):
                response = requests.post(
                    f"{base_url}/api/generate",
                    json=data,
                    timeout=30
                )
                response.raise_for_status()

                result = response.json()
                return result.get("response", "")

        except asyncio.TimeoutError:
            raise AnalyzerException(
                "Timeout de l'API Ollama",
                CoreErrorCodes.ANALYSIS_TIMEOUT
            )
        except Exception as e:
            logger.error(f"Erreur API Ollama: {e}")
            raise AnalyzerException(
                f"Erreur API Ollama: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    def _calculate_confidence_score(self, vulnerabilities: List[VulnerabilityAnalysis]) -> float:
        """Calcule un score de confiance pour l'analyse"""
        if not vulnerabilities:
            return 0.0

        # Facteurs de confiance
        factors = []

        # Présence de CVE IDs (plus fiable)
        cve_ratio = len([v for v in vulnerabilities if v.vulnerability_id.startswith("CVE")]) / len(vulnerabilities)
        factors.append(cve_ratio * 0.3)

        # Cohérence des scores de priorité
        priority_scores = [v.priority_score for v in vulnerabilities]
        priority_variance = 1.0 - (max(priority_scores) - min(priority_scores)) / 10.0 if priority_scores else 0.0
        factors.append(max(0.0, priority_variance) * 0.2)

        # Présence de recommandations
        reco_ratio = len([v for v in vulnerabilities if v.recommended_actions]) / len(vulnerabilities)
        factors.append(reco_ratio * 0.3)

        # Score de base
        factors.append(0.2)

        return min(1.0, sum(factors))

    def _get_model_name(self) -> str:
        """Retourne le nom du modèle IA utilisé"""
        if self.current_provider == "openai":
            return self.llm_config.get("model", "gpt-4")
        elif self.current_provider == "ollama":
            return f"ollama:{self.llm_config.get('model', 'llama3')}"
        else:
            return "unknown"

    async def _save_analysis_result(self, result: AnalysisResult):
        """Sauvegarde le résultat d'analyse dans la base de données"""
        try:
            # TODO: Implémenter la sauvegarde en base
            logger.debug(f"Sauvegarde analyse: {result.analysis_id}")
        except Exception as e:
            logger.warning(f"Erreur sauvegarde analyse: {e}")

    def _update_stats(self, success: bool, processing_time: float):
        """Met à jour les statistiques de l'analyseur"""
        self.stats["total_analyses"] += 1

        if success:
            self.stats["successful_analyses"] += 1
        else:
            self.stats["failed_analyses"] += 1

        # Moyenne mobile simple
        current_avg = self.stats["average_processing_time"]
        total = self.stats["total_analyses"]
        self.stats["average_processing_time"] = (current_avg * (total - 1) + processing_time) / total

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de l'analyseur"""
        return self.stats.copy()

    def is_healthy(self) -> bool:
        """Vérifie si l'analyseur est en bonne santé"""
        if not self.is_ready:
            return False

        # Vérifier la connectivité selon le provider
        try:
            if self.current_provider == "openai":
                # TODO: Ping OpenAI API
                return True
            elif self.current_provider == "ollama":
                base_url = self.client["base_url"]
                response = requests.get(f"{base_url}/api/tags", timeout=5)
                return response.status_code == 200

            return True

        except Exception:
            return False


# === FONCTIONS UTILITAIRES ===

async def quick_vulnerability_analysis(
        vulnerabilities: List[Dict[str, Any]],
        target_system: str = "Unknown System"
) -> Dict[str, Any]:
    """
    Analyse rapide de vulnérabilités (fonction utilitaire)

    Args:
        vulnerabilities: Liste des vulnérabilités
        target_system: Système cible

    Returns:
        Dict contenant l'analyse simplifiée
    """
    analyzer = Analyzer()

    try:
        result = await analyzer.analyze_vulnerabilities(vulnerabilities, target_system)
        return result.to_dict()
    except Exception as e:
        logger.error(f"Erreur analyse rapide: {e}")
        return {
            "error": str(e),
            "analysis_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "overall_risk_score": 0.0
            }
        }


def create_analyzer(provider: str = "openai") -> Analyzer:
    """
    Factory pour créer un analyseur avec un provider spécifique

    Args:
        provider: Fournisseur IA (openai, ollama, anthropic)

    Returns:
        Analyzer: Instance configurée
    """
    config = get_llm_config(provider)
    return Analyzer(config)