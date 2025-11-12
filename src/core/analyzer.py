"""
Module d'analyse IA de vulnérabilités - Version NIST avec OpenAI

Ce module analyse les vulnérabilités détectées par Nmap NSE en utilisant
OpenAI pour fournir des analyses approfondies et des recommandations de remédiation.

Workflow NIST:
1. NSE détecte les CVE
2. NIST enrichit avec scores officiels + liens solutions
3. OpenAI explique les solutions en français

Fonctionnalités:
- Analyse contextuelle des vulnérabilités avec OpenAI
- Calcul de scores de priorité et de confiance
- Génération de plans de remédiation détaillés
- Cache NIST pour optimisation
- Gestion d'erreurs robuste
"""

import asyncio
import json
import os
import time
import logging
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict

from openai import AsyncOpenAI, OpenAIError

from config import get_config
from src.utils.logger import setup_logger
from src.core import CoreException, CoreErrorCodes
from src.core.nist_enricher import NISTEnricher

# Configuration du logging
logger = setup_logger(__name__)


# ============================================================================
# EXCEPTIONS PERSONNALISÉES
# ============================================================================

class AnalyzerException(CoreException):
    """Exception levée par le module Analyzer"""

    def __init__(
            self,
            message: str,
            error_code: int = CoreErrorCodes.AI_SERVICE_ERROR,
            details: Optional[Dict] = None
    ):
        super().__init__(message, error_code, details)


# ============================================================================
# DATACLASSES POUR LES RÉSULTATS
# ============================================================================

@dataclass
class VulnerabilityAnalysis:
    """Analyse détaillée d'une vulnérabilité individuelle"""

    vulnerability_id: str
    name: str
    severity: str
    cvss_score: float
    impact_analysis: str
    exploitability: str
    priority_score: int
    affected_service: str
    recommended_actions: List[str]
    dependencies: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    # Données NIST (nouvelles)
    cvss_vector: Optional[str] = None
    nist_verified: bool = False
    nist_url: Optional[str] = None
    solution_links: List[Dict] = field(default_factory=list)

    # Explications IA (nouvelles)
    ai_explanation: Optional[Dict] = None
    correction_script: Optional[str] = None
    rollback_script: Optional[str] = None
    business_impact: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'analyse en dictionnaire"""
        return asdict(self)


@dataclass
class AnalysisResult:
    """Résultat complet de l'analyse"""

    analysis_id: str
    target_system: str
    analyzed_at: datetime
    analysis_summary: Dict[str, Any]
    vulnerabilities: List[VulnerabilityAnalysis]
    remediation_plan: Dict[str, Any]
    ai_model_used: str
    confidence_score: float
    processing_time: float
    business_context: Optional[Dict[str, Any]] = None

    # Métadonnées NIST (nouvelles)
    nist_enriched: bool = False
    nist_call_count: int = 0
    nist_cache_hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convertit le résultat en dictionnaire"""
        return {
            "analysis_id": self.analysis_id,
            "target_system": self.target_system,
            "analyzed_at": self.analyzed_at.isoformat(),
            "analysis_summary": self.analysis_summary,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "remediation_plan": self.remediation_plan,
            "ai_model_used": self.ai_model_used,
            "confidence_score": self.confidence_score,
            "processing_time": self.processing_time,
            "business_context": self.business_context,
            "nist_enriched": self.nist_enriched,
            "nist_call_count": self.nist_call_count,
            "nist_cache_hits": self.nist_cache_hits
        }


# ============================================================================
# CACHE NIST
# ============================================================================

class NISTCache:
    """Cache local pour les données NIST"""

    def __init__(self, cache_dir: str = "data/cache/nist"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_duration = timedelta(hours=24)
        logger.debug(f"Cache NIST initialisé: {self.cache_dir}")

    def get(self, cve_id: str) -> Optional[Dict]:
        """Récupère depuis le cache si valide"""
        cache_file = self.cache_dir / f"{cve_id}.json"

        if cache_file.exists():
            file_age = datetime.now() - datetime.fromtimestamp(
                cache_file.stat().st_mtime
            )

            if file_age < self.cache_duration:
                try:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                except Exception as e:
                    logger.warning(f"Erreur lecture cache {cve_id}: {e}")

        return None

    def set(self, cve_id: str, data: dict):
        """Sauvegarde dans le cache"""
        cache_file = self.cache_dir / f"{cve_id}.json"

        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Erreur écriture cache {cve_id}: {e}")

    def clear_old(self, max_age_days: int = 7):
        """Nettoie les caches anciens"""
        cutoff = datetime.now() - timedelta(days=max_age_days)
        cleaned = 0

        for cache_file in self.cache_dir.glob("*.json"):
            file_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if file_time < cutoff:
                cache_file.unlink()
                cleaned += 1

        if cleaned > 0:
            logger.info(f"Cache NIST nettoyé: {cleaned} fichiers supprimés")


# ============================================================================
# CLASSE PRINCIPALE ANALYZER
# ============================================================================
    def _filter_nist_references(self, references: List[dict]) -> Optional[str]:
        """
        Filtrer les références NIST pour garder UN SEUL lien solution
        
        Priorité : Patch > Vendor Advisory > Mitigation > Premier lien
        """
        if not references:
            return None
        
        # Tags prioritaires (dans l'ordre)
        priority_tags = ['Patch', 'Vendor Advisory', 'Mitigation', 'Third Party Advisory']
        
        # Chercher le premier lien avec un tag prioritaire
        for tag in priority_tags:
            for ref in references:
                ref_tags = ref.get('tags', [])
                if tag in ref_tags:
                    return ref.get('url', '')
        
        # Si aucun tag prioritaire, prendre le premier lien
        return references[0].get('url', '') if references else None
    
    def _enrich_vulnerability_with_nist(self, vulnerability: dict) -> dict:
        """
        Enrichir une vulnérabilité avec les données NIST (FILTRÉES)
        """
        cve_id = vulnerability.get('vulnerability_id', '')
        
        if not cve_id or not cve_id.startswith('CVE-'):
            return vulnerability
        
        try:
            # Récupérer les données NIST (depuis cache ou API)
            nist_data = self.nist_cache.get(cve_id)
            
            if not nist_data:
                # Appel API NIST (votre code existant)
                # nist_data = self._call_nist_api(cve_id)
                pass
            
            if nist_data:
                # ⚡ FILTRER pour garder UN SEUL lien
                references = nist_data.get('references', [])
                solution_url = self._filter_nist_references(references)
                
                # Enrichir avec données essentielles SEULEMENT
                vulnerability['nist_data'] = {
                    'cvss_score': nist_data.get('cvss_score'),
                    'severity': nist_data.get('severity'),
                    'description': nist_data.get('description', '')[:500],  # Limiter
                    'solution_url': solution_url,  # UN SEUL LIEN
                    'published_date': nist_data.get('published_date'),
                    'last_modified': nist_data.get('last_modified')
                }
                
                # NE PAS inclure toutes les références
                # vulnerability['references'] = references  # ← SUPPRIMÉ
        
        except Exception as e:
            self.logger.warning(f"Erreur enrichissement NIST {cve_id}: {e}")
        
        return vulnerability


class Analyzer:
    """
    Analyseur IA de vulnérabilités avec intégration NIST et OpenAI

    Workflow:
    1. Reçoit les CVE détectées par NSE
    2. Enrichit avec NIST (scores officiels + liens solutions)
    3. Fait expliquer les solutions par OpenAI en français
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialise l'analyseur

        Args:
            config: Configuration personnalisée (optionnelle)
        """
        self.config = config or get_config()
        self.is_ready = False

        # Statistiques
        self.stats = {
            "total_analyses": 0,
            "successful_analyses": 0,
            "failed_analyses": 0,
            "average_processing_time": 0.0,
            "nist_api_calls": 0,
            "nist_cache_hits": 0
        }

        # Initialiser les clients IA
        self._init_llm_clients()

        # Initialiser le cache NIST
        self.nist_cache = NISTCache()
        self.nist_api_key = self.config.get('nist_api_key')

        # Nettoyer le vieux cache au démarrage
        self.nist_cache.clear_old()

        self.is_ready = True
        logger.info("✅ Analyzer initialisé (NIST + OpenAI)")

    def _init_llm_clients(self):
        """Initialise le client OpenAI"""
        # Configuration OpenAI uniquement
        api_key = self.config.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise AnalyzerException(
                "Clé API OpenAI manquante",
                CoreErrorCodes.INVALID_CONFIGURATION
            )

        self.client = AsyncOpenAI(api_key=api_key)
        self.model = self.config.get('openai_model', 'gpt-4')
        logger.info(f"Client OpenAI initialisé (modèle: {self.model})")

    # ========================================================================
    # MÉTHODE BATCH - NOUVELLE
    # ========================================================================

    async def analyze_vulnerabilities_batch(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System",
            business_context: Optional[Dict[str, Any]] = None,
            batch_size: int = 10
    ) -> AnalysisResult:
        """
        Analyse les vulnérabilités par batch pour éviter les limites OpenAI

        Cette fonction divise les vulnérabilités en petits groupes et les analyse
        séparément, puis fusionne tous les résultats.

        Args:
            vulnerabilities_data: Liste des CVE détectées (peut être très grande)
            target_system: Nom du système cible
            business_context: Contexte business optionnel
            batch_size: Nombre de vulnérabilités par batch (défaut: 10)

        Returns:
            AnalysisResult: Résultat complet fusionné de tous les batches
        """
        start_time = time.time()
        analysis_id = f"analysis_batch_{int(time.time())}"

        if not self.is_ready:
            raise AnalyzerException(
                "Analyzer non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        if not vulnerabilities_data:
            raise AnalyzerException(
                "Liste de vulnérabilités vide",
                CoreErrorCodes.INVALID_VULNERABILITY_DATA
            )

        total_vulns = len(vulnerabilities_data)
        logger.info(f"🔍 Analyse par batch: {total_vulns} vulnérabilités, batch_size={batch_size}")

        # Diviser en batches
        batches = [
            vulnerabilities_data[i:i + batch_size]
            for i in range(0, total_vulns, batch_size)
        ]

        logger.info(f"📦 {len(batches)} batches à traiter")

        # Listes pour fusionner les résultats
        all_vulnerabilities = []
        total_nist_calls = 0
        total_nist_cache_hits = 0

        # Traiter chaque batch
        for i, batch in enumerate(batches, 1):
            logger.info(f"🔄 Traitement batch {i}/{len(batches)} ({len(batch)} vulnérabilités)")

            try:
                # Analyser ce batch avec la fonction normale
                batch_result = await self.analyze_vulnerabilities(
                    vulnerabilities_data=batch,
                    target_system=f"{target_system} (batch {i}/{len(batches)})",
                    business_context=business_context
                )

                # Collecter les résultats
                all_vulnerabilities.extend(batch_result.vulnerabilities)
                total_nist_calls += batch_result.nist_call_count
                total_nist_cache_hits += batch_result.nist_cache_hits

                logger.info(f"✅ Batch {i}/{len(batches)} terminé ({len(batch_result.vulnerabilities)} vulns)")

                # Pause entre les batches pour éviter rate limit (2 secondes)
                if i < len(batches):
                    logger.debug(f"⏸️  Pause 2s avant batch suivant...")
                    await asyncio.sleep(2)

            except Exception as e:
                logger.error(f"❌ Erreur batch {i}/{len(batches)}: {e}")
                # Continuer avec les autres batches au lieu de tout arrêter
                continue

        # Générer le plan de remédiation global
        logger.info("📋 Génération plan de remédiation global...")
        remediation_plan = await self._generate_remediation_plan(
            all_vulnerabilities,
            business_context
        )

        # Calculer les métriques globales
        analysis_summary = self._generate_analysis_summary(all_vulnerabilities)
        confidence_score = self._calculate_confidence_score(all_vulnerabilities)

        processing_time = time.time() - start_time

        # Créer le résultat final fusionné
        result = AnalysisResult(
            analysis_id=analysis_id,
            target_system=target_system,
            analyzed_at=datetime.utcnow(),
            analysis_summary=analysis_summary,
            vulnerabilities=all_vulnerabilities,
            remediation_plan=remediation_plan,
            ai_model_used=self._get_model_name(),
            confidence_score=confidence_score,
            processing_time=processing_time,
            business_context=business_context,
            nist_enriched=True,  # Toujours true si on a traité des batches
            nist_call_count=total_nist_calls,
            nist_cache_hits=total_nist_cache_hits
        )

        # Mettre à jour les stats
        self._update_stats(success=True, processing_time=processing_time)

        logger.info(f"✅ Analyse batch complète terminée en {processing_time:.2f}s")
        logger.info(f"   • Total vulnérabilités: {len(all_vulnerabilities)}")
        logger.info(f"   • Batches traités: {len(batches)}")
        logger.info(f"   • NIST calls: {total_nist_calls}")
        logger.info(f"   • Cache hits: {total_nist_cache_hits}")

        return result

    # ========================================================================
    # MÉTHODE PRINCIPALE D'ANALYSE - ORIGINALE
    # ========================================================================

    async def analyze_vulnerabilities(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System",
            business_context: Optional[Dict[str, Any]] = None
    ) -> AnalysisResult:
        """
        Analyse complète des vulnérabilités avec workflow NIST

        Args:
            vulnerabilities_data: Liste des CVE détectées par NSE
            target_system: Nom du système cible
            business_context: Contexte business optionnel

        Returns:
            AnalysisResult: Résultat complet de l'analyse
        """
        start_time = time.time()
        analysis_id = f"analysis_{int(time.time())}"

        if not self.is_ready:
            raise AnalyzerException(
                "Analyzer non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        if not vulnerabilities_data:
            raise AnalyzerException(
                "Liste de vulnérabilités vide",
                CoreErrorCodes.INVALID_VULNERABILITY_DATA
            )

        logger.info(f"🔍 Démarrage analyse: {len(vulnerabilities_data)} vulnérabilités")

        try:
            # ÉTAPE 1 : Enrichir avec NIST
            logger.info("📊 Enrichissement NIST...")
            nist_enricher = NISTEnricher(api_key=self.nist_api_key)

            for vuln in vulnerabilities_data:
                if "cve_id" in vuln:
                    nist_data = await nist_enricher.enrich_cve(vuln["cve_id"])

                    if nist_data:
                        vuln["cvss_score"] = nist_data["cvss_score"]
                        vuln["severity"] = nist_data["severity"]
                        vuln["nist_description"] = nist_data["description"]
                        vuln["solution_links"] = nist_data["solution_links"]
                        vuln["references"] = nist_data["references"]
                        vuln["is_nist_enriched"] = True

                        # Incrémenter les stats
                        if vuln["cve_id"] in nist_enricher.cache:
                            self.stats["nist_cache_hits"] += 1
                        else:
                            self.stats["nist_api_calls"] += 1
                    else:
                        vuln["is_nist_enriched"] = False

            # ÉTAPE 2 : Analyser avec IA
            logger.info("🤖 Analyse IA...")
            analyzed_vulns = await self._analyze_with_ai(vulnerabilities_data, business_context)

            # ÉTAPE 3 : Générer le plan de remédiation
            logger.info("📋 Génération plan de remédiation...")
            remediation_plan = await self._generate_remediation_plan(
                analyzed_vulns,
                business_context
            )

            # ÉTAPE 4 : Calculer les métriques
            analysis_summary = self._generate_analysis_summary(analyzed_vulns)
            confidence_score = self._calculate_confidence_score(analyzed_vulns)

            processing_time = time.time() - start_time

            # Créer le résultat final
            result = AnalysisResult(
                analysis_id=analysis_id,
                target_system=target_system,
                analyzed_at=datetime.utcnow(),
                analysis_summary=analysis_summary,
                vulnerabilities=analyzed_vulns,
                remediation_plan=remediation_plan,
                ai_model_used=self._get_model_name(),
                confidence_score=confidence_score,
                processing_time=processing_time,
                business_context=business_context,
                nist_enriched=any(v.get("is_nist_enriched", False) for v in vulnerabilities_data),
                nist_call_count=self.stats["nist_api_calls"],
                nist_cache_hits=self.stats["nist_cache_hits"]
            )

            # Mettre à jour les stats
            self._update_stats(success=True, processing_time=processing_time)

            logger.info(f"✅ Analyse terminée en {processing_time:.2f}s")

            return result

        except Exception as e:
            processing_time = time.time() - start_time
            self._update_stats(success=False, processing_time=processing_time)

            logger.error(f"❌ Erreur analyse: {e}")
            raise AnalyzerException(
                f"Erreur lors de l'analyse: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR,
                {"original_error": str(e)}
            )

    # ========================================================================
    # PARTIE IA : Analyse avec OpenAI
    # ========================================================================

    async def _analyze_with_ai(
            self,
            vulnerabilities: List[Dict],
            business_context: Optional[Dict]
    ) -> List[VulnerabilityAnalysis]:
        """Analyse les vulnérabilités avec OpenAI"""

        # Préparer le prompt
        prompt = self._build_analysis_prompt(vulnerabilities, business_context)

        # Appeler OpenAI
        response = await self._call_openai(prompt)

        # Parser la réponse
        return self._parse_ai_response(response, vulnerabilities)

    async def _call_openai(self, prompt: str) -> str:
        """Appelle OpenAI"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=4000
            )

            return response.choices[0].message.content

        except OpenAIError as e:
            raise AnalyzerException(
                f"Erreur OpenAI: {str(e)}",
                CoreErrorCodes.AI_SERVICE_ERROR
            )

    def _get_system_prompt(self) -> str:
        """Prompt système pour l'IA"""
        return """Tu es un expert en cybersécurité spécialisé dans l'analyse de vulnérabilités.

🎯 TON RÔLE :
Tu reçois des CVE avec leurs scores CVSS et gravités déjà calculés par NIST.
Tu dois analyser l'impact et donner des recommandations.

❌ RÈGLES IMPORTANTES :
- Si tu ne connais pas une valeur, utilise 0 pour les nombres, "UNKNOWN" pour les textes
- NE JAMAIS mettre "None" ou null dans les valeurs numériques
- Tous les scores doivent être des nombres (0.0 à 10.0)
- Toutes les gravités doivent être: CRITICAL, HIGH, MEDIUM, LOW, ou UNKNOWN

📋 FORMAT DE RÉPONSE (JSON strict) :
```json
{
  "vulnerabilities": [
    {
      "vulnerability_id": "CVE-XXXX-XXXX",
      "name": "Nom de la vulnérabilité",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "impact_analysis": "Description de l'impact",
      "exploitability": "HIGH",
      "priority_score": 10,
      "affected_service": "Service concerné",
      "recommended_actions": ["Action 1", "Action 2"],
      "dependencies": [],
      "references": []
    }
  ]
}
```

IMPORTANT : Réponds UNIQUEMENT avec ce JSON, sans texte avant ou après."""

    def _build_analysis_prompt(
            self,
            vulnerabilities: List[Dict],
            business_context: Optional[Dict]
    ) -> str:
        """Construit le prompt d'analyse"""

        prompt = "Analyse ces vulnérabilités détectées:\n\n"

        for i, vuln in enumerate(vulnerabilities, 1):
            cve_id = vuln.get('cve_id', 'N/A')
            service = vuln.get('service', 'inconnu')
            version = vuln.get('service_version', 'inconnue')
            port = vuln.get('port', 'inconnu')
            cvss = vuln.get('cvss_score', 'N/A')
            severity = vuln.get('severity', 'UNKNOWN')
            nist_verified = vuln.get('is_nist_enriched', False)
            solution_links = vuln.get('solution_links', [])

            prompt += f"""
═══════════════════════════════════════════════════════════
Vulnérabilité #{i}
═══════════════════════════════════════════════════════════
CVE : {cve_id}
Service : {service} (version {version})
Port : {port}
Score CVSS : {cvss} {'✅ (NIST officiel)' if nist_verified else '⚠️ (non vérifié)'}
Gravité : {severity} {'✅ (NIST officielle)' if nist_verified else '⚠️ (non vérifiée)'}
"""

            if vuln.get('nist_description'):
                prompt += f"\nDescription NIST :\n{vuln['nist_description'][:300]}...\n"

            if solution_links:
                prompt += "\nLiens de solutions NIST :\n"
                for link in solution_links:
                    prompt += f"- {link}\n"

            prompt += "\n"

        if business_context:
            prompt += f"\n📊 Contexte business :\n{json.dumps(business_context, indent=2)}\n"

        prompt += """
═══════════════════════════════════════════════════════════
TÂCHES :
═══════════════════════════════════════════════════════════
Analyse chaque vulnérabilité et réponds en JSON avec le format spécifié.
NE MODIFIE PAS les scores CVSS et gravités fournis par NIST.
"""

        return prompt

    def _parse_ai_response(
            self,
            response: str,
            original_vulns: List[Dict]
    ) -> List[VulnerabilityAnalysis]:
        """Parse la réponse de l'IA"""
        try:
            # Nettoyer la réponse (enlever markdown, etc.)
            cleaned = response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            # Parser le JSON
            data = json.loads(cleaned)

            # Extraire les vulnérabilités
            vulnerabilities = data.get('vulnerabilities', [])

            if not vulnerabilities:
                raise ValueError("Aucune vulnérabilité dans la réponse IA")

            # Créer les objets VulnerabilityAnalysis
            analyses = []

            for i, vuln_data in enumerate(vulnerabilities):
                # Récupérer les données NIST originales
                original = original_vulns[i] if i < len(original_vulns) else {}

                # Créer l'analyse avec gestion robuste des None
                analysis = VulnerabilityAnalysis(
                    vulnerability_id=vuln_data.get('vulnerability_id') or original.get('cve_id') or f'VULN-{i}',
                    name=vuln_data.get('name') or original.get('name') or 'Unknown',
                    severity=vuln_data.get('severity') or original.get('severity') or 'UNKNOWN',
                    cvss_score=float(vuln_data.get('cvss_score') or original.get('cvss_score') or 0.0),
                    impact_analysis=vuln_data.get('impact_analysis') or 'N/A',
                    exploitability=vuln_data.get('exploitability') or 'UNKNOWN',
                    priority_score=int(vuln_data.get('priority_score') or 5),
                    affected_service=vuln_data.get('affected_service') or original.get('service') or 'Unknown',
                    recommended_actions=vuln_data.get('recommended_actions') or [],
                    dependencies=vuln_data.get('dependencies') or [],
                    references=vuln_data.get('references') or original.get('references') or [],

                    # Données NIST
                    nist_verified=original.get('is_nist_enriched', False),
                    nist_url=f"https://nvd.nist.gov/vuln/detail/{original.get('cve_id', '')}" if original.get(
                        'cve_id') else None,
                    solution_links=original.get('solution_links', []),

                    # Explications IA
                    ai_explanation=vuln_data.get('ai_explanation'),
                    correction_script=vuln_data.get('correction_script'),
                    rollback_script=vuln_data.get('rollback_script'),
                    business_impact=vuln_data.get('business_impact')
                )

                analyses.append(analysis)

            return analyses

        except json.JSONDecodeError as e:
            logger.error(f"Erreur parsing JSON IA: {e}")
            logger.debug(f"Réponse brute: {response[:500]}")

            # Fallback: créer des analyses basiques
            return self._create_fallback_analyses(original_vulns)

        except Exception as e:
            logger.error(f"Erreur parsing réponse IA: {e}")
            return self._create_fallback_analyses(original_vulns)

    def _create_fallback_analyses(
            self,
            vulnerabilities: List[Dict]
    ) -> List[VulnerabilityAnalysis]:
        """Crée des analyses basiques si l'IA échoue"""
        analyses = []

        for vuln in vulnerabilities:
            analysis = VulnerabilityAnalysis(
                vulnerability_id=vuln.get('cve_id', 'UNKNOWN'),
                name=vuln.get('name', 'Unknown Vulnerability'),
                severity=vuln.get('severity', 'UNKNOWN'),
                cvss_score=float(vuln.get('cvss_score') or 0.0),
                impact_analysis="Analyse IA indisponible. Consulter NIST.",
                exploitability="UNKNOWN",
                priority_score=self._calculate_basic_priority(vuln),
                affected_service=vuln.get('service', 'Unknown'),
                recommended_actions=["Consulter la documentation NIST", "Appliquer les patches disponibles"],

                # Données NIST
                nist_verified=vuln.get('is_nist_enriched', False),
                nist_url=f"https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id', '')}" if vuln.get('cve_id') else None,
                solution_links=vuln.get('solution_links', []),
                references=vuln.get('references', [])
            )

            analyses.append(analysis)

        return analyses

    def _calculate_basic_priority(self, vuln: Dict) -> int:
        """Calcule une priorité basique basée sur CVSS"""
        cvss = float(vuln.get('cvss_score') or 0.0)

        if cvss >= 9.0:
            return 10
        elif cvss >= 7.0:
            return 8
        elif cvss >= 4.0:
            return 5
        else:
            return 3

    # ========================================================================
    # GÉNÉRATION DU PLAN DE REMÉDIATION
    # ========================================================================

    async def _generate_remediation_plan(
            self,
            vulnerabilities: List[VulnerabilityAnalysis],
            business_context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Génère un plan de remédiation détaillé"""

        # Trier par priorité
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: (v.priority_score, v.cvss_score),
            reverse=True
        )

        # Actions immédiates (priorité >= 8)
        immediate = [
            {
                "vulnerability_id": v.vulnerability_id,
                "action": v.recommended_actions[0] if v.recommended_actions else "Analyser",
                "priority": v.priority_score,
                "estimated_time": self._estimate_time(v)
            }
            for v in sorted_vulns if v.priority_score >= 8
        ]

        # Actions court terme (5 <= priorité < 8)
        short_term = [
            {
                "vulnerability_id": v.vulnerability_id,
                "action": v.recommended_actions[0] if v.recommended_actions else "Planifier",
                "priority": v.priority_score
            }
            for v in sorted_vulns if 5 <= v.priority_score < 8
        ]

        # Actions long terme (priorité < 5)
        long_term = [
            {
                "vulnerability_id": v.vulnerability_id,
                "action": "Surveiller et planifier",
                "priority": v.priority_score
            }
            for v in sorted_vulns if v.priority_score < 5
        ]

        # Estimation de durée totale
        total_time = sum(self._estimate_time(v) for v in sorted_vulns)

        return {
            "immediate_actions": immediate,
            "short_term_actions": short_term,
            "long_term_actions": long_term,
            "estimated_total_time_hours": total_time,
            "critical_count": len([v for v in vulnerabilities if v.severity == "CRITICAL"]),
            "high_count": len([v for v in vulnerabilities if v.severity == "HIGH"]),
            "priority_order": [v.vulnerability_id for v in sorted_vulns]
        }

    def _estimate_time(self, vuln: VulnerabilityAnalysis) -> float:
        """Estime le temps de remédiation (en heures)"""
        base_time = {
            "CRITICAL": 4.0,
            "HIGH": 2.0,
            "MEDIUM": 1.0,
            "LOW": 0.5
        }

        return base_time.get(vuln.severity, 1.0)

    # ========================================================================
    # MÉTRIQUES ET STATISTIQUES
    # ========================================================================

    def _generate_analysis_summary(
            self,
            vulnerabilities: List[VulnerabilityAnalysis]
    ) -> Dict[str, Any]:
        """Génère un résumé de l'analyse"""

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }

        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

        # Score de risque global (moyenne pondérée)
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "UNKNOWN": 0}
        total_weight = sum(weights.get(v.severity, 0) for v in vulnerabilities)
        max_weight = len(vulnerabilities) * 10
        overall_risk = (total_weight / max_weight * 10) if max_weight > 0 else 0

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "medium_count": severity_counts["MEDIUM"],
            "low_count": severity_counts["LOW"],
            "unknown_count": severity_counts["UNKNOWN"],
            "overall_risk_score": round(overall_risk, 2),
            "average_cvss": round(
                sum(v.cvss_score for v in vulnerabilities) / len(vulnerabilities), 2
            ) if vulnerabilities else 0.0,
            "highest_priority": max((v.priority_score for v in vulnerabilities), default=0),
            "nist_verified_count": sum(1 for v in vulnerabilities if v.nist_verified)
        }

    def _calculate_confidence_score(
            self,
            vulnerabilities: List[VulnerabilityAnalysis]
    ) -> float:
        """Calcule le score de confiance global"""
        if not vulnerabilities:
            return 0.0

        factors = []

        # Facteur 1: Pourcentage vérifié par NIST
        nist_verified_pct = sum(1 for v in vulnerabilities if v.nist_verified) / len(vulnerabilities)
        factors.append(nist_verified_pct * 0.4)

        # Facteur 2: Présence de CVE IDs
        has_cve_pct = sum(
            1 for v in vulnerabilities
            if v.vulnerability_id.startswith('CVE-')
        ) / len(vulnerabilities)
        factors.append(has_cve_pct * 0.3)

        # Facteur 3: Scores CVSS disponibles
        has_cvss_pct = sum(1 for v in vulnerabilities if v.cvss_score > 0) / len(vulnerabilities)
        factors.append(has_cvss_pct * 0.2)

        # Facteur 4: Actions recommandées disponibles
        has_actions_pct = sum(
            1 for v in vulnerabilities if v.recommended_actions
        ) / len(vulnerabilities)
        factors.append(has_actions_pct * 0.1)

        return min(1.0, sum(factors))

    # ========================================================================
    # MÉTHODES UTILITAIRES
    # ========================================================================

    def _get_model_name(self) -> str:
        """Retourne le nom du modèle OpenAI utilisé"""
        return self.model

    def _update_stats(self, success: bool, processing_time: float):
        """Met à jour les statistiques de l'analyseur"""
        self.stats["total_analyses"] += 1

        if success:
            self.stats["successful_analyses"] += 1
        else:
            self.stats["failed_analyses"] += 1

        # Moyenne mobile du temps de traitement
        current_avg = self.stats["average_processing_time"]
        total = self.stats["total_analyses"]
        self.stats["average_processing_time"] = (
                                                        current_avg * (total - 1) + processing_time
                                                ) / total

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de l'analyseur"""
        return self.stats.copy()

    def is_healthy(self) -> bool:
        """Vérifie si l'analyseur est en bonne santé"""
        return self.is_ready

    async def close(self):
        """Ferme proprement l'analyseur"""
        logger.info("Fermeture de l'analyzer...")

        # Sauvegarder les stats
        stats_file = Path("data/cache/analyzer_stats.json")
        stats_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(stats_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
            logger.info("Stats sauvegardées")
        except Exception as e:
            logger.warning(f"Erreur sauvegarde stats: {e}")

        self.is_ready = False


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

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
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities,
            target_system
        )
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
    finally:
        await analyzer.close()


def create_analyzer() -> Analyzer:
    """
    Factory pour créer un analyseur

    Returns:
        Analyzer: Instance configurée avec OpenAI
    """
    return Analyzer()


# Alias pour compatibilité
VulnerabilityAnalyzer = Analyzer

# ============================================================================
# POINT D'ENTRÉE POUR TESTS
# ============================================================================

if __name__ == "__main__":
    import sys


    async def test_analyzer():
        """Test rapide de l'analyzer"""
        print("🧪 Test de l'Analyzer avec NIST\n")

        # Données de test
        test_vulns = [
            {
                "cve_id": "CVE-2024-3094",
                "service": "xz-utils",
                "service_version": "5.6.0",
                "port": 22,
                "host": "192.168.1.100"
            }
        ]

        # Créer l'analyzer
        analyzer = Analyzer()

        try:
            print("📊 Analyse en cours...")
            result = await analyzer.analyze_vulnerabilities(
                test_vulns,
                "Test System"
            )

            print("\n✅ Analyse terminée!")
            print(f"   • Vulnérabilités: {result.analysis_summary['total_vulnerabilities']}")
            print(f"   • NIST enrichies: {result.nist_enriched}")
            print(f"   • Score de risque: {result.analysis_summary['overall_risk_score']}/10")
            print(f"   • Temps: {result.processing_time:.2f}s")
            print(f"   • Confiance: {result.confidence_score:.2%}")
            print(f"   • Appels NIST: {result.nist_call_count}")
            print(f"   • Cache hits: {result.nist_cache_hits}")

            # Afficher la première vulnérabilité
            if result.vulnerabilities:
                vuln = result.vulnerabilities[0]
                print(f"\n📋 Détails {vuln.vulnerability_id}:")
                print(f"   • CVSS: {vuln.cvss_score}")
                print(f"   • Gravité: {vuln.severity}")
                print(f"   • NIST vérifié: {vuln.nist_verified}")
                print(f"   • Priorité: {vuln.priority_score}/10")
                print(f"   • Liens solutions: {len(vuln.solution_links)}")

        except Exception as e:
            print(f"\n❌ Erreur: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
        finally:
            await analyzer.close()


    # Lancer le test
    asyncio.run(test_analyzer())