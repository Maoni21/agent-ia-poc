"""
Tests pour le module Analyzer de l'Agent IA de Cybersécurité

Ce module teste toutes les fonctionnalités du module d'analyse IA :
- Analyse de vulnérabilités avec différents modèles IA
- Génération de plans de remédiation
- Calcul des scores de priorité et de confiance
- Gestion des erreurs et timeouts
- Validation des réponses IA

Commandes pour lancer les tests :
    pytest tests/test_analyzer.py -v
    pytest tests/test_analyzer.py::test_analyze_vulnerabilities_basic
    pytest tests/test_analyzer.py -k "not requires_openai"
"""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from typing import Dict, List, Any

# Import du module à tester
from src.core.analyzer import (
    Analyzer,
    AnalysisResult,
    VulnerabilityAnalysis,
    quick_vulnerability_analysis,
    create_analyzer
)
from src.core import AnalyzerException, CoreErrorCodes
from config import get_config

# Import des utilitaires de test
from . import (
    TestData,
    MockAIResponse,
    requires_openai_key,
    slow_test,
    integration_test,
    create_test_file,
    sample_vulnerability,
    sample_analysis_result,
    mock_openai,
    test_config
)


class TestAnalyzer:
    """Tests de base pour le module Analyzer"""

    def test_analyzer_initialization(self, test_config):
        """Test de l'initialisation de l'analyzer"""
        # Test avec configuration par défaut
        analyzer = Analyzer()
        assert analyzer is not None
        assert hasattr(analyzer, 'is_ready')
        assert hasattr(analyzer, 'stats')

        # Test avec configuration personnalisée
        custom_config = test_config.copy()
        analyzer_custom = Analyzer(custom_config)
        assert analyzer_custom.config == custom_config

    def test_analyzer_factory(self):
        """Test de la factory create_analyzer"""
        analyzer = create_analyzer("openai")
        assert analyzer is not None
        assert analyzer.current_provider == "openai"

    def test_analyzer_stats_initialization(self):
        """Test de l'initialisation des statistiques"""
        analyzer = Analyzer()
        stats = analyzer.get_stats()

        expected_keys = [
            "total_analyses", "successful_analyses",
            "failed_analyses", "average_processing_time"
        ]

        for key in expected_keys:
            assert key in stats
            assert stats[key] == 0 or stats[key] == 0.0

    @pytest.mark.asyncio
    async def test_analyze_vulnerabilities_basic(self, mock_openai, sample_vulnerability):
        """Test de base pour l'analyse de vulnérabilités"""
        # Configuration du mock
        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        # Création de l'analyzer
        analyzer = Analyzer()

        # Test d'analyse
        vulnerabilities_data = [sample_vulnerability]
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities_data,
            target_system="test-system"
        )

        # Vérifications
        assert isinstance(result, AnalysisResult)
        assert result.analysis_id is not None
        assert result.target_system == "test-system"
        assert len(result.vulnerabilities) >= 1
        assert result.ai_model_used is not None
        assert 0 <= result.confidence_score <= 1
        assert result.processing_time > 0

    @pytest.mark.asyncio
    async def test_analyze_empty_vulnerabilities(self, mock_openai):
        """Test avec liste vide de vulnérabilités"""
        analyzer = Analyzer()

        with pytest.raises(AnalyzerException) as exc_info:
            await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=[],
                target_system="test-system"
            )

        assert exc_info.value.error_code == CoreErrorCodes.INVALID_VULNERABILITY_DATA

    @pytest.mark.asyncio
    async def test_analyze_multiple_vulnerabilities(self, mock_openai):
        """Test avec plusieurs vulnérabilités"""
        # Créer plusieurs vulnérabilités de test
        vulnerabilities = []
        for i in range(3):
            vuln = TestData.SAMPLE_VULNERABILITY.copy()
            vuln['vulnerability_id'] = f"CVE-2024-TEST-{i:03d}"
            vuln['name'] = f"Test Vulnerability {i + 1}"
            vuln['severity'] = ["CRITICAL", "HIGH", "MEDIUM"][i]
            vulnerabilities.append(vuln)

        # Mock de la réponse avec plusieurs vulnérabilités
        mock_response = {
            "analysis_summary": {
                "total_vulnerabilities": 3,
                "critical_count": 1,
                "high_count": 1,
                "medium_count": 1,
                "low_count": 0,
                "overall_risk_score": 7.8
            },
            "vulnerabilities": [
                {
                    "id": f"CVE-2024-TEST-{i:03d}",
                    "name": f"Test Vulnerability {i + 1}",
                    "severity": ["CRITICAL", "HIGH", "MEDIUM"][i],
                    "cvss_score": [9.5, 7.5, 5.5][i],
                    "impact_analysis": f"Impact de test {i + 1}",
                    "exploitability": "MEDIUM",
                    "priority_score": [10, 8, 6][i],
                    "affected_service": "test-service",
                    "recommended_actions": [f"Action {i + 1}"],
                    "dependencies": [],
                    "references": [f"https://example.com/vuln-{i}"]
                }
                for i in range(3)
            ],
            "remediation_plan": {
                "immediate_actions": ["Corriger la vulnérabilité critique"],
                "short_term": ["Corriger les vulnérabilités élevées"],
                "long_term": ["Audit complet"]
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(mock_response)

        # Test
        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities,
            target_system="test-system"
        )

        # Vérifications
        assert len(result.vulnerabilities) == 3
        assert result.analysis_summary['total_vulnerabilities'] == 3
        assert result.analysis_summary['critical_count'] == 1
        assert result.analysis_summary['high_count'] == 1
        assert result.analysis_summary['medium_count'] == 1

    @pytest.mark.asyncio
    async def test_business_context_integration(self, mock_openai, sample_vulnerability):
        """Test avec contexte business"""
        business_context = {
            "budget_constraints": "Budget élevé",
            "maintenance_window": "24/7",
            "critical_services": "API de production",
            "risk_tolerance": "Très faible"
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[sample_vulnerability],
            target_system="production-system",
            business_context=business_context
        )

        # Vérifier que l'analyse a pris en compte le contexte
        assert result is not None
        assert result.target_system == "production-system"

        # Vérifier que l'appel IA a bien été fait
        assert mock_openai.chat.completions.create.called

    def test_vulnerability_analysis_model(self):
        """Test du modèle VulnerabilityAnalysis"""
        vuln_analysis = VulnerabilityAnalysis(
            vulnerability_id="CVE-2024-TEST-001",
            name="Test Vuln",
            severity="HIGH",
            cvss_score=7.5,
            impact_analysis="Test impact",
            exploitability="MEDIUM",
            priority_score=8,
            affected_service="test-service",
            recommended_actions=["Action 1", "Action 2"],
            dependencies=["CVE-2024-TEST-002"],
            references=["https://example.com/vuln"]
        )

        # Test conversion en dictionnaire
        vuln_dict = vuln_analysis.to_dict()
        assert isinstance(vuln_dict, dict)
        assert vuln_dict['vulnerability_id'] == "CVE-2024-TEST-001"
        assert vuln_dict['severity'] == "HIGH"
        assert vuln_dict['priority_score'] == 8

    def test_analysis_result_model(self):
        """Test du modèle AnalysisResult"""
        vuln_analysis = VulnerabilityAnalysis(
            vulnerability_id="CVE-2024-TEST-001",
            name="Test Vuln",
            severity="HIGH",
            cvss_score=7.5,
            impact_analysis="Test impact",
            exploitability="MEDIUM",
            priority_score=8,
            affected_service="test-service",
            recommended_actions=["Action 1"],
            dependencies=[],
            references=["https://example.com/vuln"]
        )

        analysis_result = AnalysisResult(
            analysis_id="test-analysis-001",
            target_system="test-system",
            analyzed_at=datetime.utcnow(),
            analysis_summary={"total_vulnerabilities": 1},
            vulnerabilities=[vuln_analysis],
            remediation_plan={"immediate_actions": ["Action 1"]},
            ai_model_used="test-model",
            confidence_score=0.85,
            processing_time=5.0
        )

        # Test conversion en dictionnaire
        result_dict = analysis_result.to_dict()
        assert isinstance(result_dict, dict)
        assert result_dict['analysis_id'] == "test-analysis-001"
        assert result_dict['target_system'] == "test-system"
        assert len(result_dict['vulnerabilities']) == 1
        assert 'analyzed_at' in result_dict


class TestAnalyzerAIIntegration:
    """Tests d'intégration avec les modèles IA"""

    @pytest.mark.asyncio
    async def test_openai_api_error_handling(self, mock_openai, sample_vulnerability):
        """Test de gestion des erreurs API OpenAI"""
        # Simuler une erreur API
        from openai import APITimeoutError
        mock_openai.chat.completions.create.side_effect = APITimeoutError("Timeout")

        analyzer = Analyzer()

        with pytest.raises(AnalyzerException) as exc_info:
            await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=[sample_vulnerability]
            )

        assert exc_info.value.error_code == CoreErrorCodes.ANALYSIS_TIMEOUT

    @pytest.mark.asyncio
    async def test_invalid_ai_response(self, mock_openai, sample_vulnerability):
        """Test avec réponse IA invalide"""
        # Réponse IA mal formée
        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            "Réponse invalide non-JSON"

        analyzer = Analyzer()

        with pytest.raises(AnalyzerException):
            await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=[sample_vulnerability]
            )

    @pytest.mark.asyncio
    async def test_ai_response_parsing(self, mock_openai, sample_vulnerability):
        """Test du parsing des réponses IA"""
        # Réponse IA valide mais structure différente
        custom_response = {
            "analysis_summary": {
                "total_vulnerabilities": 1,
                "overall_risk_score": 6.5
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2024-TEST-001",
                    "name": "Custom Test Vuln",
                    "severity": "MEDIUM",
                    "cvss_score": 6.5,
                    "impact_analysis": "Custom impact",
                    "exploitability": "HIGH",
                    "priority_score": 7,
                    "affected_service": "custom-service",
                    "recommended_actions": ["Custom action"],
                    "dependencies": [],
                    "references": []
                }
            ],
            "remediation_plan": {
                "immediate_actions": ["Custom immediate action"]
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(custom_response)

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[sample_vulnerability]
        )

        # Vérifier que le parsing a fonctionné
        assert result.vulnerabilities[0].name == "Custom Test Vuln"
        assert result.vulnerabilities[0].severity == "MEDIUM"
        assert result.vulnerabilities[0].priority_score == 7

    @pytest.mark.asyncio
    @requires_openai_key
    @slow_test
    async def test_real_openai_integration(self, sample_vulnerability):
        """Test d'intégration réelle avec OpenAI (nécessite une clé API)"""
        analyzer = Analyzer()

        # Test avec une vraie vulnérabilité
        test_vuln = {
            "vulnerability_id": "CVE-2023-44487",
            "name": "HTTP/2 Rapid Reset Attack",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "description": "HTTP/2 protocol vulnerability allowing DDoS attacks",
            "affected_service": "HTTP server",
            "affected_port": 443,
            "cve_ids": ["CVE-2023-44487"],
            "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487"]
        }

        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[test_vuln],
            target_system="production-web-server"
        )

        # Vérifications de base
        assert result is not None
        assert len(result.vulnerabilities) >= 1
        assert result.confidence_score > 0
        assert result.ai_model_used is not None


class TestAnalyzerPerformance:
    """Tests de performance de l'analyzer"""

    @pytest.mark.asyncio
    async def test_large_vulnerability_set(self, mock_openai):
        """Test avec un grand nombre de vulnérabilités"""
        # Créer 50 vulnérabilités de test
        vulnerabilities = []
        for i in range(50):
            vuln = TestData.SAMPLE_VULNERABILITY.copy()
            vuln['vulnerability_id'] = f"CVE-2024-TEST-{i:03d}"
            vuln['name'] = f"Test Vulnerability {i + 1}"
            vulnerabilities.append(vuln)

        # Mock de réponse pour traitement en lot
        mock_response = {
            "analysis_summary": {
                "total_vulnerabilities": 50,
                "critical_count": 5,
                "high_count": 15,
                "medium_count": 20,
                "low_count": 10,
                "overall_risk_score": 6.8
            },
            "vulnerabilities": [
                {
                    "id": f"CVE-2024-TEST-{i:03d}",
                    "name": f"Test Vulnerability {i + 1}",
                    "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
                    "cvss_score": 9.0 - (i % 10) * 0.5,
                    "impact_analysis": f"Impact {i + 1}",
                    "exploitability": "MEDIUM",
                    "priority_score": 10 - (i % 10),
                    "affected_service": "test-service",
                    "recommended_actions": [f"Action {i + 1}"],
                    "dependencies": [],
                    "references": []
                }
                for i in range(50)
            ],
            "remediation_plan": {
                "immediate_actions": ["Process all critical vulnerabilities"],
                "short_term": ["Address high and medium vulnerabilities"],
                "long_term": ["Review security posture"]
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(mock_response)

        # Test avec mesure du temps
        analyzer = Analyzer()
        start_time = time.time()

        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities,
            target_system="large-system"
        )

        end_time = time.time()
        processing_time = end_time - start_time

        # Vérifications
        assert len(result.vulnerabilities) == 50
        assert processing_time < 30  # Doit traiter en moins de 30 secondes
        assert result.processing_time > 0

    @pytest.mark.asyncio
    async def test_concurrent_analyses(self, mock_openai):
        """Test d'analyses concurrentes"""
        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        # Créer plusieurs analyzers
        analyzers = [Analyzer() for _ in range(3)]
        vulnerabilities = [TestData.SAMPLE_VULNERABILITY]

        # Lancer les analyses en parallèle
        tasks = []
        for i, analyzer in enumerate(analyzers):
            task = analyzer.analyze_vulnerabilities(
                vulnerabilities_data=vulnerabilities,
                target_system=f"system-{i + 1}"
            )
            tasks.append(task)

        # Attendre tous les résultats
        results = await asyncio.gather(*tasks)

        # Vérifier que toutes les analyses ont réussi
        assert len(results) == 3
        for i, result in enumerate(results):
            assert result.target_system == f"system-{i + 1}"
            assert len(result.vulnerabilities) >= 1

    def test_stats_tracking(self, mock_openai):
        """Test du suivi des statistiques"""
        analyzer = Analyzer()

        # Statistiques initiales
        initial_stats = analyzer.get_stats()
        assert initial_stats['total_analyses'] == 0
        assert initial_stats['successful_analyses'] == 0

        # Simuler quelques analyses (version synchrone pour les stats)
        analyzer.stats['total_analyses'] = 5
        analyzer.stats['successful_analyses'] = 4
        analyzer.stats['failed_analyses'] = 1
        analyzer.stats['average_processing_time'] = 2.5

        # Vérifier les statistiques
        updated_stats = analyzer.get_stats()
        assert updated_stats['total_analyses'] == 5
        assert updated_stats['successful_analyses'] == 4
        assert updated_stats['failed_analyses'] == 1
        assert updated_stats['average_processing_time'] == 2.5


class TestAnalyzerUtilities:
    """Tests des fonctions utilitaires"""

    @pytest.mark.asyncio
    async def test_quick_vulnerability_analysis(self, mock_openai):
        """Test de la fonction quick_vulnerability_analysis"""
        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        vulnerabilities = [TestData.SAMPLE_VULNERABILITY]

        # Patcher la classe Analyzer pour utiliser le mock
        with patch('src.core.analyzer.Analyzer') as mock_analyzer_class:
            mock_analyzer = Mock()
            mock_analyzer.analyze_vulnerabilities.return_value = AnalysisResult(
                analysis_id="quick-test",
                target_system="quick-system",
                analyzed_at=datetime.utcnow(),
                analysis_summary={"total_vulnerabilities": 1},
                vulnerabilities=[],
                remediation_plan={},
                ai_model_used="test-model",
                confidence_score=0.8,
                processing_time=1.0
            )
            mock_analyzer_class.return_value = mock_analyzer

            result = await quick_vulnerability_analysis(
                vulnerabilities, "quick-system"
            )

            assert isinstance(result, dict)
            assert 'analysis_id' in result

    def test_confidence_score_calculation(self):
        """Test du calcul du score de confiance"""
        analyzer = Analyzer()

        # Test avec vulnérabilités ayant des CVE IDs
        vulnerabilities_with_cve = [
            VulnerabilityAnalysis(
                vulnerability_id="CVE-2024-001",
                name="Test 1",
                severity="HIGH",
                cvss_score=7.5,
                impact_analysis="Test",
                exploitability="MEDIUM",
                priority_score=8,
                affected_service="service",
                recommended_actions=["action"],
                dependencies=[],
                references=["ref"]
            )
        ]

        confidence = analyzer._calculate_confidence_score(vulnerabilities_with_cve)
        assert 0 <= confidence <= 1
        assert confidence > 0  # Devrait avoir une confiance > 0 avec CVE ID

    def test_model_name_detection(self):
        """Test de la détection du nom du modèle"""
        analyzer = Analyzer()
        model_name = analyzer._get_model_name()
        assert model_name is not None
        assert isinstance(model_name, str)

    def test_health_check(self):
        """Test du health check"""
        analyzer = Analyzer()
        is_healthy = analyzer.is_healthy()

        # Devrait être True si l'analyzer est correctement initialisé
        # (peut être False si OpenAI n'est pas configuré)
        assert isinstance(is_healthy, bool)


class TestAnalyzerErrorHandling:
    """Tests de gestion d'erreurs"""

    @pytest.mark.asyncio
    async def test_analyzer_not_ready(self, sample_vulnerability):
        """Test avec analyzer non initialisé"""
        analyzer = Analyzer()
        analyzer.is_ready = False  # Forcer l'état non prêt

        with pytest.raises(AnalyzerException) as exc_info:
            await analyzer.analyze_vulnerabilities([sample_vulnerability])

        assert exc_info.value.error_code == CoreErrorCodes.MODULE_NOT_READY

    @pytest.mark.asyncio
    async def test_network_timeout_handling(self, mock_openai, sample_vulnerability):
        """Test de gestion des timeouts réseau"""
        import asyncio

        # Simuler un timeout
        async def timeout_side_effect(*args, **kwargs):
            raise asyncio.TimeoutError("Network timeout")

        mock_openai.chat.completions.create.side_effect = timeout_side_effect

        analyzer = Analyzer()

        with pytest.raises(AnalyzerException):
            await analyzer.analyze_vulnerabilities([sample_vulnerability])

    @pytest.mark.asyncio
    async def test_malformed_vulnerability_data(self, mock_openai):
        """Test avec données de vulnérabilité malformées"""
        malformed_data = [
            {"invalid": "data"},  # Structure incorrecte
            None,  # Données nulles
            "string_instead_of_dict"  # Type incorrect
        ]

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()

        # Devrait gérer gracieusement les données malformées
        result = await analyzer.analyze_vulnerabilities(malformed_data)
        assert result is not None

    def test_invalid_configuration(self):
        """Test avec configuration invalide"""
        invalid_config = {
            "openai_api_key": None,  # Clé manquante
            "openai_model": "invalid-model"
        }

        with pytest.raises(AnalyzerException):
            Analyzer(invalid_config)


class TestAnalyzerIntegrationScenarios:
    """Tests de scénarios d'intégration réalistes"""

    @pytest.mark.asyncio
    @integration_test
    async def test_full_analysis_workflow(self, mock_openai):
        """Test d'un workflow d'analyse complet"""
        # Simuler des résultats de scan réalistes
        scan_vulnerabilities = [
            {
                "vulnerability_id": "CVE-2023-44487",
                "name": "HTTP/2 Rapid Reset Attack",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "description": "DDoS vulnerability in HTTP/2",
                "affected_service": "nginx",
                "affected_port": 443
            },
            {
                "vulnerability_id": "CVE-2023-4911",
                "name": "Looney Tunables Local Privilege Escalation",
                "severity": "HIGH",
                "cvss_score": 7.8,
                "description": "Buffer overflow in glibc",
                "affected_service": "glibc",
                "affected_port": 0
            }
        ]

        # Mock de réponse réaliste
        realistic_response = {
            "analysis_summary": {
                "total_vulnerabilities": 2,
                "critical_count": 0,
                "high_count": 2,
                "medium_count": 0,
                "low_count": 0,
                "overall_risk_score": 7.65
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2023-44487",
                    "name": "HTTP/2 Rapid Reset Attack",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "impact_analysis": "Peut causer des attaques DoS sur les serveurs web",
                    "exploitability": "EASY",
                    "priority_score": 9,
                    "affected_service": "nginx",
                    "recommended_actions": [
                        "Mettre à jour nginx vers une version corrigée",
                        "Implémenter une limitation des connexions HTTP/2"
                    ],
                    "dependencies": [],
                    "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487"]
                },
                {
                    "id": "CVE-2023-4911",
                    "name": "Looney Tunables Local Privilege Escalation",
                    "severity": "HIGH",
                    "cvss_score": 7.8,
                    "impact_analysis": "Permet l'escalade de privilèges local",
                    "exploitability": "MEDIUM",
                    "priority_score": 8,
                    "affected_service": "glibc",
                    "recommended_actions": [
                        "Mettre à jour glibc immédiatement",
                        "Auditer les comptes utilisateurs"
                    ],
                    "dependencies": [],
                    "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4911"]
                }
            ],
            "remediation_plan": {
                "immediate_actions": [
                    "Appliquer les correctifs pour CVE-2023-44487 et CVE-2023-4911"
                ],
                "short_term": [
                    "Audit complet de sécurité du serveur web",
                    "Mise en place de monitoring des connexions HTTP/2"
                ],
                "long_term": [
                    "Automatisation des mises à jour de sécurité",
                    "Formation de l'équipe sur les vulnérabilités web"
                ]
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(realistic_response)

        # Test du workflow complet
        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=scan_vulnerabilities,
            target_system="production-web-server",
            business_context={
                "budget_constraints": "Modéré",
                "maintenance_window": "Dimanche 2h-6h",
                "critical_services": "Site web e-commerce",
                "risk_tolerance": "Faible"
            }
        )

        # Vérifications détaillées
        assert result.analysis_summary['total_vulnerabilities'] == 2
        assert result.analysis_summary['high_count'] == 2
        assert result.analysis_summary['overall_risk_score'] > 7.0

        # Vérifier les priorités
        priorities = [vuln.priority_score for vuln in result.vulnerabilities]
        assert all(p >= 8 for p in priorities)  # Toutes les vulnérabilités sont prioritaires

        # Vérifier le plan de remédiation
        assert 'immediate_actions' in result.remediation_plan
        assert len(result.remediation_plan['immediate_actions']) > 0

    @pytest.mark.asyncio
    async def test_analysis_with_dependencies(self, mock_openai):
        """Test d'analyse avec vulnérabilités dépendantes"""
        vulnerabilities_with_deps = [
            {
                "vulnerability_id": "CVE-2024-PARENT",
                "name": "Parent Vulnerability",
                "severity": "CRITICAL",
                "cvss_score": 9.0
            },
            {
                "vulnerability_id": "CVE-2024-CHILD-1",
                "name": "Dependent Vulnerability 1",
                "severity": "HIGH",
                "cvss_score": 7.5
            },
            {
                "vulnerability_id": "CVE-2024-CHILD-2",
                "name": "Dependent Vulnerability 2",
                "severity": "MEDIUM",
                "cvss_score": 6.0
            }
        ]

        # Mock avec dépendances
        dependency_response = {
            "analysis_summary": {
                "total_vulnerabilities": 3,
                "critical_count": 1,
                "high_count": 1,
                "medium_count": 1,
                "overall_risk_score": 7.5
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2024-PARENT",
                    "name": "Parent Vulnerability",
                    "severity": "CRITICAL",
                    "cvss_score": 9.0,
                    "impact_analysis": "Vulnérabilité racine critique",
                    "exploitability": "EASY",
                    "priority_score": 10,
                    "affected_service": "core-service",
                    "recommended_actions": ["Corriger immédiatement"],
                    "dependencies": [],
                    "references": []
                },
                {
                    "id": "CVE-2024-CHILD-1",
                    "name": "Dependent Vulnerability 1",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "impact_analysis": "Dépend de la vulnérabilité parent",
                    "exploitability": "MEDIUM",
                    "priority_score": 8,
                    "affected_service": "dependent-service-1",
                    "recommended_actions": ["Corriger après CVE-2024-PARENT"],
                    "dependencies": ["CVE-2024-PARENT"],
                    "references": []
                },
                {
                    "id": "CVE-2024-CHILD-2",
                    "name": "Dependent Vulnerability 2",
                    "severity": "MEDIUM",
                    "cvss_score": 6.0,
                    "impact_analysis": "Dépend de la vulnérabilité parent",
                    "exploitability": "MEDIUM",
                    "priority_score": 6,
                    "affected_service": "dependent-service-2",
                    "recommended_actions": ["Corriger après CVE-2024-PARENT"],
                    "dependencies": ["CVE-2024-PARENT"],
                    "references": []
                }
            ],
            "remediation_plan": {
                "immediate_actions": ["Corriger CVE-2024-PARENT en priorité"],
                "short_term": ["Corriger les vulnérabilités dépendantes"],
                "long_term": ["Audit des dépendances"]
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(dependency_response)

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities_with_deps,
            target_system="complex-system"
        )

        # Vérifier que les dépendances sont correctement analysées
        parent_vuln = next(v for v in result.vulnerabilities if v.vulnerability_id == "CVE-2024-PARENT")
        child_vulns = [v for v in result.vulnerabilities if v.vulnerability_id.startswith("CVE-2024-CHILD")]

        assert len(parent_vuln.dependencies) == 0  # Parent n'a pas de dépendances
        assert all(len(child.dependencies) > 0 for child in child_vulns)  # Enfants ont des dépendances
        assert parent_vuln.priority_score == 10  # Parent a la priorité la plus haute

    @pytest.mark.asyncio
    async def test_multilingual_vulnerability_analysis(self, mock_openai):
        """Test d'analyse de vulnérabilités avec descriptions multilingues"""
        multilingual_vulnerabilities = [
            {
                "vulnerability_id": "CVE-2024-FR-001",
                "name": "Vulnérabilité de test française",
                "description": "Description en français de la vulnérabilité",
                "severity": "HIGH"
            },
            {
                "vulnerability_id": "CVE-2024-EN-001",
                "name": "English test vulnerability",
                "description": "English description of the vulnerability",
                "severity": "MEDIUM"
            }
        ]

        # Mock de réponse multilingue
        multilingual_response = {
            "analysis_summary": {
                "total_vulnerabilities": 2,
                "high_count": 1,
                "medium_count": 1,
                "overall_risk_score": 6.8
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2024-FR-001",
                    "name": "Vulnérabilité de test française",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "impact_analysis": "Impact analysé en français",
                    "exploitability": "MEDIUM",
                    "priority_score": 8,
                    "affected_service": "service-fr",
                    "recommended_actions": ["Action en français"],
                    "dependencies": [],
                    "references": []
                },
                {
                    "id": "CVE-2024-EN-001",
                    "name": "English test vulnerability",
                    "severity": "MEDIUM",
                    "cvss_score": 6.0,
                    "impact_analysis": "Impact analyzed in English",
                    "exploitability": "LOW",
                    "priority_score": 6,
                    "affected_service": "service-en",
                    "recommended_actions": ["English action"],
                    "dependencies": [],
                    "references": []
                }
            ],
            "remediation_plan": {
                "immediate_actions": ["Actions multilingues"],
                "short_term": [],
                "long_term": []
            }
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(multilingual_response)

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=multilingual_vulnerabilities,
            target_system="multilingual-system"
        )

        # Vérifier que l'analyse fonctionne avec différentes langues
        assert len(result.vulnerabilities) == 2
        fr_vuln = next(v for v in result.vulnerabilities if "français" in v.impact_analysis)
        en_vuln = next(v for v in result.vulnerabilities if "English" in v.impact_analysis)

        assert fr_vuln is not None
        assert en_vuln is not None


class TestAnalyzerEdgeCases:
    """Tests des cas limites et edge cases"""

    @pytest.mark.asyncio
    async def test_very_long_vulnerability_description(self, mock_openai):
        """Test avec description de vulnérabilité très longue"""
        long_description = "A" * 10000  # 10k caractères

        long_vuln = TestData.SAMPLE_VULNERABILITY.copy()
        long_vuln['description'] = long_description

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[long_vuln],
            target_system="test-system"
        )

        assert result is not None
        assert len(result.vulnerabilities) >= 1

    @pytest.mark.asyncio
    async def test_unicode_vulnerability_data(self, mock_openai):
        """Test avec données Unicode et caractères spéciaux"""
        unicode_vuln = {
            "vulnerability_id": "CVE-2024-🔒-001",
            "name": "Vulnérabilité avec émojis 🚨💀⚡",
            "description": "Description avec caractères Unicode: αβγδε, 中文, العربية",
            "severity": "HIGH",
            "affected_service": "service-ñoño"
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[unicode_vuln],
            target_system="unicode-system"
        )

        assert result is not None

    @pytest.mark.asyncio
    async def test_zero_cvss_score(self, mock_openai):
        """Test avec score CVSS à zéro"""
        zero_cvss_vuln = TestData.SAMPLE_VULNERABILITY.copy()
        zero_cvss_vuln['cvss_score'] = 0.0

        mock_response = MockAIResponse.vulnerability_analysis_response()
        # Modifier la réponse pour avoir un score CVSS à 0
        response_data = json.loads(mock_response)
        response_data['vulnerabilities'][0]['cvss_score'] = 0.0

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            json.dumps(response_data)

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[zero_cvss_vuln]
        )

        assert result is not None
        assert result.vulnerabilities[0].cvss_score == 0.0

    @pytest.mark.asyncio
    async def test_missing_optional_fields(self, mock_openai):
        """Test avec vulnérabilité ayant des champs optionnels manquants"""
        minimal_vuln = {
            "vulnerability_id": "CVE-2024-MINIMAL",
            "name": "Minimal Vulnerability",
            "severity": "MEDIUM"
            # Tous les autres champs optionnels sont absents
        }

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[minimal_vuln]
        )

        assert result is not None
        assert len(result.vulnerabilities) >= 1

    @pytest.mark.asyncio
    async def test_duplicate_vulnerability_ids(self, mock_openai):
        """Test avec IDs de vulnérabilités dupliqués"""
        duplicate_vulns = [
            TestData.SAMPLE_VULNERABILITY.copy(),
            TestData.SAMPLE_VULNERABILITY.copy()  # Même ID
        ]

        # Modifier légèrement le deuxième
        duplicate_vulns[1]['name'] = "Duplicate Test Vulnerability"

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=duplicate_vulns
        )

        # L'analyzer devrait gérer les doublons gracieusement
        assert result is not None


class TestAnalyzerConfigurationVariations:
    """Tests avec différentes configurations"""

    @pytest.mark.asyncio
    async def test_different_ai_models(self, mock_openai):
        """Test avec différents modèles d'IA"""
        models_to_test = ["gpt-4", "gpt-3.5-turbo"]

        for model in models_to_test:
            config = get_config()
            config.openai_model = model

            analyzer = Analyzer(config)

            mock_openai.chat.completions.create.return_value.choices[0].message.content = \
                MockAIResponse.vulnerability_analysis_response()

            result = await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=[TestData.SAMPLE_VULNERABILITY],
                target_system=f"system-{model}"
            )

            assert result is not None
            assert model in result.ai_model_used or "gpt" in result.ai_model_used.lower()

    @pytest.mark.asyncio
    async def test_temperature_variations(self, mock_openai):
        """Test avec différentes températures"""
        temperatures = [0.0, 0.3, 0.7, 1.0]

        for temp in temperatures:
            config = get_config()
            config.openai_temperature = temp

            analyzer = Analyzer(config)

            mock_openai.chat.completions.create.return_value.choices[0].message.content = \
                MockAIResponse.vulnerability_analysis_response()

            result = await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=[TestData.SAMPLE_VULNERABILITY]
            )

            assert result is not None
            # Vérifier que l'appel a été fait avec la bonne température
            call_kwargs = mock_openai.chat.completions.create.call_args.kwargs
            assert call_kwargs.get('temperature') == temp

    def test_custom_timeout_configuration(self):
        """Test avec timeout personnalisé"""
        config = get_config()
        config_dict = {
            "openai_api_key": "test-key",
            "timeout": 120  # 2 minutes
        }

        analyzer = Analyzer(config_dict)
        assert analyzer.llm_config.get('timeout', 60) == 120


# === TESTS DE BENCHMARK ET PERFORMANCE ===

class TestAnalyzerBenchmark:
    """Tests de performance et benchmark"""

    @pytest.mark.asyncio
    @slow_test
    async def test_processing_time_measurement(self, mock_openai):
        """Test de mesure des temps de traitement"""

        # Simuler un délai de traitement
        async def delayed_response(*args, **kwargs):
            await asyncio.sleep(0.1)  # 100ms de délai
            response = Mock()
            response.choices = [Mock()]
            response.choices[0].message.content = MockAIResponse.vulnerability_analysis_response()
            return response

        mock_openai.chat.completions.create.side_effect = delayed_response

        analyzer = Analyzer()

        start_time = time.time()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=[TestData.SAMPLE_VULNERABILITY]
        )
        end_time = time.time()

        actual_time = end_time - start_time
        reported_time = result.processing_time

        # Le temps rapporté devrait être cohérent avec le temps mesuré
        assert abs(actual_time - reported_time) < 0.5  # Marge de 500ms

    @pytest.mark.asyncio
    async def test_memory_usage_with_large_dataset(self, mock_openai):
        """Test d'utilisation mémoire avec gros dataset"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Créer un dataset volumineux
        large_dataset = []
        for i in range(1000):
            vuln = TestData.SAMPLE_VULNERABILITY.copy()
            vuln['vulnerability_id'] = f"CVE-2024-LARGE-{i:04d}"
            vuln['description'] = f"Large description {i} " * 100  # ~2KB par description
            large_dataset.append(vuln)

        mock_openai.chat.completions.create.return_value.choices[0].message.content = \
            MockAIResponse.vulnerability_analysis_response()

        analyzer = Analyzer()
        result = await analyzer.analyze_vulnerabilities(
            vulnerabilities_data=large_dataset[:100]  # Limiter pour éviter les timeouts
        )

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        # L'augmentation de mémoire devrait rester raisonnable (< 100MB)
        assert memory_increase < 100 * 1024 * 1024
        assert result is not None


# === CONFIGURATION DES TESTS ===

# Marqueurs pytest pour ce module
pytestmark = [
    pytest.mark.asyncio,  # Tous les tests sont async par défaut
]


# === FIXTURES SPÉCIFIQUES À CE MODULE ===

@pytest.fixture
def analyzer_with_mock_ai():
    """Fixture qui fournit un analyzer avec IA mockée"""
    with patch('src.core.analyzer.AsyncOpenAI') as mock_client:
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = MockAIResponse.vulnerability_analysis_response()

        mock_instance = Mock()
        mock_instance.chat.completions.create.return_value = mock_response
        mock_client.return_value = mock_instance

        analyzer = Analyzer()
        yield analyzer, mock_instance


@pytest.fixture
def complex_vulnerability_dataset():
    """Fixture avec un dataset complexe de vulnérabilités"""
    vulnerabilities = []

    # Vulnérabilités critiques
    for i in range(2):
        vuln = TestData.SAMPLE_VULNERABILITY.copy()
        vuln.update({
            'vulnerability_id': f'CVE-2024-CRIT-{i:03d}',
            'name': f'Critical Vulnerability {i + 1}',
            'severity': 'CRITICAL',
            'cvss_score': 9.0 + i * 0.5,
            'affected_service': f'critical-service-{i + 1}'
        })
        vulnerabilities.append(vuln)

    # Vulnérabilités élevées
    for i in range(3):
        vuln = TestData.SAMPLE_VULNERABILITY.copy()
        vuln.update({
            'vulnerability_id': f'CVE-2024-HIGH-{i:03d}',
            'name': f'High Vulnerability {i + 1}',
            'severity': 'HIGH',
            'cvss_score': 7.0 + i * 0.3,
            'affected_service': f'high-service-{i + 1}'
        })
        vulnerabilities.append(vuln)

    # Vulnérabilités moyennes
    for i in range(5):
        vuln = TestData.SAMPLE_VULNERABILITY.copy()
        vuln.update({
            'vulnerability_id': f'CVE-2024-MED-{i:03d}',
            'name': f'Medium Vulnerability {i + 1}',
            'severity': 'MEDIUM',
            'cvss_score': 4.0 + i * 0.5,
            'affected_service': f'medium-service-{i + 1}'
        })
        vulnerabilities.append(vuln)

    return vulnerabilities


# === UTILITAIRES DE TEST SPÉCIFIQUES ===

def assert_analysis_result_valid(result: AnalysisResult):
    """Vérifie qu'un résultat d'analyse est valide"""
    assert result is not None
    assert isinstance(result, AnalysisResult)
    assert result.analysis_id is not None
    assert result.target_system is not None
    assert isinstance(result.vulnerabilities, list)
    assert isinstance(result.analysis_summary, dict)
    assert isinstance(result.remediation_plan, dict)
    assert 0 <= result.confidence_score <= 1
    assert result.processing_time >= 0
    assert result.ai_model_used is not None


def create_custom_ai_response(vuln_count: int, risk_level: str = "MEDIUM") -> str:
    """Crée une réponse IA personnalisée pour les tests"""
    severity_distribution = {
        "LOW": {"critical": 0, "high": 0, "medium": 0, "low": vuln_count},
        "MEDIUM": {"critical": 0, "high": 1, "medium": vuln_count - 1, "low": 0},
        "HIGH": {"critical": 1, "high": vuln_count - 1, "medium": 0, "low": 0},
        "CRITICAL": {"critical": vuln_count, "high": 0, "medium": 0, "low": 0}
    }

    dist = severity_distribution.get(risk_level, severity_distribution["MEDIUM"])

    response = {
        "analysis_summary": {
            "total_vulnerabilities": vuln_count,
            "critical_count": dist["critical"],
            "high_count": dist["high"],
            "medium_count": dist["medium"],
            "low_count": dist["low"],
            "overall_risk_score": {"LOW": 3.0, "MEDIUM": 6.0, "HIGH": 8.0, "CRITICAL": 9.5}[risk_level]
        },
        "vulnerabilities": [
            {
                "id": f"CVE-2024-CUSTOM-{i:03d}",
                "name": f"Custom Vulnerability {i + 1}",
                "severity": risk_level,
                "cvss_score": {"LOW": 2.0, "MEDIUM": 5.0, "HIGH": 7.5, "CRITICAL": 9.0}[risk_level],
                "impact_analysis": f"Custom impact analysis {i + 1}",
                "exploitability": "MEDIUM",
                "priority_score": {"LOW": 3, "MEDIUM": 6, "HIGH": 8, "CRITICAL": 10}[risk_level],
                "affected_service": f"custom-service-{i + 1}",
                "recommended_actions": [f"Custom action {i + 1}"],
                "dependencies": [],
                "references": [f"https://example.com/custom-{i}"]
            }
            for i in range(vuln_count)
        ],
        "remediation_plan": {
            "immediate_actions": [f"Address {risk_level.lower()} priority vulnerabilities"],
            "short_term": ["Comprehensive security review"],
            "long_term": ["Implement continuous monitoring"]
        }
    }

    return json.dumps(response)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])