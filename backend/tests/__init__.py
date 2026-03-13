"""
Package de tests pour l'Agent IA

Ce module expose également quelques utilitaires communs utilisés
par plusieurs fichiers de tests (données de test, helpers, etc.).
"""

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pytest
from unittest.mock import AsyncMock, Mock

# Ajouter src au path
TEST_ROOT = Path(__file__).parent
PROJECT_ROOT = TEST_ROOT.parent
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

__version__ = "1.0.0"


class TestData:
    """
    Données de vulnérabilité réutilisables dans plusieurs tests.
    """

    SAMPLE_VULNERABILITY: Dict[str, Any] = {
        "vulnerability_id": "CVE-2024-0001",
        "name": "Test Vulnerability",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Vulnérabilité de test pour l'analyse IA.",
        "affected_service": "test-service",
        "affected_port": 80,
        "cve_ids": ["CVE-2024-0001"],
        "references": ["https://example.com/vuln/CVE-2024-0001"],
        "detection_method": "unit-test",
        "confidence": "high",
    }


class MockAIResponse:
    """
    Génère des réponses IA factices au format JSON attendu par l'analyzer.
    """

    @staticmethod
    def vulnerability_analysis_response() -> str:
        data = {
            "vulnerabilities": [
                {
                    "vulnerability_id": TestData.SAMPLE_VULNERABILITY["vulnerability_id"],
                    "name": TestData.SAMPLE_VULNERABILITY["name"],
                    "severity": TestData.SAMPLE_VULNERABILITY["severity"],
                    "cvss_score": TestData.SAMPLE_VULNERABILITY["cvss_score"],
                    "impact_analysis": "Impact de test généré par MockAIResponse.",
                    "exploitability": "MEDIUM",
                    "priority_score": 8,
                    "affected_service": TestData.SAMPLE_VULNERABILITY["affected_service"],
                    "recommended_actions": ["Appliquer le correctif de sécurité."],
                    "dependencies": [],
                    "references": TestData.SAMPLE_VULNERABILITY["references"],
                }
            ]
        }
        return json.dumps(data)


def requires_openai_key(test_func):
    """
    Décorateur pour marquer les tests qui nécessitent une vraie clé OpenAI.
    Si la variable d'environnement n'est pas définie, le test est ignoré.
    """

    @pytest.mark.skipif(
        not os.getenv("OPENAI_API_KEY"),
        reason="OPENAI_API_KEY non défini pour les tests d'intégration OpenAI.",
    )
    def wrapper(*args, **kwargs):
        return test_func(*args, **kwargs)

    return wrapper


def slow_test(test_func):
    """Décorateur pour marquer un test comme lent."""
    return pytest.mark.slow(test_func)


def integration_test(test_func):
    """Décorateur pour marquer un test d'intégration."""
    return pytest.mark.integration(test_func)


def create_test_file(directory: Path, name: str = "test.txt", content: str = "test") -> Path:
    """
    Helper simple pour créer un fichier de test dans un répertoire donné.
    """
    directory.mkdir(parents=True, exist_ok=True)
    file_path = directory / name
    file_path.write_text(content, encoding="utf-8")
    return file_path


@pytest.fixture
def sample_vulnerability() -> Dict[str, Any]:
    """Fixture retournant une vulnérabilité de test."""
    return TestData.SAMPLE_VULNERABILITY.copy()


@pytest.fixture
def sample_analysis_result(sample_vulnerability) -> Dict[str, Any]:
    """Fixture retournant un résultat d'analyse minimal."""
    return {
        "analysis_id": "analysis-test-001",
        "target_system": "test-system",
        "analyzed_at": datetime.utcnow().isoformat(),
        "analysis_summary": {"total_vulnerabilities": 1},
        "vulnerabilities": [sample_vulnerability],
        "remediation_plan": {"immediate_actions": ["Corriger la vulnérabilité critique"]},
    }


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """
    Configuration générique utilisée dans plusieurs tests.
    On laisse le provider par défaut géré par le code applicatif.
    """
    return {
        "ai_provider": "anthropic",
        "openai_api_key": "test-key",
        "anthropic_api_key": "test-key",
    }


@pytest.fixture
def mock_openai(monkeypatch) -> Mock:
    """
    Fixture renvoyant un client OpenAI factice.
    Les tests peuvent configurer .chat.completions.create sur cet objet.
    """
    client = AsyncMock()
    # Structure minimale utilisée par les tests
    client.chat.completions.create.return_value = Mock(
        choices=[Mock(message=Mock(content=MockAIResponse.vulnerability_analysis_response()))]
    )
    return client
