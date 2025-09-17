"""
Package de tests pour l'Agent IA de Cybersécurité

Ce package contient tous les tests automatisés de l'application :
- Tests unitaires pour chaque module
- Tests d'intégration pour les workflows
- Fixtures et données de test
- Configuration des environnements de test

Structure des tests :
    tests/
    ├── __init__.py (ce fichier)
    ├── fixtures/              # Données de test réutilisables
    ├── test_data/             # Exemples de scans et rapports
    ├── test_collector.py      # Tests du module Collector
    ├── test_analyzer.py       # Tests du module Analyzer
    ├── test_generator.py      # Tests du module Generator
    ├── test_database.py       # Tests de la base de données
    ├── test_utils.py          # Tests des utilitaires
    └── test_integration.py    # Tests d'intégration
"""

import os
import sys
import tempfile
import shutil
import pytest
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, Generator
from unittest.mock import Mock, patch
from datetime import datetime
import json

# Ajouter le chemin src au PYTHONPATH pour les imports
TEST_ROOT = Path(__file__).parent
PROJECT_ROOT = TEST_ROOT.parent
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

# Version du package de tests
__version__ = "1.0.0"

# === CONFIGURATION DES TESTS ===

# Configuration par défaut pour les tests
TEST_CONFIG = {
    "database": {
        "database_path": ":memory:",  # Base en mémoire pour les tests
        "backup_enabled": False,
        "auto_vacuum": False,
        "foreign_keys": True
    },
    "logging": {
        "level": "WARNING",  # Moins verbeux pendant les tests
        "enable_file_logging": False,
        "enable_console_logging": False
    },
    "scan": {
        "timeout": 30,  # Timeout réduit pour les tests
        "max_concurrent_scans": 1
    },
    "ai": {
        "mock_responses": True,  # Utiliser des réponses mockées par défaut
        "timeout": 10
    }
}

# Répertoires de test
TEST_DIRS = {
    "fixtures": TEST_ROOT / "fixtures",
    "test_data": TEST_ROOT / "test_data",
    "temp": TEST_ROOT / "temp",
    "output": TEST_ROOT / "output"
}


# === FIXTURES ET DONNÉES DE TEST ===

class TestData:
    """Classe contenant les données de test standard"""

    # Exemple de vulnérabilité pour les tests
    SAMPLE_VULNERABILITY = {
        "vulnerability_id": "CVE-2024-TEST-001",
        "name": "Test Vulnerability",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Vulnérabilité de test pour les tests unitaires",
        "affected_service": "test-service",
        "affected_port": 8080,
        "cve_ids": ["CVE-2024-TEST-001"],
        "references": ["https://example.com/test-vuln"],
        "detection_method": "test-scanner",
        "confidence": "HIGH"
    }

    # Exemple de scan result
    SAMPLE_SCAN_RESULT = {
        "scan_id": "test-scan-001",
        "target": "192.168.1.100",
        "scan_type": "quick",
        "started_at": "2025-01-15T10:00:00Z",
        "completed_at": "2025-01-15T10:05:00Z",
        "duration": 300.0,
        "host_status": "up",
        "open_ports": [22, 80, 443],
        "services": [
            {
                "port": 22,
                "protocol": "tcp",
                "service_name": "ssh",
                "version": "OpenSSH 8.0",
                "state": "open"
            },
            {
                "port": 80,
                "protocol": "tcp",
                "service_name": "http",
                "version": "Apache 2.4.41",
                "state": "open"
            }
        ],
        "vulnerabilities": [SAMPLE_VULNERABILITY],
        "scan_parameters": {
            "nmap_args": "-sV -sC",
            "timeout": 300
        }
    }

    # Exemple d'analyse IA
    SAMPLE_ANALYSIS_RESULT = {
        "analysis_id": "test-analysis-001",
        "target_system": "test-system",
        "analyzed_at": "2025-01-15T10:10:00Z",
        "analysis_summary": {
            "total_vulnerabilities": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "overall_risk_score": 7.5
        },
        "vulnerabilities": [
            {
                "vulnerability_id": "CVE-2024-TEST-001",
                "name": "Test Vulnerability",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "impact_analysis": "Impact de test",
                "exploitability": "MEDIUM",
                "priority_score": 8,
                "affected_service": "test-service",
                "recommended_actions": ["Action 1", "Action 2"],
                "dependencies": [],
                "references": ["https://example.com/test-vuln"]
            }
        ],
        "remediation_plan": {
            "immediate_actions": ["Corriger la vulnérabilité de test"],
            "short_term": [],
            "long_term": []
        },
        "ai_model_used": "test-model",
        "confidence_score": 0.85,
        "processing_time": 5.0
    }

    # Exemple de script généré
    SAMPLE_SCRIPT_RESULT = {
        "script_id": "test-script-001",
        "vulnerability_id": "CVE-2024-TEST-001",
        "metadata": {
            "script_id": "test-script-001",
            "vulnerability_id": "CVE-2024-TEST-001",
            "target_system": "ubuntu",
            "script_type": "main",
            "generated_at": "2025-01-15T10:15:00Z",
            "generated_by": "test-generator",
            "risk_level": "MEDIUM",
            "estimated_duration": "5 minutes",
            "requires_reboot": False,
            "requires_sudo": True
        },
        "main_script": "#!/bin/bash\necho 'Test script'\nexit 0",
        "rollback_script": "#!/bin/bash\necho 'Test rollback'\nexit 0",
        "validation_result": {
            "is_safe": True,
            "overall_risk": "MEDIUM",
            "execution_recommendation": "APPROVE",
            "confidence_level": 0.9,
            "identified_risks": [],
            "security_checks": {},
            "improvements": []
        },
        "pre_checks": ["Vérifier les permissions"],
        "post_checks": ["Vérifier que le service redémarre"],
        "warnings": ["Script de test - ne pas exécuter en production"],
        "script_hash": "abc123def456",
        "dependencies": ["bash"],
        "backup_commands": ["cp /etc/config /etc/config.backup"]
    }


# === MOCKS ET UTILITAIRES ===

class MockAIResponse:
    """Mock pour les réponses d'IA"""

    @staticmethod
    def vulnerability_analysis_response():
        """Réponse mockée pour l'analyse de vulnérabilités"""
        return json.dumps({
            "analysis_summary": {
                "total_vulnerabilities": 1,
                "critical_count": 0,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
                "overall_risk_score": 7.5
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2024-TEST-001",
                    "name": "Test Vulnerability",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "impact_analysis": "Impact de test pour les tests unitaires",
                    "exploitability": "MEDIUM",
                    "priority_score": 8,
                    "affected_service": "test-service",
                    "recommended_actions": [
                        "Mettre à jour le service vers la dernière version",
                        "Configurer un firewall restrictif"
                    ],
                    "dependencies": [],
                    "references": ["https://example.com/test-vuln"]
                }
            ],
            "remediation_plan": {
                "immediate_actions": ["Corriger la vulnérabilité critique"],
                "short_term": ["Audit de sécurité complet"],
                "long_term": ["Mise en place d'un monitoring permanent"]
            }
        })

    @staticmethod
    def script_generation_response():
        """Réponse mockée pour la génération de scripts"""
        return json.dumps({
            "script_info": {
                "vulnerability_id": "CVE-2024-TEST-001",
                "description": "Script de correction pour vulnérabilité de test",
                "estimated_duration": "5 minutes",
                "requires_reboot": False,
                "risk_level": "MEDIUM"
            },
            "pre_checks": [
                "Vérifier les droits administrateur",
                "Créer une sauvegarde"
            ],
            "backup_commands": [
                "cp /etc/config /etc/config.backup.$(date +%Y%m%d_%H%M%S)"
            ],
            "main_script": """#!/bin/bash
set -euo pipefail

# Script de test généré automatiquement
echo "Début de la correction de test"

# Simulation de correction
echo "Correction appliquée avec succès"

echo "Fin de la correction de test"
""",
            "rollback_script": """#!/bin/bash
set -euo pipefail

# Script de rollback de test
echo "Début du rollback de test"

# Restaurer la configuration
if [[ -f /etc/config.backup.* ]]; then
    cp /etc/config.backup.* /etc/config
    echo "Configuration restaurée"
fi

echo "Fin du rollback de test"
""",
            "post_checks": [
                "Vérifier que le service redémarre",
                "Tester la fonctionnalité"
            ],
            "warnings": [
                "Script de test - ne pas utiliser en production",
                "Tester dans un environnement de développement"
            ]
        })


class MockNmapResult:
    """Mock pour les résultats Nmap"""

    def __init__(self, target: str = "192.168.1.100"):
        self.target = target
        self._hosts = [target]
        self._scaninfo = {
            "tcp": {
                "method": "syn",
                "services": "1-1000"
            }
        }

    def all_hosts(self):
        return self._hosts

    def scaninfo(self):
        return self._scaninfo

    def command_line(self):
        return f"nmap -sV -sC {self.target}"

    def __getitem__(self, host):
        return MockHostResult(host)


class MockHostResult:
    """Mock pour les résultats d'un hôte"""

    def __init__(self, host: str):
        self.host = host
        self._protocols = ["tcp"]
        self._ports = {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.0",
                "product": "OpenSSH",
                "extrainfo": ""
            },
            80: {
                "state": "open",
                "name": "http",
                "version": "Apache 2.4.41",
                "product": "Apache httpd",
                "extrainfo": ""
            }
        }

    def state(self):
        return "up"

    def all_protocols(self):
        return self._protocols

    def __getitem__(self, protocol):
        return MockProtocolResult(self._ports)


class MockProtocolResult:
    """Mock pour les résultats d'un protocole"""

    def __init__(self, ports_data):
        self._ports_data = ports_data

    def keys(self):
        return self._ports_data.keys()

    def __getitem__(self, port):
        return self._ports_data[port]


# === FIXTURES PYTEST ===

@pytest.fixture
def test_config():
    """Fixture qui fournit une configuration de test"""
    return TEST_CONFIG.copy()


@pytest.fixture
def temp_dir():
    """Fixture qui crée un répertoire temporaire pour les tests"""
    temp_path = tempfile.mkdtemp(prefix="agent_ia_test_")
    yield Path(temp_path)
    # Nettoyage
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def test_database():
    """Fixture qui fournit une base de données de test en mémoire"""
    from src.database.database import Database

    config = {
        "database_path": ":memory:",
        "backup_enabled": False,
        "foreign_keys": True
    }

    db = Database(config)
    db.create_tables()
    yield db
    db.close()


@pytest.fixture
def sample_vulnerability():
    """Fixture qui fournit une vulnérabilité d'exemple"""
    return TestData.SAMPLE_VULNERABILITY.copy()


@pytest.fixture
def sample_scan_result():
    """Fixture qui fournit un résultat de scan d'exemple"""
    return TestData.SAMPLE_SCAN_RESULT.copy()


@pytest.fixture
def sample_analysis_result():
    """Fixture qui fournit un résultat d'analyse d'exemple"""
    return TestData.SAMPLE_ANALYSIS_RESULT.copy()


@pytest.fixture
def mock_nmap():
    """Fixture qui mock les appels Nmap"""
    with patch('nmap.PortScanner') as mock_scanner:
        mock_instance = Mock()
        mock_instance.scan.return_value = None
        mock_instance.all_hosts.return_value = ["192.168.1.100"]
        mock_instance.scaninfo.return_value = {"tcp": {"method": "syn", "services": "1-1000"}}
        mock_instance.command_line.return_value = "nmap -sV -sC 192.168.1.100"
        mock_instance.__getitem__.return_value = MockHostResult("192.168.1.100")
        mock_scanner.return_value = mock_instance
        yield mock_instance


@pytest.fixture
def mock_openai():
    """Fixture qui mock les appels OpenAI"""
    with patch('openai.AsyncOpenAI') as mock_client:
        # Mock de la réponse de completion
        mock_response = Mock()
        mock_response.choices = [Mock()]
        mock_response.choices[0].message.content = MockAIResponse.vulnerability_analysis_response()

        # Mock du client
        mock_instance = Mock()
        mock_instance.chat.completions.create.return_value = mock_response
        mock_client.return_value = mock_instance

        yield mock_instance


@pytest.fixture(scope="session")
def event_loop():
    """Fixture pour gérer la boucle d'événements asyncio dans les tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# === UTILITAIRES DE TEST ===

def create_test_file(content: str, filename: str, directory: Path = None) -> Path:
    """
    Crée un fichier de test avec le contenu spécifié

    Args:
        content: Contenu du fichier
        filename: Nom du fichier
        directory: Répertoire où créer le fichier (temp par défaut)

    Returns:
        Path: Chemin vers le fichier créé
    """
    if directory is None:
        directory = TEST_DIRS["temp"]

    directory.mkdir(parents=True, exist_ok=True)
    file_path = directory / filename

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return file_path


def load_test_data(filename: str) -> Dict[str, Any]:
    """
    Charge des données de test depuis un fichier JSON

    Args:
        filename: Nom du fichier dans test_data/

    Returns:
        Dict: Données chargées
    """
    file_path = TEST_DIRS["test_data"] / filename

    if not file_path.exists():
        raise FileNotFoundError(f"Fichier de test non trouvé: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def assert_vulnerability_equal(vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> None:
    """
    Compare deux vulnérabilités en ignorant les champs temporels

    Args:
        vuln1: Première vulnérabilité
        vuln2: Deuxième vulnérabilité
    """
    # Champs à ignorer dans la comparaison
    ignore_fields = {'created_at', 'updated_at', 'detected_at'}

    for key in vuln1:
        if key not in ignore_fields:
            assert key in vuln2, f"Champ manquant: {key}"
            assert vuln1[key] == vuln2[key], f"Différence sur {key}: {vuln1[key]} != {vuln2[key]}"


def create_mock_scan_result(
        target: str = "192.168.1.100",
        vulnerability_count: int = 1,
        scan_type: str = "quick"
):
    """
    Crée un résultat de scan mocké

    Args:
        target: Cible du scan
        vulnerability_count: Nombre de vulnérabilités à inclure
        scan_type: Type de scan

    Returns:
        Mock ScanResult
    """
    from src.core.collector import ScanResult, VulnerabilityInfo, ServiceInfo

    # Créer des vulnérabilités de test
    vulnerabilities = []
    for i in range(vulnerability_count):
        vuln = VulnerabilityInfo(
            vulnerability_id=f"CVE-2024-TEST-{i:03d}",
            name=f"Test Vulnerability {i + 1}",
            severity="HIGH" if i == 0 else "MEDIUM",
            cvss_score=7.5 - i * 0.5,
            description=f"Vulnérabilité de test numéro {i + 1}",
            affected_service="test-service",
            affected_port=8080 + i,
            cve_ids=[f"CVE-2024-TEST-{i:03d}"],
            references=[f"https://example.com/vuln-{i}"],
            detection_method="test-scanner",
            confidence="HIGH"
        )
        vulnerabilities.append(vuln)

    # Créer des services de test
    services = [
        ServiceInfo(
            port=22,
            protocol="tcp",
            service_name="ssh",
            version="OpenSSH 8.0",
            state="open"
        ),
        ServiceInfo(
            port=80,
            protocol="tcp",
            service_name="http",
            version="Apache 2.4.41",
            state="open"
        )
    ]

    # Créer le résultat de scan
    scan_result = ScanResult(
        scan_id=f"test-scan-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        target=target,
        scan_type=scan_type,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration=300.0,
        host_status="up",
        open_ports=[22, 80, 8080],
        services=services,
        vulnerabilities=vulnerabilities,
        scan_parameters={
            "nmap_args": "-sV -sC",
            "timeout": 300,
            "scan_type": scan_type
        },
        nmap_version="7.80"
    )

    return scan_result


# === DÉCORATEURS DE TEST ===

def requires_nmap(func):
    """
    Décorateur qui skip le test si Nmap n'est pas disponible
    """
    import shutil

    def wrapper(*args, **kwargs):
        if not shutil.which('nmap'):
            pytest.skip("Nmap non disponible")
        return func(*args, **kwargs)

    return wrapper


def requires_openai_key(func):
    """
    Décorateur qui skip le test si la clé OpenAI n'est pas configurée
    """

    def wrapper(*args, **kwargs):
        if not os.getenv('OPENAI_API_KEY'):
            pytest.skip("Clé OpenAI non configurée")
        return func(*args, **kwargs)

    return wrapper


def slow_test(func):
    """
    Décorateur pour marquer les tests lents
    """
    return pytest.mark.slow(func)


def integration_test(func):
    """
    Décorateur pour marquer les tests d'intégration
    """
    return pytest.mark.integration(func)


# === INITIALISATION DU PACKAGE ===

def setup_test_environment():
    """Configure l'environnement de test"""
    # Créer les répertoires de test
    for test_dir in TEST_DIRS.values():
        test_dir.mkdir(parents=True, exist_ok=True)

    # Configurer les variables d'environnement pour les tests
    os.environ['TESTING'] = 'true'
    os.environ['LOG_LEVEL'] = 'WARNING'

    # Désactiver les sauvegardes automatiques pendant les tests
    os.environ['BACKUP_ENABLED'] = 'false'


def cleanup_test_environment():
    """Nettoie l'environnement de test"""
    # Nettoyer les répertoires temporaires
    temp_dir = TEST_DIRS.get("temp")
    if temp_dir and temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)

    output_dir = TEST_DIRS.get("output")
    if output_dir and output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)


# Initialiser l'environnement de test au chargement du module
setup_test_environment()

# === EXPORTS ===

__all__ = [
    # Configuration
    "TEST_CONFIG",
    "TEST_DIRS",
    "TestData",

    # Mocks
    "MockAIResponse",
    "MockNmapResult",
    "MockHostResult",

    # Fixtures (automatiquement découvertes par pytest)

    # Utilitaires
    "create_test_file",
    "load_test_data",
    "assert_vulnerability_equal",
    "create_mock_scan_result",

    # Décorateurs
    "requires_nmap",
    "requires_openai_key",
    "slow_test",
    "integration_test",

    # Fonctions
    "setup_test_environment",
    "cleanup_test_environment"
]

# === CONFIGURATION PYTEST ===

# Markers personnalisés pour pytest (à ajouter dans pytest.ini)
pytest_markers = {
    "slow": "Tests lents qui prennent plus de 10 secondes",
    "integration": "Tests d'intégration qui nécessitent des services externes",
    "requires_nmap": "Tests qui nécessitent Nmap",
    "requires_openai": "Tests qui nécessitent une clé OpenAI",
    "network": "Tests qui nécessitent un accès réseau"
}

if __name__ == "__main__":
    print(f"Package de tests Agent IA Cybersécurité v{__version__}")
    print(f"Répertoire de test: {TEST_ROOT}")
    print(f"Répertoire source: {SRC_PATH}")

    print("\nRépertoires de test:")
    for name, path in TEST_DIRS.items():
        exists = "✅" if path.exists() else "❌"
        print(f"  {exists} {name}: {path}")

    print(
        f"\nFixtures disponibles: {len([name for name in globals() if name.endswith('_fixture') or 'fixture' in str(globals()[name])])}")
    print(f"Utilitaires de test disponibles: {len([name for name in __all__ if 'mock' not in name.lower()])}")

    print("\nPour lancer les tests:")
    print("  pytest tests/")
    print("  pytest tests/ -v --tb=short")
    print("  pytest tests/ -k 'not slow'")
    print("  pytest tests/test_collector.py::test_scan_basic")