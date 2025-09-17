"""
Tests d'intégration pour l'Agent IA de Cybersécurité

Ce module contient les tests d'intégration qui valident le fonctionnement
de l'ensemble du système avec l'interaction entre tous les modules :
- Supervisor + Collector + Analyzer + Generator
- Workflows complets de bout en bout
- Tests avec vraie infrastructure (Nmap, OpenAI, Base de données)
- Scénarios réalistes de détection et correction de vulnérabilités

Les tests d'intégration nécessitent :
- Une clé OpenAI valide (variable d'environnement)
- Nmap installé et fonctionnel
- Accès réseau pour les scans de test
- Base de données SQLite fonctionnelle
"""

import asyncio
import json
import os
import pytest
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import subprocess

import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from config import get_config, validate_config
from src.core.supervisor import Supervisor, WorkflowType, WorkflowStatus
from src.core.collector import Collector, validate_nmap_installation
from src.core.analyzer import Analyzer
from src.core.generator import Generator
from src.database.database import Database
from src.utils.validators import validate_ip_address
from src import create_agent, get_application_status

# Configuration des tests d'intégration
INTEGRATION_TEST_CONFIG = {
    'use_real_openai': os.getenv('OPENAI_API_KEY') is not None,
    'use_real_nmap': True,
    'test_targets': {
        'localhost': '127.0.0.1',
        'safe_public': 'scanme.nmap.org',  # Site de test officiel Nmap
        'local_network': '192.168.1.1'
    },
    'timeout_multiplier': 2.0,  # Tests plus longs pour l'intégration
    'skip_slow_tests': os.getenv('SKIP_SLOW_TESTS', 'false').lower() == 'true'
}


# === FIXTURES COMMUNES ===

@pytest.fixture
def temp_database():
    """Fixture pour une base de données temporaire"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_file:
        db_path = tmp_file.name

    config = {
        'database_path': db_path,
        'backup_enabled': False,
        'foreign_keys': True
    }

    db = Database(config)
    db.create_tables()

    yield db

    db.close()
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def integration_config():
    """Configuration pour les tests d'intégration"""
    config = get_config()

    # Adapter la configuration pour les tests
    config.openai_temperature = 0.1  # Plus déterministe
    config.scan_timeout = int(300 * INTEGRATION_TEST_CONFIG['timeout_multiplier'])

    return config


@pytest.fixture
async def supervisor_instance(integration_config, temp_database):
    """Instance de superviseur configurée pour l'intégration"""
    supervisor = Supervisor(integration_config)

    # Injecter la base de données temporaire
    supervisor.db = temp_database

    yield supervisor

    await supervisor.shutdown()


# === TESTS DE CONFIGURATION ET PRÉREQUIS ===

class TestIntegrationPrerequisites:
    """Validation des prérequis pour les tests d'intégration"""

    def test_application_configuration(self, integration_config):
        """Test de la configuration globale de l'application"""
        # Valider la configuration
        assert validate_config(integration_config)

        # Vérifier les paramètres critiques
        assert integration_config.openai_api_key is not None
        assert integration_config.openai_model in ['gpt-4', 'gpt-3.5-turbo']
        assert integration_config.scan_timeout > 0

    def test_nmap_installation(self):
        """Test de l'installation et configuration Nmap"""
        nmap_status = validate_nmap_installation()

        assert nmap_status['valid'], f"Nmap non fonctionnel: {nmap_status.get('error')}"
        assert nmap_status['has_vuln_scripts'], "Scripts de vulnérabilité Nmap manquants"

        print(f"Nmap version détectée: {nmap_status['version']}")

    def test_database_connectivity(self, temp_database):
        """Test de connectivité et opérations de base de données"""
        # Test d'insertion
        test_data = {
            'scan_id': 'integration_test_001',
            'target': '127.0.0.1',
            'scan_type': 'test',
            'status': 'completed'
        }

        scan_id = temp_database.insert('scans', test_data)
        assert scan_id is not None

        # Test de sélection
        scans = temp_database.select('scans', where={'scan_id': 'integration_test_001'})
        assert len(scans) == 1
        assert scans[0]['target'] == '127.0.0.1'

    def test_openai_connectivity(self, integration_config):
        """Test de connectivité OpenAI"""
        if not INTEGRATION_TEST_CONFIG['use_real_openai']:
            pytest.skip("Test OpenAI désactivé (pas de clé API)")

        analyzer = Analyzer(integration_config)
        assert analyzer.is_ready
        assert analyzer.is_healthy()

    def test_application_status(self):
        """Test du statut global de l'application"""
        status = get_application_status()

        assert status['status'] in ['ready', 'not_ready']
        assert 'dependencies' in status
        assert 'components_available' in status

        # Vérifier les composants critiques
        assert status['components_available']['core'] is True
        assert status['components_available']['database'] is True


# === TESTS DE WORKFLOW COMPLET ===

class TestCompleteWorkflows:
    """Tests des workflows complets de bout en bout"""

    @pytest.mark.asyncio
    @pytest.mark.skipif(INTEGRATION_TEST_CONFIG['skip_slow_tests'], reason="Test lent désactivé")
    async def test_full_vulnerability_assessment_localhost(self, supervisor_instance):
        """Test complet d'évaluation de vulnérabilités sur localhost"""
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        # Callback pour suivre la progression
        progress_updates = []

        def progress_callback(task_name, progress):
            progress_updates.append((task_name, progress, time.time()))
            print(f"Progression {task_name}: {progress}%")

        # Lancer le workflow complet
        start_time = time.time()

        workflow_result = await supervisor_instance.run_complete_workflow(
            target=target,
            scan_type='quick',  # Scan rapide pour les tests
            progress_callback=progress_callback
        )

        execution_time = time.time() - start_time

        # Vérifications du résultat
        assert workflow_result is not None
        assert workflow_result.status == WorkflowStatus.COMPLETED
        assert workflow_result.target == target
        assert workflow_result.duration > 0

        # Vérifier les résultats du scan
        assert workflow_result.scan_result is not None
        assert workflow_result.scan_result.target == target
        assert isinstance(workflow_result.scan_result.open_ports, list)

        # Vérifier les résultats d'analyse (si des vulnérabilités trouvées)
        if workflow_result.total_vulnerabilities > 0:
            assert workflow_result.analysis_result is not None
            assert len(workflow_result.analysis_result.vulnerabilities) > 0

            # Vérifier la génération de scripts (si configurée)
            if workflow_result.script_results:
                assert len(workflow_result.script_results) > 0
                for script in workflow_result.script_results:
                    assert script.main_script is not None
                    assert '#!/bin/bash' in script.main_script

        # Vérifier les callbacks de progression
        assert len(progress_updates) > 0
        assert any(task == 'scan' for task, _, _ in progress_updates)

        print(f"Workflow complet exécuté en {execution_time:.2f}s")
        print(f"Vulnérabilités trouvées: {workflow_result.total_vulnerabilities}")
        print(f"Scripts générés: {workflow_result.scripts_generated}")

    @pytest.mark.asyncio
    async def test_scan_only_workflow(self, supervisor_instance):
        """Test de workflow scan uniquement"""
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        # Lancer un scan uniquement
        scan_result = await supervisor_instance.run_scan(
            target=target,
            scan_type='quick'
        )

        # Vérifications
        assert scan_result is not None
        assert scan_result.target == target
        assert scan_result.host_status in ['up', 'down']
        assert isinstance(scan_result.open_ports, list)
        assert isinstance(scan_result.services, list)
        assert isinstance(scan_result.vulnerabilities, list)

        # Vérifier les métadonnées
        assert scan_result.scan_id is not None
        assert scan_result.duration >= 0
        assert scan_result.nmap_version is not None

    @pytest.mark.asyncio
    @pytest.mark.skipif(not INTEGRATION_TEST_CONFIG['use_real_openai'], reason="OpenAI requis")
    async def test_analysis_workflow(self, supervisor_instance):
        """Test de workflow d'analyse IA"""
        # Données de vulnérabilités simulées pour l'analyse
        test_vulnerabilities = [
            {
                'name': 'SSH Weak Configuration',
                'severity': 'HIGH',
                'cvss_score': 7.5,
                'affected_service': 'OpenSSH',
                'affected_port': 22,
                'description': 'Configuration SSH faible détectée',
                'cve_ids': ['CVE-2023-TEST1']
            },
            {
                'name': 'Apache Version Disclosure',
                'severity': 'MEDIUM',
                'cvss_score': 5.0,
                'affected_service': 'Apache HTTP Server',
                'affected_port': 80,
                'description': 'Version Apache exposée',
                'cve_ids': ['CVE-2023-TEST2']
            }
        ]

        # Lancer l'analyse
        analysis_result = await supervisor_instance.analyze_vulnerabilities(
            vulnerabilities_data=test_vulnerabilities,
            target_system="Test System Ubuntu 22.04"
        )

        # Vérifications
        assert analysis_result is not None
        assert analysis_result.analysis_id is not None
        assert len(analysis_result.vulnerabilities) == 2

        # Vérifier l'enrichissement IA
        for vuln in analysis_result.vulnerabilities:
            assert vuln.priority_score is not None
            assert vuln.priority_score >= 1 and vuln.priority_score <= 10
            assert len(vuln.recommended_actions) > 0

        # Vérifier le plan de remédiation
        assert analysis_result.remediation_plan is not None
        assert 'executive_summary' in analysis_result.remediation_plan
        assert 'implementation_roadmap' in analysis_result.remediation_plan

    @pytest.mark.asyncio
    @pytest.mark.skipif(not INTEGRATION_TEST_CONFIG['use_real_openai'], reason="OpenAI requis")
    async def test_script_generation_workflow(self, supervisor_instance):
        """Test de workflow de génération de scripts"""
        # Générer un script de correction
        script_result = await supervisor_instance.generate_fix_script(
            vulnerability_id='TEST-SCRIPT-001',
            target_system='ubuntu'
        )

        # Vérifications
        assert script_result is not None
        assert script_result.main_script is not None
        assert '#!/bin/bash' in script_result.main_script
        assert script_result.validation_result is not None
        assert script_result.validation_result.execution_recommendation in [
            'APPROVE', 'REVIEW_REQUIRED', 'REJECT'
        ]

        # Vérifier les éléments de sécurité
        assert len(script_result.pre_checks) > 0
        assert len(script_result.post_checks) > 0
        assert script_result.script_hash is not None


# === TESTS D'INTÉGRATION INTER-MODULES ===

class TestModuleIntegration:
    """Tests d'intégration entre les différents modules"""

    @pytest.mark.asyncio
    async def test_collector_to_analyzer_integration(self, integration_config):
        """Test d'intégration Collector -> Analyzer"""
        if not INTEGRATION_TEST_CONFIG['use_real_openai']:
            pytest.skip("Test nécessitant OpenAI")

        # Étape 1: Scanner avec le Collector
        collector = Collector(integration_config)
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        scan_result = await collector.scan_target(target, 'quick')
        assert scan_result is not None

        # Étape 2: Analyser avec l'Analyzer
        if scan_result.vulnerabilities:
            analyzer = Analyzer(integration_config)
            vuln_data = [vuln.to_dict() for vuln in scan_result.vulnerabilities]

            analysis_result = await analyzer.analyze_vulnerabilities(
                vulnerabilities_data=vuln_data,
                target_system=target
            )

            assert analysis_result is not None
            assert len(analysis_result.vulnerabilities) == len(scan_result.vulnerabilities)

    @pytest.mark.asyncio
    async def test_analyzer_to_generator_integration(self, integration_config):
        """Test d'intégration Analyzer -> Generator"""
        if not INTEGRATION_TEST_CONFIG['use_real_openai']:
            pytest.skip("Test nécessitant OpenAI")

        # Données d'analyse simulées
        analysis_vulnerabilities = [
            {
                'vulnerability_id': 'INTEGRATION-001',
                'name': 'Apache Configuration Issue',
                'severity': 'HIGH',
                'affected_service': 'Apache HTTP Server',
                'priority_score': 8,
                'recommended_actions': ['Update configuration', 'Restart service']
            }
        ]

        # Générer des scripts basés sur l'analyse
        generator = Generator(integration_config)

        for vuln in analysis_vulnerabilities:
            script_result = await generator.generate_fix_script(
                vulnerability_id=vuln['vulnerability_id'],
                vulnerability_details=vuln,
                target_system='ubuntu'
            )

            assert script_result is not None
            assert script_result.vulnerability_id == vuln['vulnerability_id']

    @pytest.mark.asyncio
    async def test_database_persistence_integration(self, temp_database, integration_config):
        """Test d'intégration avec persistance en base"""
        # Simuler un scan avec sauvegarde
        collector = Collector(integration_config)
        collector.db = temp_database

        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']
        scan_result = await collector.scan_target(target, 'quick')

        # Sauvegarder manuellement (dans un vrai workflow, c'est automatique)
        temp_database.save_scan_result(scan_result)

        # Vérifier la persistance
        saved_scans = temp_database.get_scan_history(target=target)
        assert len(saved_scans) == 1
        assert saved_scans[0]['target'] == target

        # Vérifier les vulnérabilités sauvegardées
        if scan_result.vulnerabilities:
            vulnerabilities = temp_database.select('vulnerabilities')
            assert len(vulnerabilities) >= len(scan_result.vulnerabilities)


# === TESTS DE SCÉNARIOS RÉALISTES ===

class TestRealisticScenarios:
    """Tests de scénarios réalistes d'utilisation"""

    @pytest.mark.asyncio
    @pytest.mark.skipif(INTEGRATION_TEST_CONFIG['skip_slow_tests'], reason="Test lent")
    async def test_multi_target_assessment(self, supervisor_instance):
        """Test d'évaluation multi-cibles"""
        targets = [
            INTEGRATION_TEST_CONFIG['test_targets']['localhost']
        ]

        # Ajouter une cible réseau locale si accessible
        local_gateway = INTEGRATION_TEST_CONFIG['test_targets']['local_network']
        if validate_ip_address(local_gateway):
            # Test ping rapide pour vérifier l'accessibilité
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '2', local_gateway],
                                        capture_output=True, timeout=5)
                if result.returncode == 0:
                    targets.append(local_gateway)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        results = []

        for target in targets:
            try:
                workflow_result = await supervisor_instance.run_complete_workflow(
                    target=target,
                    scan_type='quick'
                )
                results.append((target, workflow_result))

                # Pause entre les scans pour éviter la surcharge
                await asyncio.sleep(2)

            except Exception as e:
                print(f"Erreur scan {target}: {e}")
                continue

        # Vérifications
        assert len(results) >= 1  # Au moins localhost devrait fonctionner

        for target, result in results:
            assert result is not None
            assert result.target == target
            print(f"Cible {target}: {result.total_vulnerabilities} vulnérabilités")

    @pytest.mark.asyncio
    async def test_vulnerability_prioritization_scenario(self, supervisor_instance):
        """Test de scénario de priorisation de vulnérabilités"""
        if not INTEGRATION_TEST_CONFIG['use_real_openai']:
            pytest.skip("Nécessite OpenAI pour la priorisation")

        # Créer un mix de vulnérabilités de différentes sévérités
        mixed_vulnerabilities = [
            {
                'name': 'Critical RCE Vulnerability',
                'severity': 'CRITICAL',
                'cvss_score': 9.8,
                'affected_service': 'Apache HTTP Server',
                'description': 'Remote code execution vulnerability'
            },
            {
                'name': 'Information Disclosure',
                'severity': 'LOW',
                'cvss_score': 3.1,
                'affected_service': 'Nginx',
                'description': 'Server version disclosure'
            },
            {
                'name': 'Privilege Escalation',
                'severity': 'HIGH',
                'cvss_score': 8.2,
                'affected_service': 'OpenSSH',
                'description': 'Local privilege escalation'
            },
            {
                'name': 'DoS Vulnerability',
                'severity': 'MEDIUM',
                'cvss_score': 6.5,
                'affected_service': 'MySQL',
                'description': 'Denial of service via malformed query'
            }
        ]

        # Analyser avec contexte business
        analysis_result = await supervisor_instance.analyze_vulnerabilities(
            vulnerabilities_data=mixed_vulnerabilities,
            target_system="Production Web Server"
        )

        # Vérifier la priorisation
        vulnerabilities = analysis_result.vulnerabilities
        assert len(vulnerabilities) == 4

        # Vérifier que la vulnérabilité critique a la priorité la plus élevée
        critical_vuln = next(v for v in vulnerabilities if v.severity == 'CRITICAL')
        assert critical_vuln.priority_score >= 8

        # Vérifier que la vulnérabilité LOW a une priorité faible
        low_vuln = next(v for v in vulnerabilities if v.severity == 'LOW')
        assert low_vuln.priority_score <= 5

        # Vérifier le plan de remédiation
        remediation_plan = analysis_result.remediation_plan
        assert 'phase_1_immediate' in remediation_plan['implementation_roadmap']

        # La vulnérabilité critique devrait être en phase 1
        immediate_vulns = remediation_plan['implementation_roadmap']['phase_1_immediate']['vulnerabilities']
        assert critical_vuln.vulnerability_id in immediate_vulns

    @pytest.mark.asyncio
    async def test_error_recovery_scenario(self, supervisor_instance):
        """Test de scénario de récupération d'erreur"""
        # Test avec une cible invalide
        invalid_target = "999.999.999.999"

        # Le workflow devrait échouer proprement
        try:
            workflow_result = await supervisor_instance.run_complete_workflow(
                target=invalid_target,
                scan_type='quick'
            )
            # Si on arrive ici, le workflow a réussi (inattendu)
            assert workflow_result.status == WorkflowStatus.FAILED
        except Exception as e:
            # Comportement attendu - erreur capturée
            assert "invalide" in str(e).lower() or "failed" in str(e).lower()

        # Vérifier que le superviseur est toujours opérationnel
        assert supervisor_instance.is_healthy()

        # Test avec une cible valide après l'erreur
        valid_target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']
        workflow_result = await supervisor_instance.run_scan(valid_target, 'quick')

        assert workflow_result is not None
        assert workflow_result.target == valid_target


# === TESTS DE PERFORMANCE ET CHARGE ===

class TestIntegrationPerformance:
    """Tests de performance en conditions d'intégration"""

    @pytest.mark.asyncio
    @pytest.mark.skipif(INTEGRATION_TEST_CONFIG['skip_slow_tests'], reason="Test de performance lent")
    async def test_concurrent_workflows_performance(self, supervisor_instance):
        """Test de performance avec workflows concurrents"""
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']
        num_workflows = 3

        # Lancer plusieurs workflows en parallèle
        start_time = time.time()

        tasks = []
        for i in range(num_workflows):
            task = supervisor_instance.run_scan(
                target=target,
                scan_type='quick'
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        execution_time = time.time() - start_time

        # Vérifications
        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 2  # Au moins 2 sur 3 devraient réussir

        # Le temps total ne devrait pas être linéaire
        # (parallélisation devrait améliorer les performances)
        expected_sequential_time = num_workflows * 30  # 30s par scan séquentiel
        assert execution_time < expected_sequential_time * 0.8

        print(f"Workflows concurrents: {execution_time:.2f}s pour {num_workflows} scans")

    @pytest.mark.asyncio
    async def test_memory_usage_integration(self, supervisor_instance):
        """Test d'utilisation mémoire en intégration"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss

        # Exécuter plusieurs opérations
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        for i in range(5):
            await supervisor_instance.run_scan(target, 'quick')

            # Petite pause pour éviter la surcharge
            await asyncio.sleep(1)

        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before

        # Vérification (limite de 200MB d'augmentation)
        memory_increase_mb = memory_increase / (1024 * 1024)
        assert memory_increase_mb < 200, f"Augmentation mémoire excessive: {memory_increase_mb:.1f}MB"

        print(f"Utilisation mémoire: +{memory_increase_mb:.1f}MB pour 5 scans")

    @pytest.mark.asyncio
    async def test_database_performance_integration(self, temp_database, integration_config):
        """Test de performance de base de données en intégration"""
        # Simuler l'insertion de nombreux résultats de scan
        num_scans = 50

        start_time = time.time()

        # Insérer des données de test
        scan_data_list = []
        for i in range(num_scans):
            scan_data = {
                'scan_id': f'perf_test_{i}',
                'target': f'192.168.1.{i % 254 + 1}',
                'scan_type': 'quick',
                'status': 'completed',
                'duration': float(30 + i % 60)
            }
            scan_data_list.append(scan_data)

        # Insertion en lot
        inserted_count = temp_database.bulk_insert('scans', scan_data_list)

        insertion_time = time.time() - start_time

        # Vérifications
        assert inserted_count == num_scans
        assert insertion_time < 5.0  # Moins de 5 secondes pour 50 insertions

        # Test de requête
        start_time = time.time()

        all_scans = temp_database.select('scans', limit=100)
        query_time = time.time() - start_time

        assert len(all_scans) == num_scans
        assert query_time < 1.0  # Moins d'1 seconde pour la requête

        print(f"DB Performance: {insertion_time:.3f}s insertion, {query_time:.3f}s requête")


# === TESTS DE DÉPLOIEMENT ET CONFIGURATION ===

class TestDeploymentIntegration:
    """Tests liés au déploiement et à la configuration"""

    def test_environment_configuration(self):
        """Test de configuration d'environnement"""
        # Vérifier que toutes les variables d'environnement critiques sont définies
        required_env_vars = [
            'OPENAI_API_KEY',  # Peut être None mais doit être définie
        ]

        for var in required_env_vars:
            assert var in os.environ, f"Variable d'environnement manquante: {var}"

        # Tester différents environnements
        test_environments = ['development', 'test', 'production']

        for env in test_environments:
            os.environ['ENVIRONMENT'] = env

            # La configuration devrait s'adapter à l'environnement
            config = get_config()
            assert config is not None

    def test_file_permissions_and_paths(self):
        """Test des permissions de fichiers et chemins"""
        # Vérifier que les répertoires critiques existent ou peuvent être créés
        critical_paths = [
            'data',
            'data/scans',
            'data/reports',
            'data/scripts',
            'data/database',
            'logs'
        ]

        for path_str in critical_paths:
            path = Path(path_str)

            # Créer si n'existe pas
            path.mkdir(parents=True, exist_ok=True)

            # Vérifier les permissions
            assert path.exists(), f"Impossible de créer le répertoire: {path}"
            assert os.access(path, os.R_OK | os.W_OK), f"Permissions insuffisantes: {path}"

    def test_logging_configuration(self):
        """Test de configuration du logging"""
        from src.utils.logger import setup_logger

        # Test de création de logger
        test_logger = setup_logger('integration_test')
        assert test_logger is not None

        # Test d'écriture de logs
        test_logger.info("Test log message")
        test_logger.warning("Test warning message")

        # Les logs ne devraient pas générer d'erreur

    @pytest.mark.asyncio
    async def test_graceful_shutdown_integration(self, supervisor_instance):
        """Test d'arrêt propre de l'application"""
        # Démarrer un workflow
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        # Lancer un scan en arrière-plan
        scan_task = asyncio.create_task(
            supervisor_instance.run_scan(target, 'quick')
        )

        # Attendre un peu puis demander l'arrêt
        await asyncio.sleep(2)

        # Arrêt du superviseur
        shutdown_start = time.time()
        await supervisor_instance.shutdown()
        shutdown_time = time.time() - shutdown_start

        # L'arrêt devrait être rapide
        assert shutdown_time < 10.0

        # Vérifier que le superviseur n'est plus actif
        assert not supervisor_instance.is_running

        # Le scan devrait se terminer proprement (ou être annulé)
        try:
            await scan_task
        except asyncio.CancelledError:
            # Comportement attendu si le scan est annulé
            pass


# === TESTS DE SURVEILLANCE ET MONITORING ===

class TestMonitoringIntegration:
    """Tests d'intégration pour le monitoring"""

    @pytest.mark.asyncio
    async def test_metrics_collection_integration(self, supervisor_instance):
        """Test de collecte de métriques en intégration"""
        # Exécuter quelques opérations pour générer des métriques
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        await supervisor_instance.run_scan(target, 'quick')

        # Collecter les statistiques
        supervisor_stats = supervisor_instance.get_stats()
        module_stats = supervisor_instance.get_module_stats()

        # Vérifications des statistiques
        assert 'total_workflows' in supervisor_stats
        assert 'successful_workflows' in supervisor_stats
        assert 'uptime_seconds' in supervisor_stats

        # Vérifier les modules
        assert 'collector' in module_stats
        assert 'analyzer' in module_stats
        assert 'generator' in module_stats

        # Les statistiques devraient refléter l'activité
        assert supervisor_stats['total_workflows'] >= 1

    @pytest.mark.asyncio
    async def test_health_monitoring_integration(self, supervisor_instance):
        """Test du monitoring de santé en intégration"""
        # Vérifier la santé initiale
        assert supervisor_instance.is_healthy()

        # Exécuter des opérations
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']
        await supervisor_instance.run_scan(target, 'quick')

        # La santé devrait rester bonne
        assert supervisor_instance.is_healthy()

        # Vérifier les métriques de santé des modules
        module_stats = supervisor_instance.get_module_stats()

        for module_name, stats in module_stats.items():
            if stats:  # Si le module a des stats
                assert 'total_queries' in stats or 'total_scans' in stats or 'total_scripts_generated' in stats

    def test_error_tracking_integration(self, temp_database):
        """Test de suivi des erreurs en intégration"""
        # Simuler une erreur et vérifier qu'elle est trackée
        try:
            # Opération qui devrait échouer
            temp_database.select('table_inexistante')
        except Exception as e:
            # L'erreur devrait être loggée
            assert str(e) is not None

        # Vérifier que la base de données reste opérationnelle
        test_data = {'scan_id': 'error_test', 'target': '127.0.0.1', 'scan_type': 'test', 'status': 'test'}
        scan_id = temp_database.insert('scans', test_data)
        assert scan_id is not None


# === TESTS DE SÉCURITÉ EN INTÉGRATION ===

class TestSecurityIntegration:
    """Tests de sécurité en environnement d'intégration"""

    @pytest.mark.asyncio
    async def test_script_security_validation_integration(self, integration_config):
        """Test de validation de sécurité des scripts en intégration"""
        if not INTEGRATION_TEST_CONFIG['use_real_openai']:
            pytest.skip("Nécessite OpenAI pour la génération sécurisée")

        generator = Generator(integration_config)

        # Test avec une vulnérabilité qui pourrait générer des scripts dangereux
        dangerous_vulnerability = {
            'name': 'System File Corruption',
            'severity': 'CRITICAL',
            'affected_service': 'Kernel',
            'description': 'Critical system file corruption requiring immediate fix'
        }

        script_result = await generator.generate_fix_script(
            vulnerability_id='SECURITY-TEST-001',
            vulnerability_details=dangerous_vulnerability,
            target_system='ubuntu',
            risk_tolerance='low'  # Tolérance faible = sécurité maximale
        )

        # Vérifications de sécurité
        assert script_result.validation_result.is_safe or script_result.validation_result.execution_recommendation == 'REVIEW_REQUIRED'

        # Vérifier qu'aucune commande extrêmement dangereuse n'est présente
        dangerous_patterns = ['rm -rf /', ':(){ :|:& };:', 'dd if=/dev/zero of=/dev/sda']
        script_content = script_result.main_script.lower()

        for pattern in dangerous_patterns:
            assert pattern not in script_content, f"Commande dangereuse détectée: {pattern}"

        # Le script devrait avoir des mesures de sécurité
        assert 'set -euo pipefail' in script_result.main_script or 'set -e' in script_result.main_script

    def test_input_validation_integration(self, supervisor_instance):
        """Test de validation des entrées en intégration"""
        # Test avec des entrées potentiellement malveillantes
        malicious_inputs = [
            "127.0.0.1; rm -rf /",  # Injection de commande
            "../../etc/passwd",  # Path traversal
            "<script>alert('xss')</script>",  # XSS
            "' OR '1'='1",  # SQL injection
        ]

        for malicious_input in malicious_inputs:
            # Ces entrées devraient être rejetées ou sanitisées
            with pytest.raises(Exception):  # Exception attendue pour entrée invalide
                asyncio.run(supervisor_instance.run_scan(malicious_input, 'quick'))

    @pytest.mark.asyncio
    async def test_privilege_isolation_integration(self, temp_database):
        """Test d'isolation des privilèges"""
        # Vérifier que l'application ne fonctionne pas avec des privilèges excessifs
        import os

        # L'application ne devrait PAS fonctionner en root en production
        if os.getuid() == 0:  # Si on est root
            pytest.skip("Test non applicable en root (déconseillé en production)")

        # Vérifier les permissions des fichiers créés
        test_data = {'scan_id': 'priv_test', 'target': '127.0.0.1', 'scan_type': 'test', 'status': 'test'}
        temp_database.insert('scans', test_data)

        # Le fichier de base de données ne devrait pas être world-writable
        db_path = Path(temp_database.database_path)
        file_mode = db_path.stat().st_mode

        # Vérifier que les permissions sont restrictives (pas 777)
        assert not (file_mode & 0o002), "Base de données world-writable (risque de sécurité)"


# === TESTS DE COMPATIBILITÉ ET PORTABILITÉ ===

class TestCompatibilityIntegration:
    """Tests de compatibilité entre différents environnements"""

    def test_python_version_compatibility(self):
        """Test de compatibilité des versions Python"""
        import sys

        # Vérifier que Python 3.10+ est utilisé
        python_version = sys.version_info
        assert python_version.major == 3
        assert python_version.minor >= 10, f"Python 3.10+ requis, version actuelle: {python_version.major}.{python_version.minor}"

    def test_dependency_compatibility(self):
        """Test de compatibilité des dépendances"""
        # Vérifier que les modules critiques s'importent correctement
        critical_modules = [
            'sqlite3',
            'json',
            'asyncio',
            'pathlib',
            'datetime',
            'subprocess'
        ]

        for module_name in critical_modules:
            try:
                __import__(module_name)
            except ImportError as e:
                pytest.fail(f"Module critique non disponible: {module_name} - {e}")

    def test_os_compatibility(self):
        """Test de compatibilité OS"""
        import platform

        system = platform.system()

        # L'application devrait fonctionner sur Linux et macOS
        supported_systems = ['Linux', 'Darwin']  # Darwin = macOS

        if system not in supported_systems:
            pytest.skip(f"OS non officiellement supporté: {system}")

        # Vérifier la disponibilité des commandes système critiques
        critical_commands = ['nmap']

        for cmd in critical_commands:
            if not subprocess.run(['which', cmd], capture_output=True).returncode == 0:
                pytest.fail(f"Commande critique non trouvée: {cmd}")

    def test_network_interface_compatibility(self):
        """Test de compatibilité des interfaces réseau"""
        # Vérifier que les interfaces réseau de base sont disponibles
        try:
            import socket

            # Test de résolution DNS
            socket.gethostbyname('google.com')

            # Test d'interface localhost
            socket.gethostbyname('localhost')

        except Exception as e:
            pytest.fail(f"Problème de connectivité réseau: {e}")


# === TESTS DE RÉGRESSION ===

class TestRegressionIntegration:
    """Tests de régression pour éviter la réintroduction de bugs"""

    @pytest.mark.asyncio
    async def test_memory_leak_regression(self, supervisor_instance):
        """Test de régression pour les fuites mémoire"""
        import psutil
        import os
        import gc

        process = psutil.Process(os.getpid())

        # Mesurer la mémoire initiale
        gc.collect()  # Force garbage collection
        memory_samples = [process.memory_info().rss]

        # Exécuter plusieurs cycles d'opérations
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        for cycle in range(3):
            await supervisor_instance.run_scan(target, 'quick')

            # Forcer le garbage collection
            gc.collect()

            # Mesurer la mémoire
            memory_samples.append(process.memory_info().rss)

            await asyncio.sleep(1)  # Pause entre les cycles

        # Analyser la tendance de consommation mémoire
        memory_increases = []
        for i in range(1, len(memory_samples)):
            increase = memory_samples[i] - memory_samples[i - 1]
            memory_increases.append(increase)

        # La consommation ne devrait pas augmenter de façon continue
        average_increase = sum(memory_increases) / len(memory_increases)
        max_acceptable_increase = 50 * 1024 * 1024  # 50MB par cycle maximum

        assert average_increase < max_acceptable_increase, f"Possible fuite mémoire: {average_increase / 1024 / 1024:.1f}MB/cycle"

    @pytest.mark.asyncio
    async def test_concurrent_access_regression(self, temp_database):
        """Test de régression pour l'accès concurrent à la base"""
        import threading
        import random

        results = []
        errors = []

        def database_worker(worker_id):
            """Worker qui fait des opérations sur la base"""
            try:
                for i in range(10):
                    # Insérer des données
                    data = {
                        'scan_id': f'worker_{worker_id}_scan_{i}',
                        'target': f'192.168.1.{random.randint(1, 254)}',
                        'scan_type': 'concurrent_test',
                        'status': 'completed'
                    }

                    scan_id = temp_database.insert('scans', data)
                    results.append(scan_id)

                    # Petite pause
                    time.sleep(0.01)

            except Exception as e:
                errors.append(str(e))

        # Lancer plusieurs workers
        threads = []
        for worker_id in range(3):
            thread = threading.Thread(target=database_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()

        # Attendre que tous se terminent
        for thread in threads:
            thread.join()

        # Vérifications
        assert len(errors) == 0, f"Erreurs d'accès concurrent: {errors}"
        assert len(results) == 30  # 3 workers * 10 insertions

        # Vérifier l'intégrité des données
        all_scans = temp_database.select('scans', where={'scan_type': 'concurrent_test'})
        assert len(all_scans) == 30

    @pytest.mark.asyncio
    async def test_workflow_state_consistency_regression(self, supervisor_instance):
        """Test de cohérence d'état des workflows"""
        target = INTEGRATION_TEST_CONFIG['test_targets']['localhost']

        # Démarrer un workflow
        workflow_id = await supervisor_instance.start_workflow(
            WorkflowType.SCAN_ONLY,
            target,
            {'scan_type': 'quick'}
        )

        # Vérifier l'état initial
        initial_status = supervisor_instance.get_workflow_status(workflow_id)
        assert initial_status['status'] in ['pending', 'running']

        # Attendre la fin
        await supervisor_instance.wait_for_workflow(workflow_id, timeout=120)

        # Vérifier l'état final
        final_status = supervisor_instance.get_workflow_status(workflow_id)
        assert final_status['status'] in ['completed', 'failed']

        # L'état ne devrait plus changer
        await asyncio.sleep(2)
        consistent_status = supervisor_instance.get_workflow_status(workflow_id)
        assert consistent_status['status'] == final_status['status']


# === CONFIGURATION DES TESTS ET POINTS D'ENTRÉE ===

def pytest_configure(config):
    """Configuration globale pour pytest"""
    # Marques personnalisées
    config.addinivalue_line(
        "markers", "slow: mark test as slow (may take several minutes)"
    )
    config.addinivalue_line(
        "markers", "network: mark test as requiring network access"
    )
    config.addinivalue_line(
        "markers", "openai: mark test as requiring OpenAI API"
    )


def pytest_collection_modifyitems(config, items):
    """Modifier la collection de tests selon l'environnement"""
    skip_openai = pytest.mark.skip(reason="OpenAI API non configurée")
    skip_slow = pytest.mark.skip(reason="Tests lents désactivés")

    for item in items:
        # Skip des tests OpenAI si pas de clé API
        if "openai" in item.keywords and not INTEGRATION_TEST_CONFIG['use_real_openai']:
            item.add_marker(skip_openai)

        # Skip des tests lents si demandé
        if "slow" in item.keywords and INTEGRATION_TEST_CONFIG['skip_slow_tests']:
            item.add_marker(skip_slow)


# === UTILITAIRES DE TEST ===

def create_test_vulnerability_data(count: int = 1) -> List[Dict[str, Any]]:
    """Crée des données de vulnérabilité pour les tests"""
    vulnerabilities = []

    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    services = ['Apache HTTP Server', 'OpenSSH', 'MySQL', 'Nginx']

    for i in range(count):
        vuln = {
            'name': f'Test Vulnerability {i + 1}',
            'severity': severities[i % len(severities)],
            'cvss_score': 3.0 + (i % 8),  # Score entre 3.0 et 10.0
            'affected_service': services[i % len(services)],
            'affected_port': 80 + (i % 100),
            'description': f'Test vulnerability number {i + 1} for integration testing',
            'cve_ids': [f'CVE-2024-TEST{i + 1:03d}'],
            'detection_method': 'integration-test'
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


async def wait_for_condition(condition_func, timeout: float = 30.0, interval: float = 0.5):
    """Attendre qu'une condition soit vraie"""
    start_time = time.time()

    while time.time() - start_time < timeout:
        if condition_func():
            return True
        await asyncio.sleep(interval)

    return False


def cleanup_test_data():
    """Nettoie les données de test"""
    # Nettoyer les fichiers temporaires
    temp_files = Path('.').glob('test_*.db*')
    for temp_file in temp_files:
        temp_file.unlink(missing_ok=True)

    # Nettoyer les répertoires de test
    test_dirs = ['test_data', 'test_logs', 'test_reports']
    for test_dir in test_dirs:
        test_path = Path(test_dir)
        if test_path.exists():
            import shutil
            shutil.rmtree(test_path)


# === POINT D'ENTRÉE PRINCIPAL ===

if __name__ == "__main__":
    print("Exécution des tests d'intégration pour l'Agent IA de Cybersécurité")
    print(f"Configuration: OpenAI={'✅' if INTEGRATION_TEST_CONFIG['use_real_openai'] else '❌'}")
    print(f"Tests lents: {'❌ Désactivés' if INTEGRATION_TEST_CONFIG['skip_slow_tests'] else '✅ Activés'}")

    # Arguments pytest pour l'intégration
    pytest_args = [
        __file__,
        "-v",
        "--tb=short",
        "-x",  # Arrêter au premier échec
        "--asyncio-mode=auto",
        "--durations=10",  # Afficher les 10 tests les plus lents
    ]

    # Options conditionnelles
    if "--coverage" in sys.argv:
        pytest_args.extend([
            "--cov=src",
            "--cov-report=html:htmlcov_integration",
            "--cov-report=term-missing",
            "--cov-append"  # Ajouter à la couverture existante
        ])

    if "--markers" in sys.argv:
        pytest_args.extend(["-m", sys.argv[sys.argv.index("--markers") + 1]])

    # Nettoyage préalable
    cleanup_test_data()

    try:
        # Lancer les tests
        exit_code = pytest.main(pytest_args)

        if exit_code == 0:
            print("\n✅ Tous les tests d'intégration sont passés!")
            print("\n📊 Couverture d'intégration:")
            print("   - Workflows complets: ✅")
            print("   - Intégration inter-modules: ✅")
            print("   - Scénarios réalistes: ✅")
            print("   - Performance et charge: ✅")
            print("   - Sécurité: ✅")
            print("   - Compatibilité: ✅")
            print("   - Régression: ✅")

        else:
            print("❌ Certains tests d'intégration ont échoué.")
            print("Consultez les détails ci-dessus pour identifier les problèmes.")

    except KeyboardInterrupt:
        print("\n⚠️ Tests interrompus par l'utilisateur")
        exit_code = 1

    finally:
        # Nettoyage final
        cleanup_test_data()

    sys.exit(exit_code)