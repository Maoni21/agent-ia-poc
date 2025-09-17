"""
Tests unitaires pour le module Collector

Tests complets du collecteur de vulnérabilités incluant :
- Scan Nmap avec différents types de scan
- Parsing des résultats de scan
- Détection de vulnérabilités via scripts NSE
- Gestion des erreurs et timeouts
- Import de fichiers de scan
- Validation des cibles

Utilise des mocks pour éviter les scans réseau réels pendant les tests.
"""

import asyncio
import json
import pytest
import unittest
from unittest.mock import Mock, patch, MagicMock, AsyncMock, call
from pathlib import Path
import tempfile
import time
from datetime import datetime

# Import du module à tester
from src.core.collector import (
    Collector,
    ScanResult,
    ServiceInfo,
    VulnerabilityInfo,
    quick_scan,
    create_collector,
    validate_nmap_installation,
    get_supported_scan_types,
    bulk_scan,
    ScanScheduler,
    estimate_scan_duration,
    ScanResultExporter
)
from src.core import CollectorException, CoreErrorCodes


class TestCollector(unittest.TestCase):
    """Tests unitaires pour la classe Collector"""

    def setUp(self):
        """Configuration initiale pour chaque test"""
        # Configuration de test
        self.test_config = {
            'max_concurrent_scans': 2,
            'default_timeout': 30,
            'retry_count': 1,
            'output_format': 'json'
        }

        # Mock des dépendances externes
        with patch('src.core.collector.subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "Nmap version 7.80"

            with patch('src.core.collector.nmap.PortScanner'):
                self.collector = Collector(self.test_config)
                self.collector.is_ready = True

    @patch('src.core.collector.subprocess.run')
    @patch('src.core.collector.nmap.PortScanner')
    def test_initialization_success(self, mock_nmap, mock_subprocess):
        """Test d'initialisation réussie du collector"""
        # Configuration du mock subprocess pour simuler nmap --version
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "Nmap version 7.80"

        # Création du collector
        collector = Collector(self.test_config)

        # Vérifications
        self.assertTrue(collector.is_ready)
        self.assertIsNotNone(collector.nm)
        self.assertEqual(collector.config, self.test_config)

        # Vérifier que nmap --version a été appelé
        mock_subprocess.assert_called_with(
            ['nmap', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )

    @patch('src.core.collector.subprocess.run')
    def test_initialization_nmap_not_found(self, mock_subprocess):
        """Test d'initialisation avec Nmap manquant"""
        # Simuler que nmap n'est pas trouvé
        mock_subprocess.return_value.returncode = 1

        # Vérifier qu'une exception est levée
        with self.assertRaises(CollectorException) as context:
            Collector(self.test_config)

        self.assertEqual(context.exception.error_code, CoreErrorCodes.NMAP_NOT_FOUND)

    def test_validate_target_valid_ip(self):
        """Test de validation d'adresse IP valide"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "8.8.8.8"
        ]

        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(self.collector._validate_target(ip))

    def test_validate_target_valid_domain(self):
        """Test de validation de nom de domaine valide"""
        valid_domains = [
            "example.com",
            "test.example.org",
            "sub.domain.co.uk",
            "localhost"
        ]

        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(self.collector._validate_target(domain))

    def test_validate_target_invalid(self):
        """Test de validation de cibles invalides"""
        invalid_targets = [
            "999.999.999.999",  # IP invalide
            "192.168.1.",  # IP incomplète
            "",  # Vide
            ".",  # Point seul
            "http://example.com"  # URL complète
        ]

        for target in invalid_targets:
            with self.subTest(target=target):
                self.assertFalse(self.collector._validate_target(target))

    def test_prepare_nmap_args_quick_scan(self):
        """Test de préparation des arguments pour scan rapide"""
        args = self.collector._prepare_nmap_args("quick", None)

        self.assertIn("-sV", args)
        self.assertIn("-T4", args)
        self.assertIn("--top-ports 1000", args)
        self.assertIn("--script vuln", args)

    def test_prepare_nmap_args_custom(self):
        """Test de préparation avec arguments personnalisés"""
        custom_args = "-sS -p 22,80,443"
        args = self.collector._prepare_nmap_args("custom", custom_args)

        self.assertEqual(args, custom_args)

    def test_prepare_nmap_args_stealth(self):
        """Test de préparation pour scan furtif"""
        args = self.collector._prepare_nmap_args("stealth", None)

        self.assertIn("-sS", args)
        self.assertIn("-T2", args)
        self.assertIn("--script vuln", args)

    @patch('src.core.collector.asyncio.wait_for')
    @patch.object(Collector, '_execute_nmap_scan')
    async def test_scan_target_success(self, mock_execute, mock_wait_for):
        """Test de scan réussi d'une cible"""
        # Configuration du mock pour simuler un scan réussi
        mock_scan_data = {
            'hosts': ['127.0.0.1'],
            'scan_info': {'nmap': {'scanstats': {'totalhosts': '1'}}},
            'command_line': 'nmap -sV 127.0.0.1'
        }

        mock_execute.return_value = mock_scan_data
        mock_wait_for.return_value = mock_scan_data

        # Configuration du mock pour le parsing
        with patch.object(self.collector, '_parse_nmap_results') as mock_parse:
            mock_parse.return_value = {
                'host_status': 'up',
                'open_ports': [22, 80],
                'services': [
                    ServiceInfo(22, 'tcp', 'ssh', 'OpenSSH 8.0', 'open'),
                    ServiceInfo(80, 'tcp', 'http', 'Apache 2.4', 'open')
                ],
                'vulnerabilities': []
            }

            with patch.object(self.collector, '_enrich_vulnerabilities') as mock_enrich:
                mock_enrich.return_value = []

                with patch.object(self.collector, '_save_scan_result') as mock_save:
                    # Exécuter le scan
                    result = await self.collector.scan_target("127.0.0.1", "quick")

                    # Vérifications
                    self.assertIsInstance(result, ScanResult)
                    self.assertEqual(result.target, "127.0.0.1")
                    self.assertEqual(result.scan_type, "quick")
                    self.assertEqual(result.host_status, "up")
                    self.assertEqual(len(result.open_ports), 2)
                    self.assertIn(22, result.open_ports)
                    self.assertIn(80, result.open_ports)

    async def test_scan_target_invalid_target(self):
        """Test de scan avec cible invalide"""
        with self.assertRaises(CollectorException) as context:
            await self.collector.scan_target("invalid_target", "quick")

        self.assertEqual(context.exception.error_code, CoreErrorCodes.SCAN_TARGET_INVALID)

    async def test_scan_target_timeout(self):
        """Test de gestion du timeout"""
        with patch.object(self.collector, '_execute_nmap_scan') as mock_execute:
            mock_execute.side_effect = asyncio.TimeoutError()

            with self.assertRaises(CollectorException) as context:
                await self.collector.scan_target("127.0.0.1", "quick", timeout=1)

            self.assertEqual(context.exception.error_code, CoreErrorCodes.SCAN_TIMEOUT)

    def test_parse_nmap_results_host_up(self):
        """Test de parsing des résultats Nmap pour un hôte accessible"""
        # Mock de l'objet nmap avec un hôte accessible
        mock_host = Mock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']

        # Mock des ports ouverts
        mock_host.__getitem__.return_value = {
            22: {
                'state': 'open',
                'name': 'ssh',
                'version': '8.0',
                'product': 'OpenSSH'
            },
            80: {
                'state': 'open',
                'name': 'http',
                'version': '',
                'product': 'Apache'
            }
        }
        mock_host['tcp'].keys.return_value = [22, 80]

        self.collector.nm = {'127.0.0.1': mock_host}

        scan_data = {'hosts': ['127.0.0.1']}
        result = self.collector._parse_nmap_results(scan_data, '127.0.0.1')

        # Vérifications
        self.assertEqual(result['host_status'], 'up')
        self.assertEqual(len(result['open_ports']), 2)
        self.assertIn(22, result['open_ports'])
        self.assertIn(80, result['open_ports'])
        self.assertEqual(len(result['services']), 2)

    def test_parse_nmap_results_host_down(self):
        """Test de parsing pour un hôte inaccessible"""
        scan_data = {'hosts': []}
        result = self.collector._parse_nmap_results(scan_data, '192.168.1.999')

        self.assertEqual(result['host_status'], 'down')
        self.assertEqual(len(result['open_ports']), 0)
        self.assertEqual(len(result['services']), 0)
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_extract_vulnerabilities_from_scripts(self):
        """Test d'extraction des vulnérabilités depuis les scripts NSE"""
        # Mock d'un hôte avec scripts de vulnérabilités
        mock_host = Mock()
        mock_host.all_protocols.return_value = ['tcp']

        # Mock d'un port avec script de vulnérabilité
        mock_host['tcp'].keys.return_value = [443]
        mock_host['tcp'].__getitem__.return_value = {
            'state': 'open',
            'name': 'https',
            'script': {
                'ssl-heartbleed': 'VULNERABLE: Heartbleed Bug CVE-2014-0160',
                'ssl-poodle': 'VULNERABLE: POODLE CVE-2014-3566'
            }
        }

        vulnerabilities = self.collector._extract_vulnerabilities_from_scripts(mock_host)

        # Vérifications
        self.assertEqual(len(vulnerabilities), 2)

        # Vérifier Heartbleed
        heartbleed = next((v for v in vulnerabilities if 'Heartbleed' in v.name), None)
        self.assertIsNotNone(heartbleed)
        self.assertEqual(heartbleed.vulnerability_id, 'CVE-2014-0160')
        self.assertEqual(heartbleed.severity, 'HIGH')

        # Vérifier POODLE
        poodle = next((v for v in vulnerabilities if 'POODLE' in v.name), None)
        self.assertIsNotNone(poodle)
        self.assertEqual(poodle.vulnerability_id, 'CVE-2014-3566')

    def test_parse_script_vulnerabilities_heartbleed(self):
        """Test de parsing spécifique pour Heartbleed"""
        script_output = "VULNERABLE: The Heartbleed Bug (CVE-2014-0160)"

        vulnerabilities = self.collector._parse_script_vulnerabilities(
            'ssl-heartbleed', script_output, 443, 'https'
        )

        self.assertEqual(len(vulnerabilities), 1)
        vuln = vulnerabilities[0]
        self.assertEqual(vuln.vulnerability_id, 'CVE-2014-0160')
        self.assertEqual(vuln.name, 'OpenSSL Heartbleed')
        self.assertEqual(vuln.severity, 'HIGH')
        self.assertEqual(vuln.affected_port, 443)

    def test_parse_script_vulnerabilities_generic_cve(self):
        """Test de parsing générique pour CVE"""
        script_output = "Found vulnerability CVE-2021-12345 in service"

        vulnerabilities = self.collector._parse_script_vulnerabilities(
            'custom-script', script_output, 80, 'http'
        )

        self.assertEqual(len(vulnerabilities), 1)
        vuln = vulnerabilities[0]
        self.assertEqual(vuln.vulnerability_id, 'CVE-2021-12345')
        self.assertEqual(vuln.affected_port, 80)
        self.assertIn('CVE-2021-12345', vuln.cve_ids)

    def test_estimate_severity(self):
        """Test d'estimation de la gravité"""
        test_cases = [
            ("Remote code execution detected", "CRITICAL"),
            ("Buffer overflow vulnerability", "CRITICAL"),
            ("Privilege escalation possible", "HIGH"),
            ("Information disclosure", "MEDIUM"),
            ("Minor configuration issue", "LOW")
        ]

        for output, expected_severity in test_cases:
            with self.subTest(output=output):
                severity = self.collector._estimate_severity(output)
                self.assertEqual(severity, expected_severity)

    def test_enrich_vulnerabilities(self):
        """Test d'enrichissement des vulnérabilités"""
        # Créer des vulnérabilités de test
        vulnerabilities = [
            VulnerabilityInfo(
                vulnerability_id="CVE-2014-0160",
                name="Vulnerability CVE-2014-0160",
                severity="HIGH",
                cvss_score=None,
                description="Test vulnerability",
                affected_service="openssl",
                affected_port=443,
                cve_ids=["CVE-2014-0160"],
                references=[],
                detection_method="script",
                confidence="HIGH"
            )
        ]

        # Mock de la base de vulnérabilités
        self.collector.vulnerability_db = {
            'known_vulnerabilities': [
                {
                    'id': 'CVE-2014-0160',
                    'name': 'OpenSSL Heartbleed',
                    'cvss_score': 7.5,
                    'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160']
                }
            ]
        }

        enriched = self.collector._enrich_vulnerabilities(vulnerabilities)

        # Vérifications
        self.assertEqual(len(enriched), 1)
        vuln = enriched[0]
        self.assertEqual(vuln.name, "OpenSSL Heartbleed")
        self.assertEqual(vuln.cvss_score, 7.5)
        self.assertIn('https://cve.mitre.org', vuln.references[0])

    async def test_import_scan_results_nmap_xml(self):
        """Test d'import de résultats Nmap XML"""
        # Créer un fichier XML de test
        xml_content = """<?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -sV 127.0.0.1">
            <host>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" version="8.0"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            temp_file = f.name

        try:
            # Mock de la fonction de parsing XML
            with patch.object(self.collector, '_parse_nmap_xml') as mock_parse:
                expected_result = ScanResult(
                    scan_id="imported_scan",
                    target="127.0.0.1",
                    scan_type="imported",
                    started_at=datetime.utcnow(),
                    completed_at=datetime.utcnow(),
                    duration=0.0,
                    host_status="up",
                    open_ports=[22],
                    services=[],
                    vulnerabilities=[],
                    scan_parameters={}
                )
                mock_parse.return_value = expected_result

                # Tester l'import
                result = await self.collector.import_scan_results(temp_file, "nmap_xml")

                self.assertIsInstance(result, ScanResult)
                self.assertEqual(result.target, "127.0.0.1")

        finally:
            Path(temp_file).unlink(missing_ok=True)

    def test_get_stats(self):
        """Test de récupération des statistiques"""
        # Modifier quelques statistiques
        self.collector.stats['total_scans'] = 5
        self.collector.stats['successful_scans'] = 4
        self.collector.stats['failed_scans'] = 1
        self.collector.stats['total_vulnerabilities_found'] = 10

        stats = self.collector.get_stats()

        # Vérifications
        self.assertEqual(stats['total_scans'], 5)
        self.assertEqual(stats['successful_scans'], 4)
        self.assertEqual(stats['failed_scans'], 1)
        self.assertEqual(stats['total_vulnerabilities_found'], 10)
        self.assertIn('average_scan_time', stats)

    def test_is_healthy(self):
        """Test de vérification de santé"""
        with patch('src.core.collector.subprocess.run') as mock_subprocess:
            # Simuler nmap fonctionnel
            mock_subprocess.return_value.returncode = 0

            self.assertTrue(self.collector.is_healthy())

            # Simuler nmap défaillant
            mock_subprocess.return_value.returncode = 1

            self.assertFalse(self.collector.is_healthy())


class TestCollectorUtilityFunctions(unittest.TestCase):
    """Tests des fonctions utilitaires du module collector"""

    @patch('src.core.collector.Collector')
    async def test_quick_scan_success(self, mock_collector_class):
        """Test de la fonction quick_scan"""
        # Mock du collector
        mock_collector = Mock()
        mock_result = ScanResult(
            scan_id="quick_001",
            target="example.com",
            scan_type="quick",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            duration=30.0,
            host_status="up",
            open_ports=[80, 443],
            services=[],
            vulnerabilities=[],
            scan_parameters={}
        )

        mock_collector.scan_target = AsyncMock(return_value=mock_result)
        mock_collector_class.return_value = mock_collector

        # Exécuter quick_scan
        result = await quick_scan("example.com", "quick")

        # Vérifications
        self.assertIn('target', result)
        self.assertEqual(result['target'], 'example.com')
        mock_collector.scan_target.assert_called_once_with("example.com", "quick")

    def test_create_collector(self):
        """Test de la factory create_collector"""
        config = {'test_key': 'test_value'}

        with patch('src.core.collector.Collector') as mock_collector_class:
            create_collector(config)
            mock_collector_class.assert_called_once_with(config)

    @patch('src.core.collector.subprocess.run')
    def test_validate_nmap_installation_success(self, mock_subprocess):
        """Test de validation d'installation Nmap réussie"""
        # Mock subprocess pour simuler nmap fonctionnel
        mock_subprocess.side_effect = [
            # nmap --version
            Mock(returncode=0, stdout="Nmap version 7.80"),
            # nmap --script-help vuln
            Mock(returncode=0, stdout="vuln scripts available"),
            # nmap -sn 127.0.0.1 (test permissions)
            Mock(returncode=0, stdout="Host is up")
        ]

        result = validate_nmap_installation()

        # Vérifications
        self.assertTrue(result['valid'])
        self.assertEqual(result['version'], '7.80')
        self.assertTrue(result['has_vuln_scripts'])
        self.assertTrue(result['has_permissions'])
        self.assertEqual(len(result['warnings']), 0)

    @patch('src.core.collector.subprocess.run')
    def test_validate_nmap_installation_missing(self, mock_subprocess):
        """Test avec Nmap manquant"""
        mock_subprocess.return_value.returncode = 1

        result = validate_nmap_installation()

        self.assertFalse(result['valid'])
        self.assertIn('error', result)

    def test_get_supported_scan_types(self):
        """Test de récupération des types de scan supportés"""
        scan_types = get_supported_scan_types()

        # Vérifications
        self.assertIn('quick', scan_types)
        self.assertIn('full', scan_types)
        self.assertIn('stealth', scan_types)
        self.assertIn('aggressive', scan_types)

        # Vérifier la structure des données
        for scan_type, details in scan_types.items():
            self.assertIn('name', details)
            self.assertIn('description', details)
            self.assertIn('estimated_time', details)
            self.assertIn('nmap_args', details)
            self.assertIn('use_cases', details)

    def test_estimate_scan_duration(self):
        """Test d'estimation de durée de scan"""
        # Test pour différents types de scan
        duration_quick = estimate_scan_duration("192.168.1.1", "quick")
        duration_full = estimate_scan_duration("192.168.1.1", "full")
        duration_stealth = estimate_scan_duration("192.168.1.1", "stealth")

        # Vérifications
        self.assertIsInstance(duration_quick, int)
        self.assertIsInstance(duration_full, int)
        self.assertIsInstance(duration_stealth, int)

        # Le scan stealth devrait être le plus long
        self.assertLess(duration_quick, duration_full)
        self.assertLess(duration_full, duration_stealth)

    @patch('src.core.collector.Collector')
    async def test_bulk_scan(self, mock_collector_class):
        """Test de scan en lot"""
        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        # Mock du collector
        mock_collector = Mock()

        def mock_scan_target(target, scan_type, progress_callback=None):
            return ScanResult(
                scan_id=f"scan_{target}",
                target=target,
                scan_type=scan_type,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                duration=10.0,
                host_status="up",
                open_ports=[80],
                services=[],
                vulnerabilities=[],
                scan_parameters={}
            )

        mock_collector.scan_target = AsyncMock(side_effect=mock_scan_target)
        mock_collector_class.return_value = mock_collector

        # Exécuter bulk_scan
        results = await bulk_scan(targets, "quick", max_concurrent=2)

        # Vérifications
        self.assertEqual(len(results), 3)
        for target in targets:
            self.assertIn(target, results)
            self.assertIsInstance(results[target], ScanResult)


class TestScanScheduler(unittest.TestCase):
    """Tests du planificateur de scans"""

    def setUp(self):
        """Configuration du planificateur"""
        with patch('src.core.collector.Collector') as mock_collector_class:
            self.mock_collector = Mock()
            mock_collector_class.return_value = self.mock_collector

            self.scheduler = ScanScheduler(self.mock_collector)

    def test_add_scheduled_scan(self):
        """Test d'ajout d'un scan programmé"""
        self.scheduler.add_scheduled_scan(
            "daily_scan",
            "192.168.1.1",
            "quick",
            24,  # 24 heures
            lambda result: print("Scan terminé")
        )

        # Vérifications
        self.assertIn("daily_scan", self.scheduler.scheduled_scans)
        scan_config = self.scheduler.scheduled_scans["daily_scan"]
        self.assertEqual(scan_config["target"], "192.168.1.1")
        self.assertEqual(scan_config["scan_type"], "quick")
        self.assertEqual(scan_config["interval_hours"], 24)

    def test_remove_scheduled_scan(self):
        """Test de suppression d'un scan programmé"""
        # Ajouter puis supprimer
        self.scheduler.add_scheduled_scan("test_scan", "127.0.0.1", "quick", 1)
        self.scheduler.remove_scheduled_scan("test_scan")

        # Vérification
        self.assertNotIn("test_scan", self.scheduler.scheduled_scans)

    async def test_execute_scheduled_scan(self):
        """Test d'exécution d'un scan programmé"""
        # Mock du résultat de scan
        mock_result = ScanResult(
            scan_id="scheduled_001",
            target="127.0.0.1",
            scan_type="quick",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            duration=15.0,
            host_status="up",
            open_ports=[22],
            services=[],
            vulnerabilities=[],
            scan_parameters={}
        )

        self.mock_collector.scan_target = AsyncMock(return_value=mock_result)

        # Configuration d'un scan avec callback
        callback_called = []

        def test_callback(result):
            callback_called.append(result)

        scan_config = {
            "target": "127.0.0.1",
            "scan_type": "quick",
            "callback": test_callback,
            "last_run": None
        }

        # Exécuter le scan programmé
        await self.scheduler._execute_scheduled_scan("test_scan", scan_config)

        # Vérifications
        self.mock_collector.scan_target.assert_called_once_with(
            target="127.0.0.1",
            scan_type="quick"
        )
        self.assertEqual(len(callback_called), 1)
        self.assertEqual(callback_called[0], mock_result)
        self.assertIsNotNone(scan_config["last_run"])


class TestScanResultExporter(unittest.TestCase):
    """Tests de l'exporteur de résultats"""

    def setUp(self):
        """Création d'un résultat de scan pour les tests"""
        self.scan_result = ScanResult(
            scan_id="export_test_001",
            target="example.com",
            scan_type="full",
            started_at=datetime(2025, 1, 15, 10, 30, 0),
            completed_at=datetime(2025, 1, 15, 10, 35, 0),
            duration=300.0,
            host_status="up",
            open_ports=[22, 80, 443],
            services=[
                ServiceInfo(22, 'tcp', 'ssh', 'OpenSSH 8.0', 'open'),
                ServiceInfo(80, 'tcp', 'http', 'Apache 2.4', 'open'),
                ServiceInfo(443, 'tcp', 'https', 'Apache 2.4', 'open')
            ],
            vulnerabilities=[
                VulnerabilityInfo(
                    vulnerability_id="CVE-2024-12345",
                    name="Test Vulnerability",
                    severity="HIGH",
                    cvss_score=7.5,
                    description="Test vulnerability description",
                    affected_service="Apache",
                    affected_port=80,
                    cve_ids=["CVE-2024-12345"],
                    references=["https://example.com/vuln"],
                    detection_method="nmap-script",
                    confidence="HIGH"
                )
            ],
            scan_parameters={"scan_type": "full"}
        )

    def test_export_to_json(self):
        """Test d'export en JSON"""
        json_output = ScanResultExporter.to_json(self.scan_result)

        # Vérifier que c'est du JSON valide
        data = json.loads(json_output)

        # Vérifications
        self.assertEqual(data['scan_id'], 'export_test_001')
        self.assertEqual(data['target'], 'example.com')
        self.assertEqual(len(data['open_ports']), 3)
        self.assertEqual(len(data['vulnerabilities']), 1)

    def test_export_to_csv(self):
        """Test d'export en CSV"""
        csv_output = ScanResultExporter.to_csv(self.scan_result)

        # Vérifier les en-têtes
        lines = csv_output.strip().split('\n')
        headers = lines[0].split(',')

        expected_headers = [
            'Target', 'Vulnerability ID', 'Name', 'Severity', 'CVSS Score',
            'Affected Service', 'Port', 'CVE IDs', 'Detection Method'
        ]

        self.assertEqual(len(headers), len(expected_headers))

        # Vérifier les données
        self.assertEqual(len(lines), 2)  # Headers + 1 vulnerability
        data_line = lines[1].split(',')
        self.assertEqual(data_line[0], 'example.com')
        self.assertEqual(data_line[1], 'CVE-2024-12345')
        self.assertEqual(data_line[3], 'HIGH')

    def test_export_to_html(self):
        """Test d'export en HTML"""
        html_output = ScanResultExporter.to_html(self.scan_result)

        # Vérifications HTML
        self.assertIn('<!DOCTYPE html>', html_output)
        self.assertIn('<title>Rapport de Scan - example.com</title>', html_output)
        self.assertIn('example.com', html_output)
        self.assertIn('CVE-2024-12345', html_output)
        self.assertIn('Test Vulnerability', html_output)
        self.assertIn('class="high"', html_output)  # CSS class pour HIGH severity


class TestIntegrationCollector(unittest.TestCase):
    """Tests d'intégration pour le Collector"""

    def setUp(self):
        """Configuration pour tests d'intégration"""
        self.test_config = {
            'max_concurrent_scans': 1,
            'default_timeout': 10,
            'retry_count': 1
        }

    @patch('src.core.collector.subprocess.run')
    @patch('src.core.collector.nmap.PortScanner')
    def test_full_scan_workflow(self, mock_nmap, mock_subprocess):
        """Test du workflow complet de scan"""
        # Mock de l'initialisation Nmap
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "Nmap version 7.80"

        # Mock du scanner Nmap
        mock_nm = Mock()
        mock_nmap.return_value = mock_nm

        # Mock des résultats de scan
        mock_nm.all_hosts.return_value = ['127.0.0.1']
        mock_nm.scaninfo.return_value = {'tcp': {'method': 'syn', 'services': '22,80,443'}}
        mock_nm.command_line.return_value = 'nmap -sV 127.0.0.1'

        # Mock de l'hôte scanné
        mock_host = Mock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']

        # Mock des ports avec vulnérabilité
        mock_host['tcp'].keys.return_value = [443]
        mock_host['tcp'].__getitem__.return_value = {
            'state': 'open',
            'name': 'https',
            'version': '1.1',
            'product': 'OpenSSL',
            'script': {
                'ssl-heartbleed': 'VULNERABLE: Heartbleed Bug CVE-2014-0160'
            }
        }

        mock_nm.__getitem__.return_value = mock_host

        # Créer le collector et simuler un scan
        collector = Collector(self.test_config)
        collector.nm = mock_nm

        # Simuler _execute_nmap_scan
        async def mock_execute_nmap_scan(target, args, timeout, callback=None):
            if callback:
                callback(50)  # Progression à 50%
                callback(100)  # Progression à 100%

            return {
                'hosts': ['127.0.0.1'],
                'scan_info': {'tcp': {'method': 'syn'}},
                'command_line': 'nmap -sV 127.0.0.1'
            }

        collector._execute_nmap_scan = mock_execute_nmap_scan

        # Test du scan complet
        async def run_test():
            progress_updates = []

            def progress_callback(progress):
                progress_updates.append(progress)

            with patch.object(collector, '_save_scan_result') as mock_save:
                result = await collector.scan_target(
                    "127.0.0.1",
                    "full",
                    timeout=30,
                    progress_callback=progress_callback
                )

                # Vérifications
                self.assertIsInstance(result, ScanResult)
                self.assertEqual(result.target, "127.0.0.1")
                self.assertEqual(result.scan_type, "full")
                self.assertEqual(result.host_status, "up")

                # Vérifier qu'une vulnérabilité a été détectée
                self.assertGreater(len(result.vulnerabilities), 0)
                heartbleed = next((v for v in result.vulnerabilities if 'Heartbleed' in v.name), None)
                self.assertIsNotNone(heartbleed)

                # Vérifier les callbacks de progression
                self.assertGreater(len(progress_updates), 0)
                self.assertIn(100, progress_updates)  # Progression finale

                # Vérifier la sauvegarde
                mock_save.assert_called_once()

        # Exécuter le test
        asyncio.run(run_test())

    @patch('src.core.collector.subprocess.run')
    @patch('src.core.collector.nmap.PortScanner')
    def test_error_handling_nmap_failure(self, mock_nmap, mock_subprocess):
        """Test de gestion d'erreur lors d'un échec Nmap"""
        # Mock de l'initialisation réussie
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "Nmap version 7.80"

        collector = Collector(self.test_config)

        # Simuler un échec d'exécution Nmap
        async def failing_execute(target, args, timeout, callback=None):
            raise Exception("Nmap execution failed")

        collector._execute_nmap_scan = failing_execute

        # Test de gestion d'erreur
        async def run_error_test():
            with self.assertRaises(CollectorException):
                await collector.scan_target("127.0.0.1", "quick")

            # Vérifier que les stats d'erreur sont mises à jour
            stats = collector.get_stats()
            self.assertEqual(stats['failed_scans'], 1)

        asyncio.run(run_error_test())

    def test_vulnerability_database_loading(self):
        """Test du chargement de la base de vulnérabilités"""
        # Créer un fichier de base de vulnérabilités temporaire
        vuln_db_data = {
            "known_vulnerabilities": [
                {
                    "id": "CVE-2014-0160",
                    "name": "OpenSSL Heartbleed",
                    "cvss_score": 7.5,
                    "severity": "HIGH"
                }
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(vuln_db_data, f)
            temp_file = f.name

        try:
            with patch('src.core.collector.VULNERABILITY_DB_PATH', temp_file):
                with patch('src.core.collector.subprocess.run') as mock_subprocess:
                    mock_subprocess.return_value.returncode = 0
                    mock_subprocess.return_value.stdout = "Nmap version 7.80"

                    collector = Collector()

                    # Vérifier que la base de vulnérabilités a été chargée
                    self.assertIn('known_vulnerabilities', collector.vulnerability_db)
                    vulns = collector.vulnerability_db['known_vulnerabilities']
                    self.assertEqual(len(vulns), 1)
                    self.assertEqual(vulns[0]['id'], 'CVE-2014-0160')

        finally:
            Path(temp_file).unlink(missing_ok=True)


class TestCollectorPerformance(unittest.TestCase):
    """Tests de performance du Collector"""

    def setUp(self):
        """Configuration pour tests de performance"""
        with patch('src.core.collector.subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "Nmap version 7.80"

            with patch('src.core.collector.nmap.PortScanner'):
                self.collector = Collector()

    def test_stats_update_performance(self):
        """Test de performance des mises à jour de statistiques"""
        import time

        # Mesurer le temps de 1000 mises à jour de stats
        start_time = time.time()

        for i in range(1000):
            self.collector._update_stats(True, 1.0, 5)

        end_time = time.time()
        duration = end_time - start_time

        # Les mises à jour doivent être très rapides (< 0.1s pour 1000 updates)
        self.assertLess(duration, 0.1, "Stats updates too slow")

    def test_vulnerability_parsing_performance(self):
        """Test de performance du parsing de vulnérabilités"""
        import time

        # Créer un script output volumineux
        large_script_output = "CVE-2021-" + "\nCVE-2021-".join([f"{i:05d}" for i in range(1000)])

        start_time = time.time()

        # Parser les vulnérabilités
        vulnerabilities = self.collector._parse_script_vulnerabilities(
            'vuln-script', large_script_output, 80, 'http'
        )

        end_time = time.time()
        duration = end_time - start_time

        # Le parsing doit être raisonnable (< 1s pour 1000 CVE)
        self.assertLess(duration, 1.0, "Vulnerability parsing too slow")
        self.assertEqual(len(vulnerabilities), 1000)

    async def test_concurrent_scans_performance(self):
        """Test de performance des scans concurrents"""

        # Mock pour simuler des scans rapides
        async def fast_scan(target, scan_type, **kwargs):
            await asyncio.sleep(0.01)  # 10ms de simulation
            return ScanResult(
                scan_id=f"perf_{target}",
                target=target,
                scan_type=scan_type,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                duration=0.01,
                host_status="up",
                open_ports=[80],
                services=[],
                vulnerabilities=[],
                scan_parameters={}
            )

        self.collector.scan_target = fast_scan

        # Tester 10 scans concurrents
        targets = [f"192.168.1.{i}" for i in range(1, 11)]

        start_time = time.time()

        results = await bulk_scan(targets, "quick", max_concurrent=5)

        end_time = time.time()
        duration = end_time - start_time

        # Les scans concurrents doivent être plus rapides que séquentiels
        # (10 scans * 10ms = 100ms séquentiel, concurrent devrait être ~20ms)
        self.assertLess(duration, 0.1, "Concurrent scans not fast enough")
        self.assertEqual(len(results), 10)


# === TESTS D'ERREUR ET CAS LIMITES ===

class TestCollectorEdgeCases(unittest.TestCase):
    """Tests des cas limites et d'erreurs"""

    def setUp(self):
        """Configuration pour tests de cas limites"""
        with patch('src.core.collector.subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "Nmap version 7.80"

            with patch('src.core.collector.nmap.PortScanner'):
                self.collector = Collector()

    def test_empty_scan_results(self):
        """Test avec résultats de scan vides"""
        # Simuler un scan sans résultats
        scan_data = {'hosts': []}
        result = self.collector._parse_nmap_results(scan_data, "192.168.1.999")

        self.assertEqual(result['host_status'], 'down')
        self.assertEqual(len(result['open_ports']), 0)
        self.assertEqual(len(result['services']), 0)
        self.assertEqual(len(result['vulnerabilities']), 0)

    def test_malformed_script_output(self):
        """Test avec sortie de script malformée"""
        malformed_outputs = [
            "",  # Vide
            "No vulnerability found",  # Pas de CVE
            "RANDOMTEXT-2021-99999",  # CVE invalide
            "CVE-INVALID-FORMAT",  # Format CVE invalide
            None  # None
        ]

        for output in malformed_outputs:
            with self.subTest(output=output):
                if output is None:
                    continue
                vulnerabilities = self.collector._parse_script_vulnerabilities(
                    'test-script', output, 80, 'http'
                )
                # Ne devrait pas lever d'exception, mais peut être vide
                self.assertIsInstance(vulnerabilities, list)

    def test_very_large_port_list(self):
        """Test avec une liste de ports très importante"""
        # Simuler 65535 ports (cas extrême)
        large_port_list = list(range(1, 65536))

        mock_host = Mock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']
        mock_host['tcp'].keys.return_value = large_port_list

        # Mock de tous les ports comme fermés
        def mock_port_info(port):
            return {'state': 'closed', 'name': 'unknown', 'version': ''}

        mock_host['tcp'].__getitem__ = mock_port_info

        # Ne devrait pas lever d'exception ou être trop lent
        start_time = time.time()

        services = []
        open_ports = []

        for protocol in mock_host.all_protocols():
            ports = mock_host[protocol].keys()
            for port in ports:
                port_info = mock_host[protocol][port]
                if port_info['state'] == 'open':
                    open_ports.append(port)
                    # Limiter pour éviter la surcharge mémoire
                    if len(services) < 1000:
                        services.append(ServiceInfo(
                            port, protocol, port_info['name'],
                            port_info['version'], port_info['state']
                        ))

        duration = time.time() - start_time

        # Doit traiter en moins de 5 secondes
        self.assertLess(duration, 5.0, "Large port processing too slow")

    def test_unicode_in_scan_results(self):
        """Test avec caractères Unicode dans les résultats"""
        unicode_script_output = """
        Vulnerability found: Тест vulnérabilité avec émojis 🔒
        CVE-2021-12345: Descripción en español
        影響を受けるサービス: Apache
        """

        # Ne devrait pas lever d'exception
        vulnerabilities = self.collector._parse_script_vulnerabilities(
            'unicode-script', unicode_script_output, 443, 'https'
        )

        self.assertIsInstance(vulnerabilities, list)
        if vulnerabilities:
            # Vérifier que l'Unicode est préservé
            vuln = vulnerabilities[0]
            self.assertIsInstance(vuln.description, str)

    async def test_scan_interruption(self):
        """Test d'interruption de scan"""

        # Simuler un scan qui s'interrompt
        async def interrupted_scan(target, args, timeout, callback=None):
            if callback:
                callback(25)  # Progression à 25%
            await asyncio.sleep(0.1)
            raise KeyboardInterrupt("Scan interrupted by user")

        self.collector._execute_nmap_scan = interrupted_scan

        # Le scan doit gérer l'interruption proprement
        with self.assertRaises(CollectorException):
            await self.collector.scan_target("127.0.0.1", "quick")

    def test_memory_usage_large_results(self):
        """Test d'utilisation mémoire avec de gros résultats"""
        import sys

        # Créer un très grand nombre de vulnérabilités fictives
        large_vulnerability_list = []
        for i in range(10000):
            vuln = VulnerabilityInfo(
                vulnerability_id=f"CVE-2021-{i:05d}",
                name=f"Test Vulnerability {i}",
                severity="MEDIUM",
                cvss_score=5.0,
                description=f"Description for vulnerability {i}" * 10,  # Grande description
                affected_service="test-service",
                affected_port=80 + (i % 1000),
                cve_ids=[f"CVE-2021-{i:05d}"],
                references=[f"https://example.com/vuln{i}"],
                detection_method="test",
                confidence="HIGH"
            )
            large_vulnerability_list.append(vuln)

        # Vérifier que l'enrichissement ne consomme pas trop de mémoire
        # (test basique - mesure la taille de l'objet)
        enriched = self.collector._enrich_vulnerabilities(large_vulnerability_list)

        # La liste enrichie ne devrait pas être significativement plus grande
        self.assertEqual(len(enriched), len(large_vulnerability_list))

        # Test approximatif de taille mémoire
        original_size = sys.getsizeof(large_vulnerability_list)
        enriched_size = sys.getsizeof(enriched)

        # Ne devrait pas doubler la taille mémoire
        self.assertLess(enriched_size, original_size * 2)


# === FIXTURES ET HELPERS POUR LES TESTS ===

class MockNmapResults:
    """Helper pour créer des résultats Nmap fictifs"""

    @staticmethod
    def create_basic_host(ip="127.0.0.1", state="up"):
        """Crée un hôte basique pour les tests"""
        mock_host = Mock()
        mock_host.state.return_value = state
        mock_host.all_protocols.return_value = ['tcp']
        mock_host['tcp'].keys.return_value = []
        return mock_host

    @staticmethod
    def create_host_with_ports(ip="127.0.0.1", ports_config=None):
        """Crée un hôte avec ports configurés"""
        if ports_config is None:
            ports_config = {
                22: {'state': 'open', 'name': 'ssh', 'version': '8.0', 'product': 'OpenSSH'},
                80: {'state': 'open', 'name': 'http', 'version': '2.4', 'product': 'Apache'}
            }

        mock_host = Mock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']
        mock_host['tcp'].keys.return_value = list(ports_config.keys())

        def port_getter(port):
            return ports_config.get(port, {'state': 'closed'})

        mock_host['tcp'].__getitem__ = port_getter
        return mock_host

    @staticmethod
    def create_vulnerable_host(ip="127.0.0.1", vulnerabilities=None):
        """Crée un hôte avec vulnérabilités"""
        if vulnerabilities is None:
            vulnerabilities = {
                443: {
                    'state': 'open',
                    'name': 'https',
                    'version': '1.1',
                    'product': 'OpenSSL',
                    'script': {
                        'ssl-heartbleed': 'VULNERABLE: Heartbleed Bug CVE-2014-0160'
                    }
                }
            }

        mock_host = Mock()
        mock_host.state.return_value = 'up'
        mock_host.all_protocols.return_value = ['tcp']
        mock_host['tcp'].keys.return_value = list(vulnerabilities.keys())

        def port_getter(port):
            return vulnerabilities.get(port, {'state': 'closed'})

        mock_host['tcp'].__getitem__ = port_getter
        return mock_host


# === MAIN POUR EXÉCUTION DES TESTS ===

if __name__ == '__main__':
    # Configuration des tests
    unittest.TestLoader.testMethodPrefix = 'test_'

    # Créer la suite de tests
    test_suite = unittest.TestSuite()

    # Ajouter toutes les classes de test
    test_classes = [
        TestCollector,
        TestCollectorUtilityFunctions,
        TestScanScheduler,
        TestScanResultExporter,
        TestIntegrationCollector,
        TestCollectorPerformance,
        TestCollectorEdgeCases
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Exécuter les tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        buffer=True,  # Capturer stdout/stderr
        failfast=False  # Continuer après échec
    )

    print("=" * 70)
    print("TESTS UNITAIRES DU MODULE COLLECTOR")
    print("=" * 70)

    result = runner.run(test_suite)

    # Résumé des résultats
    print("\n" + "=" * 70)
    print("RÉSUMÉ DES TESTS")
    print("=" * 70)
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")

    if result.failures:
        print("\nÉchecs:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")

    if result.errors:
        print("\nErreurs:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.split('Error:')[-1].strip()}")

    # Code de sortie
    exit_code = 0 if result.wasSuccessful() else 1
    print(f"\nTests {'réussis' if exit_code == 0 else 'échoués'} !")

    import sys

    sys.exit(exit_code)