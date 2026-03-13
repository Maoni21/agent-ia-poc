"""
Module AnsibleGenerator pour l'Agent IA de Cybersécurité
Génère des playbooks Ansible professionnels au lieu de scripts bash
"""

import asyncio
import json
import logging
import time
import uuid
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

from config import get_config
from src.utils.logger import setup_logger
from src.database.database import Database
from .exceptions import GeneratorException, CoreErrorCodes

logger = setup_logger(__name__)


# === MODÈLES DE DONNÉES ===

@dataclass
class AnsiblePlaybookResult:
    """Résultat de génération d'un playbook Ansible"""
    playbook_id: str
    vulnerability_id: str
    target_system: str
    playbook_yaml: str
    inventory_template: str
    variables: Dict[str, Any]
    validation_status: str
    risk_level: str
    estimated_execution_time: Optional[int]
    warnings: List[str]
    prerequisites: List[str]
    rollback_playbook: Optional[str]
    generated_at: str
    ai_model_used: str
    confidence_score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# === CLASSE PRINCIPALE ===

class AnsibleGenerator:
    """Générateur de playbooks Ansible professionnels"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.db = Database()
        self.is_ready = False
        self.stats = {
            "total_playbooks": 0,
            "successful_playbooks": 0,
            "failed_playbooks": 0,
            "average_generation_time": 0.0
        }

        # Détection du provider
        self.ai_provider = self.config.get('ai_provider', 'anthropic')

        # Initialisation du client IA selon le provider
        if self.ai_provider == 'openai':
            self._init_openai()
        elif self.ai_provider == 'anthropic':
            self._init_anthropic()
        else:
            raise GeneratorException(f"Provider IA non supporté: {self.ai_provider}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_openai(self):
        """Initialise le client OpenAI"""
        try:
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                api_key=self.config.get('openai_api_key'),
                timeout=self.config.get('openai_timeout', 120)
            )
            self.model = self.config.get('openai_model', 'gpt-4')
            self.max_tokens = self.config.get('openai_max_tokens', 3000)
            self.temperature = self.config.get('openai_temperature', 0.3)
            self.is_ready = True
            logger.info("Client OpenAI initialisé pour AnsibleGenerator")
        except Exception as e:
            logger.error(f"Erreur initialisation OpenAI: {e}")
            raise GeneratorException(f"Impossible d'initialiser OpenAI: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    def _init_anthropic(self):
        """Initialise le client Anthropic/Claude"""
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(
                api_key=self.config.get('anthropic_api_key')
            )
            self.model = self.config.get('anthropic_model', 'claude-sonnet-4-20250514')
            self.max_tokens = self.config.get('anthropic_max_tokens', 3000)
            self.temperature = self.config.get('anthropic_temperature', 0.3)
            self.is_ready = True
            logger.info("Client Anthropic initialisé pour AnsibleGenerator")
        except Exception as e:
            logger.error(f"Erreur initialisation Anthropic: {e}")
            raise GeneratorException(f"Impossible d'initialiser Anthropic: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    async def generate_playbook(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str = "ubuntu",
            risk_tolerance: str = "low"
    ) -> AnsiblePlaybookResult:
        """
        Génère un playbook Ansible pour corriger une vulnérabilité
        
        Args:
            vulnerability_id: ID de la vulnérabilité
            vulnerability_details: Détails de la vulnérabilité
            target_system: Système cible (ubuntu, centos, etc.)
            risk_tolerance: Tolérance au risque (low, medium, high)
            
        Returns:
            AnsiblePlaybookResult: Playbook généré avec métadonnées
        """
        if not self.is_ready:
            raise GeneratorException("AnsibleGenerator non initialisé", CoreErrorCodes.MODULE_NOT_READY)

        playbook_id = str(uuid.uuid4())
        start_time = time.time()

        logger.info(f"Génération playbook {playbook_id} pour {vulnerability_id}")

        try:
            playbook_data = await self._generate_playbook_with_retry(
                vulnerability_id,
                vulnerability_details,
                target_system,
                risk_tolerance
            )

            processing_time = time.time() - start_time

            result = AnsiblePlaybookResult(
                playbook_id=playbook_id,
                vulnerability_id=vulnerability_id,
                target_system=target_system,
                playbook_yaml=playbook_data.get('playbook_yaml', ''),
                inventory_template=playbook_data.get('inventory_template', ''),
                variables=playbook_data.get('variables', {}),
                validation_status=playbook_data.get('validation_status', 'review_required'),
                risk_level=playbook_data.get('risk_level', 'medium'),
                estimated_execution_time=playbook_data.get('estimated_execution_time'),
                warnings=playbook_data.get('warnings', []),
                prerequisites=playbook_data.get('prerequisites', []),
                rollback_playbook=playbook_data.get('rollback_playbook'),
                generated_at=datetime.utcnow().isoformat(),
                ai_model_used=self.model,
                confidence_score=playbook_data.get('confidence_score', 0.7)
            )

            self._update_stats(True, processing_time)
            logger.info(f"Playbook généré: {playbook_id} ({result.validation_status})")

            return result

        except Exception as e:
            logger.error(f"Erreur génération playbook: {e}")
            self._update_stats(False, time.time() - start_time)
            raise

    async def _generate_playbook_with_retry(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            risk_tolerance: str,
            max_retries: int = 2
    ) -> Dict[str, Any]:
        """Génère un playbook avec retry en cas d'échec"""
        for attempt in range(max_retries + 1):
            try:
                return await self._generate_playbook_ai(
                    vulnerability_id,
                    vulnerability_details,
                    target_system,
                    risk_tolerance
                )
            except Exception as e:
                if attempt == max_retries:
                    raise
                logger.warning(f"Tentative {attempt + 1} échouée, retry...")
                await asyncio.sleep(2 ** attempt)

    async def _generate_playbook_ai(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            risk_tolerance: str
    ) -> Dict[str, Any]:
        """Génère un playbook Ansible avec l'IA"""
        
        # Construire le prompt
        prompt = self._build_ansible_prompt(
            vulnerability_id,
            vulnerability_details,
            target_system,
            risk_tolerance
        )

        # Appeler l'IA
        if self.ai_provider == 'anthropic':
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            playbook_content = response.content[0].text
        else:  # OpenAI
            response = await self.client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            playbook_content = response.choices[0].message.content

        # Parser la réponse
        return self._parse_ai_response(playbook_content, vulnerability_id, target_system)

    def _build_ansible_prompt(
            self,
            vulnerability_id: str,
            vulnerability_details: Dict[str, Any],
            target_system: str,
            risk_tolerance: str
    ) -> str:
        """Construit le prompt pour générer le playbook Ansible"""
        
        cve_id = vulnerability_details.get('vulnerability_id', vulnerability_id)
        service = vulnerability_details.get('affected_service', 'Unknown')
        description = vulnerability_details.get('description', 'No description')
        cvss_score = vulnerability_details.get('cvss_score', 0)
        severity = vulnerability_details.get('severity', 'UNKNOWN')
        
        prompt = f"""Génère un playbook Ansible professionnel et complet pour corriger cette vulnérabilité de sécurité.

INFORMATIONS SUR LA VULNÉRABILITÉ:
- CVE ID: {cve_id}
- Service affecté: {service}
- Sévérité: {severity}
- Score CVSS: {cvss_score}
- Description: {description}

SYSTÈME CIBLE: {target_system}
TOLÉRANCE AU RISQUE: {risk_tolerance}

REQUIS DU PLAYBOOK:
1. Créer un snapshot/backup avant toute modification
2. Arrêter le service si nécessaire (de manière sécurisée)
3. Appliquer le correctif (mise à jour, configuration, etc.)
4. Valider la configuration après modification
5. Redémarrer le service de manière contrôlée
6. Exécuter des tests post-patch pour vérifier le fonctionnement
7. Implémenter un rollback automatique en cas d'échec
8. Utiliser des handlers Ansible pour gérer les redémarrages
9. Ajouter des tags pour permettre l'exécution sélective
10. Documenter chaque tâche avec des commentaires clairs

FORMAT DE SORTIE (JSON):
{{
    "playbook_yaml": "---\\n- name: Fix CVE...\\n  hosts: ...",
    "inventory_template": "[webservers]\\nserver1 ansible_host=...",
    "variables": {{"service_name": "apache2", "backup_dir": "/backup"}},
    "validation_status": "review_required",
    "risk_level": "medium",
    "estimated_execution_time": 300,
    "warnings": ["Requiert accès root", "Redémarrage du service nécessaire"],
    "prerequisites": ["ansible >= 2.9", "accès SSH aux serveurs"],
    "rollback_playbook": "---\\n- name: Rollback...",
    "confidence_score": 0.85
}}

IMPORTANT:
- Le playbook doit être syntaxiquement correct (YAML valide)
- Utiliser des modules Ansible standards (apt, yum, systemd, etc.)
- Inclure la gestion d'erreurs avec blocks/rescue
- Le rollback doit être sûr et testé
- Respecter les bonnes pratiques Ansible (idempotence, etc.)

Génère uniquement le JSON, sans texte supplémentaire."""

        return prompt

    def _parse_ai_response(
            self,
            ai_response: str,
            vulnerability_id: str,
            target_system: str
    ) -> Dict[str, Any]:
        """Parse la réponse de l'IA et extrait le playbook"""
        try:
            # Essayer de parser directement le JSON
            if ai_response.strip().startswith('{'):
                parsed = json.loads(ai_response)
            else:
                # Essayer d'extraire le JSON du texte
                import re
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                else:
                    raise ValueError("Aucun JSON trouvé dans la réponse")
            
            # Valider le YAML du playbook
            if 'playbook_yaml' in parsed:
                try:
                    yaml.safe_load(parsed['playbook_yaml'])
                except yaml.YAMLError as e:
                    logger.warning(f"YAML invalide dans le playbook: {e}")
                    parsed['warnings'] = parsed.get('warnings', []) + [f"YAML invalide: {str(e)}"]
            
            return parsed
            
        except Exception as e:
            logger.error(f"Erreur parsing réponse IA: {e}")
            # Retourner un playbook basique en cas d'erreur
            return self._generate_fallback_playbook(vulnerability_id, target_system)

    def _generate_fallback_playbook(
            self,
            vulnerability_id: str,
            target_system: str
    ) -> Dict[str, Any]:
        """Génère un playbook basique en cas d'échec de l'IA"""
        playbook = f"""---
- name: Fix {vulnerability_id}
  hosts: webservers
  become: true
  vars:
    backup_dir: "/backup/{{{{ inventory_hostname }}}}"
    
  tasks:
    - name: Create backup directory
      file:
        path: "{{{{ backup_dir }}}}"
        state: directory
        mode: '0755'
      
    - name: Backup configuration
      synchronize:
        src: /etc/
        dest: "{{{{ backup_dir }}}}/etc-backup-{{{{ ansible_date_time.epoch }}}}"
      delegate_to: localhost
      
    - name: Update system packages
      apt:
        update_cache: yes
        upgrade: dist
        autoremove: yes
      when: ansible_os_family == "Debian"
      
    - name: Verify service is running
      systemd:
        name: "{{{{ service_name | default('apache2') }}}}"
        state: started
      register: service_status
      
    - name: Display status
      debug:
        msg: "Service status: {{{{ service_status.status.ActiveState }}}}"
"""
        
        return {
            "playbook_yaml": playbook,
            "inventory_template": "[webservers]\nserver1 ansible_host=192.168.1.100",
            "variables": {"service_name": "apache2", "backup_dir": "/backup"},
            "validation_status": "review_required",
            "risk_level": "medium",
            "estimated_execution_time": 300,
            "warnings": ["Playbook générique - nécessite personnalisation"],
            "prerequisites": ["ansible >= 2.9"],
            "rollback_playbook": None,
            "confidence_score": 0.5
        }

    def _extract_variables(self, playbook_yaml: str) -> Dict[str, Any]:
        """Extrait les variables nécessaires du playbook"""
        variables = {}
        try:
            playbook_data = yaml.safe_load(playbook_yaml)
            if isinstance(playbook_data, list) and len(playbook_data) > 0:
                play = playbook_data[0]
                if 'vars' in play:
                    variables = play['vars']
        except Exception as e:
            logger.warning(f"Erreur extraction variables: {e}")
        return variables

    def _update_stats(self, success: bool, duration: float):
        """Met à jour les statistiques"""
        self.stats["total_playbooks"] += 1
        if success:
            self.stats["successful_playbooks"] += 1
        else:
            self.stats["failed_playbooks"] += 1
        current_avg = self.stats["average_generation_time"]
        total = self.stats["total_playbooks"]
        self.stats["average_generation_time"] = (current_avg * (total - 1) + duration) / total

    async def validate_playbook(self, playbook_yaml: str) -> Dict[str, Any]:
        """Valide un playbook Ansible"""
        errors = []
        warnings = []
        
        try:
            # Valider la syntaxe YAML
            playbook_data = yaml.safe_load(playbook_yaml)
            if not isinstance(playbook_data, list):
                errors.append("Le playbook doit être une liste")
            
            # Vérifier la structure de base
            if playbook_data:
                play = playbook_data[0]
                if 'hosts' not in play:
                    errors.append("Le playbook doit définir 'hosts'")
                if 'tasks' not in play and 'roles' not in play:
                    warnings.append("Aucune tâche ou rôle défini")
            
            # Vérifier les modules utilisés
            if playbook_data:
                for play in playbook_data:
                    if 'tasks' in play:
                        for task in play['tasks']:
                            if 'name' not in task:
                                warnings.append("Tâche sans nom trouvée")
            
            return {
                "is_valid": len(errors) == 0,
                "errors": errors,
                "warnings": warnings
            }
            
        except yaml.YAMLError as e:
            return {
                "is_valid": False,
                "errors": [f"Erreur YAML: {str(e)}"],
                "warnings": []
            }

