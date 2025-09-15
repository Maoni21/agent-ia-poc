"""
Module Supervisor pour l'Agent IA de Cybersécurité

Le Supervisor est le module central qui orchestre tous les autres modules :
- Collector (scan de vulnérabilités)
- Analyzer (analyse IA)
- Generator (génération de scripts)

Il fournit une interface unifiée pour exécuter des workflows complets
de détection, analyse et correction de vulnérabilités.

Fonctionnalités :
- Orchestration des workflows de sécurité
- Gestion des tâches asynchrones
- Monitoring et logging centralisé
- Gestion d'état et persistance
- Interface API unifiée
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict

from config import get_config, DEFAULT_CONFIG
from src.utils.logger import setup_logger
from src.database.database import Database
from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from . import SupervisorException, CoreErrorCodes, ERROR_MESSAGES, TASK_STATUS, OPERATION_TYPES

# Configuration du logging
logger = setup_logger(__name__)


# === ÉNUMÉRATIONS ===

class WorkflowType(str, Enum):
    """Types de workflow disponibles"""
    SCAN_ONLY = "scan_only"
    SCAN_AND_ANALYZE = "scan_and_analyze"
    FULL_WORKFLOW = "full_workflow"
    ANALYZE_EXISTING = "analyze_existing"
    GENERATE_SCRIPTS = "generate_scripts"
    CUSTOM = "custom"


class TaskPriority(str, Enum):
    """Priorités des tâches"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowStatus(str, Enum):
    """États des workflows"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


# === MODÈLES DE DONNÉES ===

@dataclass
class TaskInfo:
    """Informations sur une tâche"""
    task_id: str
    workflow_id: str
    task_type: str
    status: str
    priority: TaskPriority
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['created_at'] = self.created_at.isoformat()
        if self.started_at:
            result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        return result


@dataclass
class WorkflowDefinition:
    """Définition d'un workflow"""
    workflow_id: str
    name: str
    workflow_type: WorkflowType
    target: str
    parameters: Dict[str, Any]
    tasks: List[str]
    status: WorkflowStatus
    priority: TaskPriority
    created_at: datetime
    created_by: str
    estimated_duration: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['created_at'] = self.created_at.isoformat()
        return result


@dataclass
class WorkflowResult:
    """Résultat d'un workflow complet"""
    workflow_id: str
    workflow_type: WorkflowType
    target: str
    status: WorkflowStatus
    started_at: datetime
    completed_at: Optional[datetime]
    duration: Optional[float]

    # Résultats par étape
    scan_result: Optional[ScanResult] = None
    analysis_result: Optional[AnalysisResult] = None
    script_results: List[ScriptResult] = None

    # Métadonnées
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    scripts_generated: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        if self.scan_result:
            result['scan_result'] = self.scan_result.to_dict()
        if self.analysis_result:
            result['analysis_result'] = self.analysis_result.to_dict()
        if self.script_results:
            result['script_results'] = [script.to_dict() for script in self.script_results]
        return result


# === CLASSE PRINCIPALE ===

class Supervisor:
    """
    Superviseur central de l'Agent IA de Cybersécurité

    Orchestre tous les modules (Collector, Analyzer, Generator) pour
    exécuter des workflows complets de détection et correction de vulnérabilités.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialise le superviseur

        Args:
            config: Configuration personnalisée (optionnel)
        """
        self.config = config or get_config()

        # État du superviseur
        self.is_ready = False
        self.is_running = False

        # Modules core
        self.collector: Optional[Collector] = None
        self.analyzer: Optional[Analyzer] = None
        self.generator: Optional[Generator] = None

        # Base de données
        self.db = Database()

        # Gestion des tâches et workflows
        self.active_workflows: Dict[str, WorkflowDefinition] = {}
        self.active_tasks: Dict[str, TaskInfo] = {}
        self.workflow_queue: List[str] = []

        # Configuration d'orchestration
        self.max_concurrent_workflows = self.config.get('max_concurrent_workflows', 3)
        self.max_concurrent_tasks = self.config.get('max_concurrent_tasks', 5)

        # Callbacks et monitoring
        self.progress_callbacks: Dict[str, Callable] = {}
        self.completion_callbacks: Dict[str, Callable] = {}

        # Statistiques
        self.stats = {
            "total_workflows": 0,
            "successful_workflows": 0,
            "failed_workflows": 0,
            "total_vulnerabilities_found": 0,
            "total_scripts_generated": 0,
            "average_workflow_time": 0.0,
            "uptime_start": datetime.utcnow()
        }

        # Initialiser les modules
        self._initialize_modules()

    def _initialize_modules(self):
        """Initialise tous les modules core"""
        try:
            logger.info("Initialisation des modules core...")

            # Initialiser le collector
            self.collector = Collector(self.config)
            logger.info("✅ Collector initialisé")

            # Initialiser l'analyzer
            self.analyzer = Analyzer(self.config)
            logger.info("✅ Analyzer initialisé")

            # Initialiser le generator
            self.generator = Generator(self.config)
            logger.info("✅ Generator initialisé")

            self.is_ready = True
            logger.info("🚀 Supervisor initialisé avec succès")

        except Exception as e:
            logger.error(f"❌ Erreur initialisation modules: {e}")
            raise SupervisorException(
                f"Impossible d'initialiser les modules: {str(e)}",
                CoreErrorCodes.CORE_INIT_ERROR
            )

    async def start_workflow(
            self,
            workflow_type: WorkflowType,
            target: str,
            parameters: Optional[Dict[str, Any]] = None,
            priority: TaskPriority = TaskPriority.NORMAL,
            created_by: str = "system"
    ) -> str:
        """
        Lance un nouveau workflow

        Args:
            workflow_type: Type de workflow à exécuter
            target: Cible du workflow (IP, hostname, etc.)
            parameters: Paramètres spécifiques au workflow
            priority: Priorité du workflow
            created_by: Créateur du workflow

        Returns:
            str: ID du workflow créé

        Raises:
            SupervisorException: Si le workflow ne peut pas être créé
        """
        if not self.is_ready:
            raise SupervisorException(
                "Supervisor non initialisé",
                CoreErrorCodes.MODULE_NOT_READY
            )

        workflow_id = str(uuid.uuid4())
        parameters = parameters or {}

        try:
            # Créer la définition du workflow
            workflow_def = self._create_workflow_definition(
                workflow_id, workflow_type, target, parameters, priority, created_by
            )

            # Enregistrer le workflow
            self.active_workflows[workflow_id] = workflow_def

            # Ajouter à la queue
            self.workflow_queue.append(workflow_id)

            # Démarrer le processeur de queue si nécessaire
            if not self.is_running:
                asyncio.create_task(self._workflow_processor())

            logger.info(f"Workflow créé: {workflow_id} ({workflow_type.value})")
            return workflow_id

        except Exception as e:
            logger.error(f"Erreur création workflow: {e}")
            raise SupervisorException(
                f"Impossible de créer le workflow: {str(e)}",
                CoreErrorCodes.ORCHESTRATION_FAILED
            )

    def _create_workflow_definition(
            self,
            workflow_id: str,
            workflow_type: WorkflowType,
            target: str,
            parameters: Dict[str, Any],
            priority: TaskPriority,
            created_by: str
    ) -> WorkflowDefinition:
        """Crée une définition de workflow"""

        # Définir les tâches selon le type de workflow
        tasks = self._get_workflow_tasks(workflow_type)

        # Estimer la durée
        estimated_duration = self._estimate_workflow_duration(workflow_type, parameters)

        return WorkflowDefinition(
            workflow_id=workflow_id,
            name=f"{workflow_type.value}_{target}",
            workflow_type=workflow_type,
            target=target,
            parameters=parameters,
            tasks=tasks,
            status=WorkflowStatus.PENDING,
            priority=priority,
            created_at=datetime.utcnow(),
            created_by=created_by,
            estimated_duration=estimated_duration
        )

    def _get_workflow_tasks(self, workflow_type: WorkflowType) -> List[str]:
        """Retourne la liste des tâches pour un type de workflow"""

        task_definitions = {
            WorkflowType.SCAN_ONLY: ["scan"],
            WorkflowType.SCAN_AND_ANALYZE: ["scan", "analyze"],
            WorkflowType.FULL_WORKFLOW: ["scan", "analyze", "generate_scripts"],
            WorkflowType.ANALYZE_EXISTING: ["analyze"],
            WorkflowType.GENERATE_SCRIPTS: ["generate_scripts"],
            WorkflowType.CUSTOM: []  # Défini dynamiquement
        }

        return task_definitions.get(workflow_type, [])

    def _estimate_workflow_duration(
            self,
            workflow_type: WorkflowType,
            parameters: Dict[str, Any]
    ) -> int:
        """Estime la durée d'un workflow en secondes"""

        base_durations = {
            WorkflowType.SCAN_ONLY: 300,  # 5 minutes
            WorkflowType.SCAN_AND_ANALYZE: 480,  # 8 minutes
            WorkflowType.FULL_WORKFLOW: 600,  # 10 minutes
            WorkflowType.ANALYZE_EXISTING: 120,  # 2 minutes
            WorkflowType.GENERATE_SCRIPTS: 180,  # 3 minutes
            WorkflowType.CUSTOM: 300  # 5 minutes par défaut
        }

        base_duration = base_durations.get(workflow_type, 300)

        # Ajustements selon les paramètres
        scan_type = parameters.get('scan_type', 'full')
        if scan_type == 'aggressive':
            base_duration *= 1.5
        elif scan_type == 'quick':
            base_duration *= 0.7

        return int(base_duration)

    async def _workflow_processor(self):
        """Processeur principal des workflows"""
        self.is_running = True
        logger.info("🔄 Processeur de workflows démarré")

        try:
            while self.is_running:
                # Traiter les workflows en attente
                await self._process_pending_workflows()

                # Vérifier les workflows actifs
                await self._check_active_workflows()

                # Attendre avant la prochaine itération
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Erreur dans le processeur de workflows: {e}")
        finally:
            self.is_running = False
            logger.info("🛑 Processeur de workflows arrêté")

    async def _process_pending_workflows(self):
        """Traite les workflows en attente"""
        if not self.workflow_queue:
            return

        # Compter les workflows actifs
        active_count = len([
            wf for wf in self.active_workflows.values()
            if wf.status == WorkflowStatus.RUNNING
        ])

        # Démarrer de nouveaux workflows si possible
        while (active_count < self.max_concurrent_workflows and
               self.workflow_queue):

            workflow_id = self.workflow_queue.pop(0)
            if workflow_id in self.active_workflows:
                await self._execute_workflow(workflow_id)
                active_count += 1

    async def _execute_workflow(self, workflow_id: str):
        """Exécute un workflow complet"""
        workflow_def = self.active_workflows[workflow_id]
        workflow_def.status = WorkflowStatus.RUNNING

        start_time = datetime.utcnow()

        try:
            logger.info(f"🚀 Exécution workflow: {workflow_id}")

            # Créer le résultat du workflow
            workflow_result = WorkflowResult(
                workflow_id=workflow_id,
                workflow_type=workflow_def.workflow_type,
                target=workflow_def.target,
                status=WorkflowStatus.RUNNING,
                started_at=start_time,
                completed_at=None,
                duration=None
            )

            # Exécuter chaque tâche
            for task_name in workflow_def.tasks:
                await self._execute_task(
                    workflow_id, task_name, workflow_def, workflow_result
                )

            # Finaliser le workflow
            end_time = datetime.utcnow()
            workflow_result.completed_at = end_time
            workflow_result.duration = (end_time - start_time).total_seconds()
            workflow_result.status = WorkflowStatus.COMPLETED
            workflow_def.status = WorkflowStatus.COMPLETED

            # Sauvegarder le résultat
            await self._save_workflow_result(workflow_result)

            # Mettre à jour les statistiques
            self._update_workflow_stats(True, workflow_result.duration)

            # Appeler les callbacks
            await self._call_completion_callbacks(workflow_id, workflow_result)

            logger.info(f"✅ Workflow terminé: {workflow_id}")

        except Exception as e:
            logger.error(f"❌ Erreur workflow {workflow_id}: {e}")
            workflow_def.status = WorkflowStatus.FAILED
            self._update_workflow_stats(False, (datetime.utcnow() - start_time).total_seconds())

            # Nettoyer les tâches actives de ce workflow
            await self._cleanup_workflow_tasks(workflow_id)

    async def _execute_task(
            self,
            workflow_id: str,
            task_name: str,
            workflow_def: WorkflowDefinition,
            workflow_result: WorkflowResult
    ):
        """Exécute une tâche spécifique"""

        task_id = f"{workflow_id}_{task_name}_{int(time.time())}"

        # Créer l'info de tâche
        task_info = TaskInfo(
            task_id=task_id,
            workflow_id=workflow_id,
            task_type=task_name,
            status=TASK_STATUS["RUNNING"],
            priority=workflow_def.priority,
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow()
        )

        self.active_tasks[task_id] = task_info

        try:
            logger.info(f"🔧 Exécution tâche: {task_name} ({workflow_id})")

            # Exécuter selon le type de tâche
            if task_name == "scan":
                result = await self._execute_scan_task(workflow_def, task_info)
                workflow_result.scan_result = result

            elif task_name == "analyze":
                result = await self._execute_analyze_task(workflow_def, workflow_result, task_info)
                workflow_result.analysis_result = result

            elif task_name == "generate_scripts":
                results = await self._execute_generate_task(workflow_def, workflow_result, task_info)
                workflow_result.script_results = results

            else:
                raise SupervisorException(
                    f"Type de tâche inconnu: {task_name}",
                    CoreErrorCodes.ORCHESTRATION_FAILED
                )

            # Finaliser la tâche
            task_info.status = TASK_STATUS["COMPLETED"]
            task_info.completed_at = datetime.utcnow()
            task_info.progress = 100
            task_info.result = result.to_dict() if hasattr(result, 'to_dict') else result

            logger.info(f"✅ Tâche terminée: {task_name}")

        except Exception as e:
            logger.error(f"❌ Erreur tâche {task_name}: {e}")
            task_info.status = TASK_STATUS["FAILED"]
            task_info.error = str(e)
            task_info.completed_at = datetime.utcnow()
            raise

        finally:
            # Nettoyer la tâche de la liste active
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]

    async def _execute_scan_task(
            self,
            workflow_def: WorkflowDefinition,
            task_info: TaskInfo
    ) -> ScanResult:
        """Exécute une tâche de scan"""

        def progress_callback(progress: int):
            task_info.progress = progress
            self._call_progress_callbacks(workflow_def.workflow_id, "scan", progress)

        scan_type = workflow_def.parameters.get('scan_type', 'full')
        timeout = workflow_def.parameters.get('timeout', 300)
        custom_args = workflow_def.parameters.get('nmap_args')

        result = await self.collector.scan_target(
            target=workflow_def.target,
            scan_type=scan_type,
            custom_args=custom_args,
            timeout=timeout,
            progress_callback=progress_callback
        )

        return result

    async def _execute_analyze_task(
            self,
            workflow_def: WorkflowDefinition,
            workflow_result: WorkflowResult,
            task_info: TaskInfo
    ) -> AnalysisResult:
        """Exécute une tâche d'analyse"""

        # Récupérer les données de vulnérabilités
        if workflow_result.scan_result:
            # Utiliser les vulnérabilités du scan
            vulnerabilities_data = [vuln.to_dict() for vuln in workflow_result.scan_result.vulnerabilities]
        else:
            # Utiliser les données fournies dans les paramètres
            vulnerabilities_data = workflow_def.parameters.get('vulnerabilities_data', [])

        if not vulnerabilities_data:
            raise SupervisorException(
                "Aucune donnée de vulnérabilité disponible pour l'analyse",
                CoreErrorCodes.INVALID_VULNERABILITY_DATA
            )

        business_context = workflow_def.parameters.get('business_context')

        result = await self.analyzer.analyze_vulnerabilities(
            vulnerabilities_data=vulnerabilities_data,
            target_system=workflow_def.target,
            business_context=business_context
        )

        # Mettre à jour les statistiques du workflow
        workflow_result.total_vulnerabilities = len(vulnerabilities_data)
        workflow_result.critical_vulnerabilities = len([
            v for v in result.vulnerabilities if v.severity == "CRITICAL"
        ])

        task_info.progress = 100
        return result

    async def _execute_generate_task(
            self,
            workflow_def: WorkflowDefinition,
            workflow_result: WorkflowResult,
            task_info: TaskInfo
    ) -> List[ScriptResult]:
        """Exécute une tâche de génération de scripts"""

        # Récupérer les vulnérabilités à traiter
        vulnerabilities = []

        if workflow_result.analysis_result:
            vulnerabilities = workflow_result.analysis_result.vulnerabilities
        elif workflow_result.scan_result:
            vulnerabilities = workflow_result.scan_result.vulnerabilities
        else:
            # Utiliser les vulnérabilités fournies dans les paramètres
            vuln_data = workflow_def.parameters.get('vulnerabilities_data', [])
            vulnerabilities = vuln_data

        if not vulnerabilities:
            raise SupervisorException(
                "Aucune vulnérabilité disponible pour la génération de scripts",
                CoreErrorCodes.INVALID_VULNERABILITY_DATA
            )

        target_system = workflow_def.parameters.get('target_system', 'ubuntu')
        risk_tolerance = workflow_def.parameters.get('risk_tolerance', 'low')
        max_scripts = workflow_def.parameters.get('max_scripts', 10)

        script_results = []

        # Limiter le nombre de vulnérabilités à traiter
        vulnerabilities_to_process = vulnerabilities[:max_scripts]

        for i, vulnerability in enumerate(vulnerabilities_to_process):
            try:
                # Préparer les détails de la vulnérabilité
                if hasattr(vulnerability, 'to_dict'):
                    vuln_details = vulnerability.to_dict()
                else:
                    vuln_details = vulnerability

                # Générer le script
                script_result = await self.generator.generate_fix_script(
                    vulnerability_id=vuln_details.get('vulnerability_id', f'vuln_{i}'),
                    vulnerability_details=vuln_details,
                    target_system=target_system,
                    risk_tolerance=risk_tolerance
                )

                script_results.append(script_result)

                # Mettre à jour la progression
                progress = int((i + 1) / len(vulnerabilities_to_process) * 100)
                task_info.progress = progress
                self._call_progress_callbacks(workflow_def.workflow_id, "generate_scripts", progress)

            except Exception as e:
                logger.warning(f"Erreur génération script pour vulnérabilité {i}: {e}")
                continue

        # Mettre à jour les statistiques
        workflow_result.scripts_generated = len(script_results)

        return script_results

    async def _check_active_workflows(self):
        """Vérifie l'état des workflows actifs"""
        for workflow_id, workflow_def in list(self.active_workflows.items()):
            # Nettoyer les workflows terminés après un délai
            if workflow_def.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]:
                # Garder pendant 1 heure pour consultation
                if (datetime.utcnow() - workflow_def.created_at).total_seconds() > 3600:
                    del self.active_workflows[workflow_id]
                    logger.debug(f"Workflow nettoyé: {workflow_id}")

    async def _cleanup_workflow_tasks(self, workflow_id: str):
        """Nettoie les tâches d'un workflow"""
        tasks_to_remove = [
            task_id for task_id, task_info in self.active_tasks.items()
            if task_info.workflow_id == workflow_id
        ]

        for task_id in tasks_to_remove:
            del self.active_tasks[task_id]

    def _call_progress_callbacks(self, workflow_id: str, task_name: str, progress: int):
        """Appelle les callbacks de progression"""
        callback = self.progress_callbacks.get(workflow_id)
        if callback:
            try:
                callback(task_name, progress)
            except Exception as e:
                logger.warning(f"Erreur callback progression: {e}")

    async def _call_completion_callbacks(self, workflow_id: str, result: WorkflowResult):
        """Appelle les callbacks de fin de workflow"""
        callback = self.completion_callbacks.get(workflow_id)
        if callback:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(result)
                else:
                    callback(result)
            except Exception as e:
                logger.warning(f"Erreur callback completion: {e}")

    async def _save_workflow_result(self, result: WorkflowResult):
        """Sauvegarde le résultat d'un workflow"""
        try:
            # TODO: Sauvegarder en base de données
            logger.debug(f"Sauvegarde workflow: {result.workflow_id}")

            # Sauvegarder aussi en fichier JSON pour debugging
            results_dir = Path("data/workflow_results")
            results_dir.mkdir(exist_ok=True)

            result_file = results_dir / f"{result.workflow_id}.json"
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        except Exception as e:
            logger.warning(f"Erreur sauvegarde workflow: {e}")

    def _update_workflow_stats(self, success: bool, duration: float):
        """Met à jour les statistiques des workflows"""
        self.stats["total_workflows"] += 1

        if success:
            self.stats["successful_workflows"] += 1
        else:
            self.stats["failed_workflows"] += 1

        # Moyenne mobile simple
        current_avg = self.stats["average_workflow_time"]
        total = self.stats["total_workflows"]
        self.stats["average_workflow_time"] = (current_avg * (total - 1) + duration) / total

    # === MÉTHODES PUBLIQUES ===

    async def run_scan(
            self,
            target: str,
            scan_type: str = "full",
            progress_callback: Optional[Callable[[int], None]] = None
    ) -> ScanResult:
        """
        Lance un scan simple (interface publique)

        Args:
            target: Cible à scanner
            scan_type: Type de scan
            progress_callback: Callback de progression

        Returns:
            ScanResult: Résultats du scan
        """
        workflow_id = await self.start_workflow(
            WorkflowType.SCAN_ONLY,
            target,
            {"scan_type": scan_type}
        )

        if progress_callback:
            self.progress_callbacks[workflow_id] = lambda task, progress: progress_callback(progress)

        # Attendre la fin du workflow
        result = await self.wait_for_workflow(workflow_id)
        return result.scan_result

    async def analyze_vulnerabilities(
            self,
            vulnerabilities_data: List[Dict[str, Any]],
            target_system: str = "Unknown System"
    ) -> AnalysisResult:
        """
        Lance une analyse de vulnérabilités (interface publique)

        Args:
            vulnerabilities_data: Données des vulnérabilités
            target_system: Système cible

        Returns:
            AnalysisResult: Résultats de l'analyse
        """
        workflow_id = await self.start_workflow(
            WorkflowType.ANALYZE_EXISTING,
            target_system,
            {"vulnerabilities_data": vulnerabilities_data}
        )

        result = await self.wait_for_workflow(workflow_id)
        return result.analysis_result

    async def generate_fix_script(
            self,
            vulnerability_id: str,
            target_system: str = "ubuntu"
    ) -> ScriptResult:
        """
        Génère un script de correction (interface publique)

        Args:
            vulnerability_id: ID de la vulnérabilité
            target_system: Système cible

        Returns:
            ScriptResult: Script généré
        """
        workflow_id = await self.start_workflow(
            WorkflowType.GENERATE_SCRIPTS,
            target_system,
            {
                "vulnerabilities_data": [{"vulnerability_id": vulnerability_id}],
                "target_system": target_system
            }
        )

        result = await self.wait_for_workflow(workflow_id)
        return result.script_results[0] if result.script_results else None

    async def run_complete_workflow(
            self,
            target: str,
            scan_type: str = "full",
            progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> WorkflowResult:
        """
        Lance un workflow complet (scan + analyse + génération)

        Args:
            target: Cible à traiter
            scan_type: Type de scan
            progress_callback: Callback de progression

        Returns:
            WorkflowResult: Résultats complets
            """
            workflow_id = await self.start_workflow(
            WorkflowType.FULL_WORKFLOW,
            target,
            {"scan_type": scan_type}
        )

        if progress_callback:
            self.progress_callbacks[workflow_id] = progress_callback

        return await self.wait_for_workflow(workflow_id)

    async def wait_for_workflow(self, workflow_id: str, timeout: int = 3600) -> WorkflowResult:
        """
        Attend la fin d'un workflow

        Args:
            workflow_id: ID du workflow
            timeout: Timeout en secondes

        Returns:
            WorkflowResult: Résultat du workflow

        Raises:
            SupervisorException: Si le workflow échoue ou timeout
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            if workflow_id not in self.active_workflows:
                raise SupervisorException(
                    f"Workflow non trouvé: {workflow_id}",
                    CoreErrorCodes.ORCHESTRATION_FAILED
                )

            workflow_def = self.active_workflows[workflow_id]

            if workflow_def.status == WorkflowStatus.COMPLETED:
                # Charger le résultat
                return await self._load_workflow_result(workflow_id)

            elif workflow_def.status == WorkflowStatus.FAILED:
                raise SupervisorException(
                    f"Workflow échoué: {workflow_id}",
                    CoreErrorCodes.WORKFLOW_INTERRUPTED
                )

            await asyncio.sleep(1)

        raise SupervisorException(
            f"Timeout workflow: {workflow_id}",
            CoreErrorCodes.WORKFLOW_INTERRUPTED
        )

    async def _load_workflow_result(self, workflow_id: str) -> WorkflowResult:
        """Charge le résultat d'un workflow depuis le stockage"""
        try:
            results_dir = Path("data/workflow_results")
            result_file = results_dir / f"{workflow_id}.json"

            if result_file.exists():
                with open(result_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Reconstruire l'objet WorkflowResult
                # (Simplification - en production, utiliser un désérialiseur complet)
                return WorkflowResult(
                    workflow_id=data['workflow_id'],
                    workflow_type=WorkflowType(data['workflow_type']),
                    target=data['target'],
                    status=WorkflowStatus(data['status']),
                    started_at=datetime.fromisoformat(data['started_at']),
                    completed_at=datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None,
                    duration=data.get('duration'),
                    total_vulnerabilities=data.get('total_vulnerabilities', 0),
                    critical_vulnerabilities=data.get('critical_vulnerabilities', 0),
                    scripts_generated=data.get('scripts_generated', 0)
                )

            else:
                # Créer un résultat basique
                workflow_def = self.active_workflows[workflow_id]
                return WorkflowResult(
                    workflow_id=workflow_id,
                    workflow_type=workflow_def.workflow_type,
                    target=workflow_def.target,
                    status=workflow_def.status,
                    started_at=workflow_def.created_at,
                    completed_at=datetime.utcnow(),
                    duration=0.0
                )

        except Exception as e:
            logger.error(f"Erreur chargement résultat workflow: {e}")
            raise SupervisorException(
                f"Impossible de charger le résultat: {str(e)}",
                CoreErrorCodes.ORCHESTRATION_FAILED
            )

    def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """
        Récupère le statut d'un workflow

        Args:
            workflow_id: ID du workflow

        Returns:
            Dict contenant le statut et la progression
        """
        if workflow_id not in self.active_workflows:
            return {"error": "Workflow non trouvé"}

        workflow_def = self.active_workflows[workflow_id]

        # Calculer la progression globale
        total_progress = 0
        completed_tasks = 0

        for task_id, task_info in self.active_tasks.items():
            if task_info.workflow_id == workflow_id:
                total_progress += task_info.progress
                if task_info.status == TASK_STATUS["COMPLETED"]:
                    completed_tasks += 1

        overall_progress = total_progress // len(workflow_def.tasks) if workflow_def.tasks else 0

        return {
            "workflow_id": workflow_id,
            "status": workflow_def.status.value,
            "progress": overall_progress,
            "target": workflow_def.target,
            "workflow_type": workflow_def.workflow_type.value,
            "created_at": workflow_def.created_at.isoformat(),
            "estimated_duration": workflow_def.estimated_duration,
            "completed_tasks": completed_tasks,
            "total_tasks": len(workflow_def.tasks),
            "current_tasks": [
                {
                    "task_id": task_info.task_id,
                    "task_type": task_info.task_type,
                    "status": task_info.status,
                    "progress": task_info.progress
                }
                for task_info in self.active_tasks.values()
                if task_info.workflow_id == workflow_id
            ]
        }

    def list_workflows(
        self,
        status_filter: Optional[WorkflowStatus] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Liste les workflows

        Args:
            status_filter: Filtrer par statut
            limit: Nombre maximum de résultats

        Returns:
            Liste des workflows avec leurs métadonnées
        """
        workflows = []

        for workflow_def in self.active_workflows.values():
            if status_filter and workflow_def.status != status_filter:
                continue

            workflows.append({
                "workflow_id": workflow_def.workflow_id,
                "name": workflow_def.name,
                "workflow_type": workflow_def.workflow_type.value,
                "target": workflow_def.target,
                "status": workflow_def.status.value,
                "priority": workflow_def.priority.value,
                "created_at": workflow_def.created_at.isoformat(),
                "created_by": workflow_def.created_by,
                "estimated_duration": workflow_def.estimated_duration
            })

        # Trier par date de création (plus récent en premier)
        workflows.sort(key=lambda w: w["created_at"], reverse=True)

        return workflows[:limit]

    async def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Annule un workflow

        Args:
            workflow_id: ID du workflow à annuler

        Returns:
            bool: True si annulé avec succès
        """
        if workflow_id not in self.active_workflows:
            return False

        workflow_def = self.active_workflows[workflow_id]

        if workflow_def.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]:
            return False  # Déjà terminé

        # Marquer comme annulé
        workflow_def.status = WorkflowStatus.CANCELLED

        # Annuler les tâches actives
        await self._cleanup_workflow_tasks(workflow_id)

        # Retirer de la queue si en attente
        if workflow_id in self.workflow_queue:
            self.workflow_queue.remove(workflow_id)

        logger.info(f"Workflow annulé: {workflow_id}")
        return True

    async def pause_workflow(self, workflow_id: str) -> bool:
        """
        Met en pause un workflow

        Args:
            workflow_id: ID du workflow

        Returns:
            bool: True si mis en pause
        """
        if workflow_id not in self.active_workflows:
            return False

        workflow_def = self.active_workflows[workflow_id]

        if workflow_def.status == WorkflowStatus.RUNNING:
            workflow_def.status = WorkflowStatus.PAUSED
            logger.info(f"Workflow mis en pause: {workflow_id}")
            return True

        return False

    async def resume_workflow(self, workflow_id: str) -> bool:
        """
        Reprend un workflow en pause

        Args:
            workflow_id: ID du workflow

        Returns:
            bool: True si repris
        """
        if workflow_id not in self.active_workflows:
            return False

        workflow_def = self.active_workflows[workflow_id]

        if workflow_def.status == WorkflowStatus.PAUSED:
            workflow_def.status = WorkflowStatus.PENDING
            # Remettre en queue
            if workflow_id not in self.workflow_queue:
                self.workflow_queue.append(workflow_id)
            logger.info(f"Workflow repris: {workflow_id}")
            return True

        return False

    def set_progress_callback(
        self,
        workflow_id: str,
        callback: Callable[[str, int], None]
    ):
        """Définit un callback de progression pour un workflow"""
        self.progress_callbacks[workflow_id] = callback

    def set_completion_callback(
        self,
        workflow_id: str,
        callback: Callable[[WorkflowResult], None]
    ):
        """Définit un callback de fin pour un workflow"""
        self.completion_callbacks[workflow_id] = callback

    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du superviseur"""
        uptime = (datetime.utcnow() - self.stats["uptime_start"]).total_seconds()

        return {
            **self.stats,
            "uptime_seconds": uptime,
            "active_workflows": len(self.active_workflows),
            "queued_workflows": len(self.workflow_queue),
            "active_tasks": len(self.active_tasks),
            "modules_status": {
                "collector": self.collector.is_healthy() if self.collector else False,
                "analyzer": self.analyzer.is_healthy() if self.analyzer else False,
                "generator": self.generator.is_healthy() if self.generator else False
            }
        }

    def get_module_stats(self) -> Dict[str, Dict[str, Any]]:
        """Retourne les statistiques détaillées des modules"""
        return {
            "collector": self.collector.get_stats() if self.collector else {},
            "analyzer": self.analyzer.get_stats() if self.analyzer else {},
            "generator": self.generator.get_stats() if self.generator else {}
        }

    async def generate_report(
        self,
        report_type: str = "summary",
        workflow_id: Optional[str] = None,
        format: str = "json"
    ) -> Dict[str, Any]:
        """
        Génère un rapport de l'activité du superviseur

        Args:
            report_type: Type de rapport (summary, detailed, workflow)
            workflow_id: ID du workflow spécifique (optionnel)
            format: Format du rapport (json, html)

        Returns:
            Dict contenant le rapport
        """
        if report_type == "workflow" and workflow_id:
            return await self._generate_workflow_report(workflow_id, format)

        elif report_type == "summary":
            return self._generate_summary_report()

        elif report_type == "detailed":
            return self._generate_detailed_report()

        else:
            raise SupervisorException(
                f"Type de rapport non supporté: {report_type}",
                CoreErrorCodes.INVALID_CONFIGURATION
            )

    async def _generate_workflow_report(self, workflow_id: str, format: str) -> Dict[str, Any]:
        """Génère un rapport pour un workflow spécifique"""
        if workflow_id not in self.active_workflows:
            raise SupervisorException(
                f"Workflow non trouvé: {workflow_id}",
                CoreErrorCodes.ORCHESTRATION_FAILED
            )

        workflow_def = self.active_workflows[workflow_id]

        try:
            workflow_result = await self._load_workflow_result(workflow_id)
        except:
            workflow_result = None

        report = {
            "report_type": "workflow",
            "workflow_id": workflow_id,
            "workflow_definition": workflow_def.to_dict(),
            "workflow_result": workflow_result.to_dict() if workflow_result else None,
            "generated_at": datetime.utcnow().isoformat()
        }

        if format == "html":
            report["html_content"] = self._format_workflow_report_html(workflow_def, workflow_result)

        return report

    def _generate_summary_report(self) -> Dict[str, Any]:
        """Génère un rapport de résumé"""
        stats = self.get_stats()

        return {
            "report_type": "summary",
            "generated_at": datetime.utcnow().isoformat(),
            "overview": {
                "total_workflows": stats["total_workflows"],
                "success_rate": (stats["successful_workflows"] / stats["total_workflows"] * 100) if stats["total_workflows"] > 0 else 0,
                "average_workflow_time": stats["average_workflow_time"],
                "uptime_hours": stats["uptime_seconds"] / 3600,
                "active_workflows": stats["active_workflows"]
            },
            "current_activity": {
                "queued_workflows": stats["queued_workflows"],
                "active_tasks": stats["active_tasks"],
                "modules_status": stats["modules_status"]
            },
            "security_metrics": {
                "total_vulnerabilities_found": stats["total_vulnerabilities_found"],
                "total_scripts_generated": stats["total_scripts_generated"]
            }
        }

    def _generate_detailed_report(self) -> Dict[str, Any]:
        """Génère un rapport détaillé"""
        summary = self._generate_summary_report()
        module_stats = self.get_module_stats()

        return {
            **summary,
            "report_type": "detailed",
            "module_statistics": module_stats,
            "active_workflows": [
                {
                    "workflow_id": wf.workflow_id,
                    "status": wf.status.value,
                    "target": wf.target,
                    "created_at": wf.created_at.isoformat(),
                    "progress": self.get_workflow_status(wf.workflow_id).get("progress", 0)
                }
                for wf in self.active_workflows.values()
            ],
            "recent_errors": []  # TODO: Implémenter le tracking des erreurs
        }

    def _format_workflow_report_html(
        self,
        workflow_def: WorkflowDefinition,
        workflow_result: Optional[WorkflowResult]
    ) -> str:
        """Formate un rapport de workflow en HTML"""
        html_content = f"""
        <div class="workflow-report">
            <h2>Rapport de Workflow</h2>
            <div class="workflow-info">
                <h3>Informations Générales</h3>
                <p><strong>ID:</strong> {workflow_def.workflow_id}</p>
                <p><strong>Type:</strong> {workflow_def.workflow_type.value}</p>
                <p><strong>Cible:</strong> {workflow_def.target}</p>
                <p><strong>Statut:</strong> {workflow_def.status.value}</p>
                <p><strong>Créé le:</strong> {workflow_def.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """

        if workflow_result:
            html_content += f"""
            <div class="workflow-results">
                <h3>Résultats</h3>
                <p><strong>Durée:</strong> {workflow_result.duration:.1f} secondes</p>
                <p><strong>Vulnérabilités trouvées:</strong> {workflow_result.total_vulnerabilities}</p>
                <p><strong>Vulnérabilités critiques:</strong> {workflow_result.critical_vulnerabilities}</p>
                <p><strong>Scripts générés:</strong> {workflow_result.scripts_generated}</p>
            </div>
            """

        html_content += "</div>"
        return html_content

    def is_healthy(self) -> bool:
        """Vérifie si le superviseur est en bonne santé"""
        if not self.is_ready:
            return False

        # Vérifier les modules
        modules_healthy = all([
            self.collector and self.collector.is_healthy(),
            self.analyzer and self.analyzer.is_healthy(),
            self.generator and self.generator.is_healthy()
        ])

        return modules_healthy

    async def shutdown(self):
        """Arrête proprement le superviseur"""
        logger.info("🛑 Arrêt du superviseur...")

        # Arrêter le processeur de workflows
        self.is_running = False

        # Annuler tous les workflows en cours
        for workflow_id in list(self.active_workflows.keys()):
            await self.cancel_workflow(workflow_id)

        # Nettoyer les ressources
        self.active_workflows.clear()
        self.active_tasks.clear()
        self.workflow_queue.clear()
        self.progress_callbacks.clear()
        self.completion_callbacks.clear()

        logger.info("✅ Superviseur arrêté")

# === FONCTIONS UTILITAIRES ===

async def quick_vulnerability_scan(
    target: str,
    scan_type: str = "quick"
) -> Dict[str, Any]:
    """
    Scan rapide de vulnérabilités (fonction utilitaire)

    Args:
        target: Cible à scanner
        scan_type: Type de scan

    Returns:
        Dict contenant les résultats
    """
    supervisor = Supervisor()

    try:
        result = await supervisor.run_scan(target, scan_type)
        return {
            "success": True,
            "target": target,
            "vulnerabilities_found": len(result.vulnerabilities),
            "scan_duration": result.duration,
            "vulnerabilities": [vuln.to_dict() for vuln in result.vulnerabilities]
        }
    except Exception as e:
        logger.error(f"Erreur scan rapide: {e}")
        return {
            "success": False,
            "error": str(e),
            "target": target
        }
    finally:
        await supervisor.shutdown()

async def complete_security_assessment(
    target: str,
    generate_scripts: bool = True
) -> Dict[str, Any]:
    """
    Évaluation complète de sécurité (fonction utilitaire)

    Args:
        target: Cible à évaluer
        generate_scripts: Générer les scripts de correction

    Returns:
        Dict contenant l'évaluation complète
    """
    supervisor = Supervisor()

    try:
        workflow_type = WorkflowType.FULL_WORKFLOW if generate_scripts else WorkflowType.SCAN_AND_ANALYZE

        result = await supervisor.run_complete_workflow(target, "full")

        return {
            "success": True,
            "target": target,
            "assessment_summary": {
                "total_vulnerabilities": result.total_vulnerabilities,
                "critical_vulnerabilities": result.critical_vulnerabilities,
                "scripts_generated": result.scripts_generated,
                "assessment_duration": result.duration
            },
            "scan_result": result.scan_result.to_dict() if result.scan_result else None,
            "analysis_result": result.analysis_result.to_dict() if result.analysis_result else None,
            "script_results": [script.to_dict() for script in result.script_results] if result.script_results else []
        }

    except Exception as e:
        logger.error(f"Erreur évaluation complète: {e}")
        return {
            "success": False,
            "error": str(e),
            "target": target
        }
    finally:
        await supervisor.shutdown()

def create_supervisor(config: Optional[Dict[str, Any]] = None) -> Supervisor:
    """
    Factory pour créer un superviseur avec configuration spécifique

    Args:
        config: Configuration personnalisée

    Returns:
        Supervisor: Instance configurée
    """
    return Supervisor(config)

# === CLASSE DE PLANIFICATION ===

class WorkflowScheduler:
    """
    Planificateur de workflows automatiques

    Permet de programmer l'exécution automatique de workflows
    selon des horaires ou intervalles définis.
    """

    def __init__(self, supervisor: Supervisor):
        self.supervisor = supervisor
        self.scheduled_workflows = {}
        self.is_running = False

    def schedule_workflow(
        self,
        schedule_id: str,
        workflow_type: WorkflowType,
        target: str,
        cron_expression: str,
        parameters: Optional[Dict[str, Any]] = None
    ):
        """
        Programme un workflow récurrent

        Args:
            schedule_id: ID unique du planning
            workflow_type: Type de workflow
            target: Cible du workflow
            cron_expression: Expression cron pour la planification
            parameters: Paramètres du workflow
        """
        self.scheduled_workflows[schedule_id] = {
            "workflow_type": workflow_type,
            "target": target,
            "cron_expression": cron_expression,
            "parameters": parameters or {},
            "last_run": None,
            "next_run": None,
            "enabled": True
        }

        logger.info(f"Workflow programmé: {schedule_id} ({cron_expression})")

    async def start_scheduler(self):
        """Démarre le planificateur"""
        self.is_running = True
        logger.info("🕐 Planificateur de workflows démarré")

        while self.is_running:
            await self._check_scheduled_workflows()
            await asyncio.sleep(60)  # Vérifier toutes les minutes

    def stop_scheduler(self):
        """Arrête le planificateur"""
        self.is_running = False
        logger.info("🛑 Planificateur arrêté")

    async def _check_scheduled_workflows(self):
        """Vérifie et exécute les workflows programmés"""
        current_time = datetime.utcnow()

        for schedule_id, schedule_config in self.scheduled_workflows.items():
            if not schedule_config.get("enabled", True):
                continue

            # TODO: Implémenter la logique cron
            # Pour l'instant, utilisation d'un intervalle simple
            last_run = schedule_config.get("last_run")
            if not last_run or (current_time - last_run).total_seconds() > 3600:  # 1 heure
                await self._execute_scheduled_workflow(schedule_id, schedule_config)

    async def _execute_scheduled_workflow(self, schedule_id: str, config: Dict[str, Any]):
        """Exécute un workflow programmé"""
        try:
            logger.info(f"Exécution workflow programmé: {schedule_id}")

            workflow_id = await self.supervisor.start_workflow(
                workflow_type=config["workflow_type"],
                target=config["target"],
                parameters=config["parameters"],
                created_by=f"scheduler:{schedule_id}"
            )

            config["last_run"] = datetime.utcnow()
            logger.info(f"Workflow programmé lancé: {workflow_id}")

        except Exception as e:
            logger.error(f"Erreur workflow programmé {schedule_id}: {e}")

if __name__ == "__main__":
    # Tests et exemples d'utilisation
    async def test_supervisor():
        print("Test du superviseur")

        # Test scan rapide
        result = await quick_vulnerability_scan("127.0.0.1", "quick")
        print(f"Scan rapide: {result['success']}")

        # Test évaluation complète
        result = await complete_security_assessment("127.0.0.1", True)
        print(f"Évaluation complète: {result['success']}")

    # Lancer les tests
    asyncio.run(test_supervisor())