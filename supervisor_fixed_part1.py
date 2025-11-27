"""
Module Supervisor pour l'Agent IA de Cybersécurité

Le Supervisor est le module central qui orchestre tous les autres modules :
- Collector (scan de vulnérabilités)
- Analyzer (analyse IA)
- Generator (génération de scripts)

Il fournit une interface unifiée pour exécuter des workflows complets
de détection, analyse et correction de vulnérabilités.
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

from config import get_config
from src.utils.logger import setup_logger
from src.database.database import Database
from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from .exceptions import SupervisorException, CoreErrorCodes, ERROR_MESSAGES, TASK_STATUS, OPERATION_TYPES

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
    scan_result: Optional[ScanResult] = None
    analysis_result: Optional[AnalysisResult] = None
    script_results: List[ScriptResult] = None
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
    """Superviseur central de l'Agent IA de Cybersécurité"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config()
        self.is_ready = False
        self.is_running = False
        self.collector: Optional[Collector] = None
        self.analyzer: Optional[Analyzer] = None
        self.generator: Optional[Generator] = None
        self.db = Database()
        self.active_workflows: Dict[str, WorkflowDefinition] = {}
        self.active_tasks: Dict[str, TaskInfo] = {}
        self.workflow_queue: List[str] = []
        self.max_concurrent_workflows = self.config.get('max_concurrent_workflows', 3)
        self.max_concurrent_tasks = self.config.get('max_concurrent_tasks', 5)
        self.progress_callbacks: Dict[str, Callable] = {}
        self.completion_callbacks: Dict[str, Callable] = {}
        self.stats = {
            "total_workflows": 0,
            "successful_workflows": 0,
            "failed_workflows": 0,
            "total_vulnerabilities_found": 0,
            "total_scripts_generated": 0,
            "average_workflow_time": 0.0,
            "uptime_start": datetime.utcnow()
        }
        self._initialize_modules()

    def _initialize_modules(self):
        """Initialise tous les modules core"""
        try:
            logger.info("Initialisation des modules core...")
            self.collector = Collector(self.config)
            logger.info("✅ Collector initialisé")
            self.analyzer = Analyzer(self.config)
            logger.info("✅ Analyzer initialisé")
            self.generator = Generator(self.config)
            logger.info("✅ Generator initialisé")
            self.is_ready = True
            logger.info("🚀 Supervisor initialisé avec succès")
        except Exception as e:
            logger.error(f"❌ Erreur initialisation modules: {e}")
            raise SupervisorException(f"Impossible d'initialiser les modules: {str(e)}", CoreErrorCodes.CORE_INIT_ERROR)

    async def start_workflow(self, workflow_type: WorkflowType, target: str,
                             parameters: Optional[Dict[str, Any]] = None,
                             priority: TaskPriority = TaskPriority.NORMAL, created_by: str = "system") -> str:
        """Lance un nouveau workflow"""
        if not self.is_ready:
            raise SupervisorException("Supervisor non initialisé", CoreErrorCodes.MODULE_NOT_READY)

        workflow_id = str(uuid.uuid4())
        parameters = parameters or {}

        try:
            workflow_def = self._create_workflow_definition(workflow_id, workflow_type, target, parameters, priority,
                                                            created_by)
            self.active_workflows[workflow_id] = workflow_def
            self.workflow_queue.append(workflow_id)

            if not self.is_running:
                asyncio.create_task(self._workflow_processor())

            logger.info(f"Workflow créé: {workflow_id} ({workflow_type.value})")
            return workflow_id
        except Exception as e:
            logger.error(f"Erreur création workflow: {e}")
            raise SupervisorException(f"Impossible de créer le workflow: {str(e)}", CoreErrorCodes.ORCHESTRATION_FAILED)

    def _create_workflow_definition(self, workflow_id: str, workflow_type: WorkflowType, target: str,
                                    parameters: Dict[str, Any], priority: TaskPriority,
                                    created_by: str) -> WorkflowDefinition:
        """Crée une définition de workflow"""
        tasks = self._get_workflow_tasks(workflow_type)
        estimated_duration = self._estimate_workflow_duration(workflow_type, parameters)

        return WorkflowDefinition(
            workflow_id=workflow_id, name=f"{workflow_type.value}_{target}", workflow_type=workflow_type,
            target=target, parameters=parameters, tasks=tasks, status=WorkflowStatus.PENDING,
            priority=priority, created_at=datetime.utcnow(), created_by=created_by,
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
            WorkflowType.CUSTOM: []
        }
        return task_definitions.get(workflow_type, [])

    def _estimate_workflow_duration(self, workflow_type: WorkflowType, parameters: Dict[str, Any]) -> int:
        """Estime la durée d'un workflow en secondes"""
        base_durations = {
            WorkflowType.SCAN_ONLY: 300,
            WorkflowType.SCAN_AND_ANALYZE: 480,
            WorkflowType.FULL_WORKFLOW: 600,
            WorkflowType.ANALYZE_EXISTING: 120,
            WorkflowType.GENERATE_SCRIPTS: 180,
            WorkflowType.CUSTOM: 300
        }
        base_duration = base_durations.get(workflow_type, 300)
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
                await self._process_pending_workflows()
                await self._check_active_workflows()
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

        active_count = len([wf for wf in self.active_workflows.values() if wf.status == WorkflowStatus.RUNNING])

        while active_count < self.max_concurrent_workflows and self.workflow_queue:
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

            workflow_result = WorkflowResult(
                workflow_id=workflow_id, workflow_type=workflow_def.workflow_type,
                target=workflow_def.target, status=WorkflowStatus.RUNNING,
                started_at=start_time, completed_at=None, duration=None
            )

            for task_name in workflow_def.tasks:
                await self._execute_task(workflow_id, task_name, workflow_def, workflow_result)

            end_time = datetime.utcnow()
            workflow_result.completed_at = end_time
            workflow_result.duration = (end_time - start_time).total_seconds()
            workflow_result.status = WorkflowStatus.COMPLETED
            workflow_def.status = WorkflowStatus.COMPLETED

            await self._save_workflow_result(workflow_result)
            self._update_workflow_stats(True, workflow_result.duration)
            await self._call_completion_callbacks(workflow_id, workflow_result)

            logger.info(f"✅ Workflow terminé: {workflow_id}")
        except Exception as e:
            logger.error(f"❌ Erreur workflow {workflow_id}: {e}")
            workflow_def.status = WorkflowStatus.FAILED
            self._update_workflow_stats(False, (datetime.utcnow() - start_time).total_seconds())
            await self._cleanup_workflow_tasks(workflow_id)

    async def _execute_task(self, workflow_id: str, task_name: str, workflow_def: WorkflowDefinition,
                            workflow_result: WorkflowResult):
        """Exécute une tâche spécifique"""
        task_id = f"{workflow_id}_{task_name}_{int(time.time())}"
        task_info = TaskInfo(
            task_id=task_id, workflow_id=workflow_id, task_type=task_name,
            status=TASK_STATUS["RUNNING"], priority=workflow_def.priority,
            created_at=datetime.utcnow(), started_at=datetime.utcnow()
        )
        self.active_tasks[task_id] = task_info

        try:
            logger.info(f"🔧 Exécution tâche: {task_name} ({workflow_id})")

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
                raise SupervisorException(f"Type de tâche inconnu: {task_name}", CoreErrorCodes.ORCHESTRATION_FAILED)

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
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]

    async def _execute_scan_task(self, workflow_def: WorkflowDefinition, task_info: TaskInfo) -> ScanResult:
        """Exécute une tâche de scan"""

        def progress_callback(progress: int):
            task_info.progress = progress
            self._call_progress_callbacks(workflow_def.workflow_id, "scan", progress)

        scan_type = workflow_def.parameters.get('scan_type', 'full')
        timeout = workflow_def.parameters.get('timeout', 3600)
        custom_args = workflow_def.parameters.get('nmap_args')

        result = await self.collector.scan_target(
            target=workflow_def.target, scan_type=scan_type,
            custom_args=custom_args, timeout=timeout,
            progress_callback=progress_callback
        )
        return result

    async def _execute_analyze_task(self, workflow_def: WorkflowDefinition, workflow_result: WorkflowResult,
                                    task_info: TaskInfo) -> AnalysisResult:
        """Exécute une tâche d'analyse"""
        if workflow_result.scan_result:
            all_vulnerabilities = [vuln.to_dict() for vuln in workflow_result.scan_result.vulnerabilities]
            max_vulns = self.config.get('max_vulnerabilities_to_analyze', 10)
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            sorted_vulns = sorted(all_vulnerabilities, key=lambda v: (
                severity_order.get(v.get('severity', 'UNKNOWN'), 4),
                -(float(v.get('cvss_score')) if v.get('cvss_score') is not None else 0.0)
            ))
            vulnerabilities_data = sorted_vulns[:max_vulns]
            logger.info(f"📊 Filtrage : {len(all_vulnerabilities)} → {len(vulnerabilities_data)} à analyser")
        else:
            vulnerabilities_data = workflow_def.parameters.get('vulnerabilities_data', [])

        if not vulnerabilities_data:
            raise SupervisorException("Aucune donnée de vulnérabilité", CoreErrorCodes.INVALID_VULNERABILITY_DATA)

        business_context = workflow_def.parameters.get('business_context')
        result = await self.analyzer.analyze_vulnerabilities_batch(
            vulnerabilities_data=vulnerabilities_data, target_system=workflow_def.target,
            business_context=business_context, batch_size=10
        )

        workflow_result.total_vulnerabilities = len(vulnerabilities_data)
        workflow_result.critical_vulnerabilities = len([v for v in result.vulnerabilities if v.severity == "CRITICAL"])
        task_info.progress = 100
        return result

    async def _execute_generate_task(self, workflow_def: WorkflowDefinition, workflow_result: WorkflowResult,
                                     task_info: TaskInfo) -> List[ScriptResult]:
        """Exécute une tâche de génération de scripts"""
        vulnerabilities = []
        if workflow_result.analysis_result:
            vulnerabilities = workflow_result.analysis_result.vulnerabilities
        elif workflow_result.scan_result:
            vulnerabilities = workflow_result.scan_result.vulnerabilities
        else:
            vuln_data = workflow_def.parameters.get('vulnerabilities_data', [])
            vulnerabilities = vuln_data

        if not vulnerabilities:
            raise SupervisorException("Aucune vulnérabilité disponible", CoreErrorCodes.INVALID_VULNERABILITY_DATA)

        target_system = workflow_def.parameters.get('target_system', 'ubuntu')
        risk_tolerance = workflow_def.parameters.get('risk_tolerance', 'low')
        max_scripts = self.config.get('max_scripts_to_generate', 5)

        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        sorted_vulnerabilities = sorted(vulnerabilities, key=lambda v: (
            severity_order.get(getattr(v, 'severity', 'UNKNOWN'), 4),
            -(getattr(v, 'cvss_score', 0.0) or 0.0)
        ))
        vulnerabilities_to_process = sorted_vulnerabilities[:max_scripts]

        logger.info(f"Génération de {len(vulnerabilities_to_process)} scripts")
        script_results = []

        for i, vulnerability in enumerate(vulnerabilities_to_process):
            try:
                vuln_details = vulnerability.to_dict() if hasattr(vulnerability, 'to_dict') else vulnerability
                script_result = await self.generator.generate_fix_script(
                    vulnerability_id=vuln_details.get('vulnerability_id', f'vuln_{i}'),
                    vulnerability_details=vuln_details, target_system=target_system,
                    risk_tolerance=risk_tolerance
                )
                script_results.append(script_result)

                if i < len(vulnerabilities_to_process) - 1:
                    await asyncio.sleep(2)

                progress = int((i + 1) / len(vulnerabilities_to_process) * 100)
                task_info.progress = progress
                self._call_progress_callbacks(workflow_def.workflow_id, "generate_scripts", progress)
            except Exception as e:
                logger.warning(f"Erreur génération script {i}: {e}")
                continue

        workflow_result.scripts_generated = len(script_results)
        return script_results

    async def _check_active_workflows(self):
        """Vérifie l'état des workflows actifs"""
        for workflow_id, workflow_def in list(self.active_workflows.items()):
            if workflow_def.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]:
                if (datetime.utcnow() - workflow_def.created_at).total_seconds() > 3600:
                    del self.active_workflows[workflow_id]
                    logger.debug(f"Workflow nettoyé: {workflow_id}")

    async def _cleanup_workflow_tasks(self, workflow_id: str):
        """Nettoie les tâches d'un workflow"""
        tasks_to_remove = [task_id for task_id, task_info in self.active_tasks.items()
                           if task_info.workflow_id == workflow_id]
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
            logger.debug(f"Sauvegarde workflow: {result.workflow_id}")
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
        current_avg = self.stats["average_workflow_time"]
        total = self.stats["total_workflows"]
        self.stats["average_workflow_time"] = (current_avg * (total - 1) + duration) / total