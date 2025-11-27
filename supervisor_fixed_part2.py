# === MÉTHODES PUBLIQUES ===

async def run_scan(self, target: str, scan_type: str = "full",
                   progress_callback: Optional[Callable[[int], None]] = None) -> ScanResult:
    """Lance un scan simple"""
    workflow_id = await self.start_workflow(WorkflowType.SCAN_ONLY, target, {"scan_type": scan_type})
    if progress_callback:
        self.progress_callbacks[workflow_id] = lambda task, progress: progress_callback(progress)
    result = await self.wait_for_workflow(workflow_id)
    return result.scan_result if result and result.scan_result else None


async def analyze_vulnerabilities(self, vulnerabilities_data: List[Dict[str, Any]],
                                  target_system: str = "Unknown System") -> AnalysisResult:
    """Lance une analyse de vulnérabilités"""
    workflow_id = await self.start_workflow(WorkflowType.ANALYZE_EXISTING, target_system,
                                            {"vulnerabilities_data": vulnerabilities_data})
    result = await self.wait_for_workflow(workflow_id)
    return result.analysis_result


async def generate_fix_script(self, vulnerability_id: str, target_system: str = "ubuntu") -> ScriptResult:
    """Génère un script de correction"""
    workflow_id = await self.start_workflow(WorkflowType.GENERATE_SCRIPTS, target_system,
                                            {"vulnerabilities_data": [{"vulnerability_id": vulnerability_id}],
                                             "target_system": target_system})
    result = await self.wait_for_workflow(workflow_id)
    return result.script_results[0] if result.script_results else None


async def run_complete_workflow(self, target: str, scan_type: str = "full",
                                progress_callback: Optional[Callable[[str, int], None]] = None) -> WorkflowResult:
    """Lance un workflow complet"""
    workflow_id = await self.start_workflow(WorkflowType.FULL_WORKFLOW, target, {"scan_type": scan_type})
    if progress_callback:
        self.progress_callbacks[workflow_id] = progress_callback
    return await self.wait_for_workflow(workflow_id)


async def wait_for_workflow(self, workflow_id: str, timeout: int = 3600) -> WorkflowResult:
    """Attend la fin d'un workflow"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if workflow_id not in self.active_workflows:
            raise SupervisorException(f"Workflow non trouvé: {workflow_id}", CoreErrorCodes.ORCHESTRATION_FAILED)
        workflow_def = self.active_workflows[workflow_id]
        if workflow_def.status == WorkflowStatus.COMPLETED:
            return await self._load_workflow_result(workflow_id)
        elif workflow_def.status == WorkflowStatus.FAILED:
            raise SupervisorException(f"Workflow échoué: {workflow_id}", CoreErrorCodes.WORKFLOW_INTERRUPTED)
        await asyncio.sleep(1)
    raise SupervisorException(f"Timeout workflow: {workflow_id}", CoreErrorCodes.WORKFLOW_INTERRUPTED)


async def _load_workflow_result(self, workflow_id: str) -> WorkflowResult:
    """Charge le résultat d'un workflow depuis le stockage - VERSION FIXÉE"""
    try:
        results_dir = Path("data/workflow_results")
        result_file = results_dir / f"{workflow_id}.json"

        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            result = WorkflowResult(
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

            # ============================================================
            # FIX : RECHARGER analysis_result depuis le JSON
            # ============================================================
            if 'analysis_result' in data and data['analysis_result']:
                analysis_data = data['analysis_result']
                from src.core.analyzer import VulnerabilityAnalysis, AnalysisResult

                vulnerabilities = []
                for vuln_dict in analysis_data.get('vulnerabilities', []):
                    vuln = VulnerabilityAnalysis(
                        vulnerability_id=vuln_dict['vulnerability_id'],
                        name=vuln_dict['name'],
                        severity=vuln_dict['severity'],
                        cvss_score=vuln_dict['cvss_score'],
                        impact_analysis=vuln_dict['impact_analysis'],
                        exploitability=vuln_dict['exploitability'],
                        priority_score=vuln_dict['priority_score'],
                        affected_service=vuln_dict['affected_service'],
                        recommended_actions=vuln_dict.get('recommended_actions', []),
                        dependencies=vuln_dict.get('dependencies', []),
                        references=vuln_dict.get('references', []),
                        cvss_vector=vuln_dict.get('cvss_vector'),
                        nist_verified=vuln_dict.get('nist_verified', False),
                        nist_url=vuln_dict.get('nist_url'),
                        solution_links=vuln_dict.get('solution_links', []),
                        ai_explanation=vuln_dict.get('ai_explanation'),
                        correction_script=vuln_dict.get('correction_script'),
                        rollback_script=vuln_dict.get('rollback_script'),
                        business_impact=vuln_dict.get('business_impact')
                    )
                    vulnerabilities.append(vuln)

                result.analysis_result = AnalysisResult(
                    analysis_id=analysis_data['analysis_id'],
                    target_system=analysis_data['target_system'],
                    analyzed_at=datetime.fromisoformat(analysis_data['analyzed_at']),
                    analysis_summary=analysis_data['analysis_summary'],
                    vulnerabilities=vulnerabilities,
                    remediation_plan=analysis_data['remediation_plan'],
                    ai_model_used=analysis_data['ai_model_used'],
                    confidence_score=analysis_data['confidence_score'],
                    processing_time=analysis_data['processing_time'],
                    business_context=analysis_data.get('business_context'),
                    nist_enriched=analysis_data.get('nist_enriched', False),
                    nist_call_count=analysis_data.get('nist_call_count', 0),
                    nist_cache_hits=analysis_data.get('nist_cache_hits', 0)
                )
                logger.info(f"✅ analysis_result rechargé: {len(vulnerabilities)} vulnérabilités")

            return result
        else:
            workflow_def = self.active_workflows[workflow_id]
            return WorkflowResult(
                workflow_id=workflow_id, workflow_type=workflow_def.workflow_type,
                target=workflow_def.target, status=workflow_def.status,
                started_at=workflow_def.created_at, completed_at=None, duration=None
            )
    except Exception as e:
        logger.error(f"Erreur chargement workflow: {e}")
        raise


def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
    """Récupère le statut d'un workflow"""
    if workflow_id not in self.active_workflows:
        return {"error": "Workflow non trouvé"}
    workflow_def = self.active_workflows[workflow_id]
    total_progress = 0
    completed_tasks = 0
    for task_id, task_info in self.active_tasks.items():
        if task_info.workflow_id == workflow_id:
            total_progress += task_info.progress
            if task_info.status == TASK_STATUS["COMPLETED"]:
                completed_tasks += 1
    overall_progress = total_progress // len(workflow_def.tasks) if workflow_def.tasks else 0
    return {
        "workflow_id": workflow_id, "status": workflow_def.status.value,
        "progress": overall_progress, "target": workflow_def.target,
        "workflow_type": workflow_def.workflow_type.value,
        "created_at": workflow_def.created_at.isoformat(),
        "estimated_duration": workflow_def.estimated_duration,
        "completed_tasks": completed_tasks, "total_tasks": len(workflow_def.tasks),
        "current_tasks": [{
            "task_id": task_info.task_id, "task_type": task_info.task_type,
            "status": task_info.status, "progress": task_info.progress
        } for task_info in self.active_tasks.values() if task_info.workflow_id == workflow_id]
    }


def list_workflows(self, status_filter: Optional[WorkflowStatus] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Liste les workflows"""
    workflows = []
    for workflow_def in self.active_workflows.values():
        if status_filter and workflow_def.status != status_filter:
            continue
        workflows.append({
            "workflow_id": workflow_def.workflow_id, "name": workflow_def.name,
            "workflow_type": workflow_def.workflow_type.value, "target": workflow_def.target,
            "status": workflow_def.status.value, "priority": workflow_def.priority.value,
            "created_at": workflow_def.created_at.isoformat(), "created_by": workflow_def.created_by,
            "estimated_duration": workflow_def.estimated_duration
        })
    workflows.sort(key=lambda w: w["created_at"], reverse=True)
    return workflows[:limit]


async def cancel_workflow(self, workflow_id: str) -> bool:
    """Annule un workflow"""
    if workflow_id not in self.active_workflows:
        return False
    workflow_def = self.active_workflows[workflow_id]
    if workflow_def.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]:
        return False
    workflow_def.status = WorkflowStatus.CANCELLED
    await self._cleanup_workflow_tasks(workflow_id)
    if workflow_id in self.workflow_queue:
        self.workflow_queue.remove(workflow_id)
    logger.info(f"Workflow annulé: {workflow_id}")
    return True


async def pause_workflow(self, workflow_id: str) -> bool:
    """Met en pause un workflow"""
    if workflow_id not in self.active_workflows:
        return False
    workflow_def = self.active_workflows[workflow_id]
    if workflow_def.status == WorkflowStatus.RUNNING:
        workflow_def.status = WorkflowStatus.PAUSED
        logger.info(f"Workflow mis en pause: {workflow_id}")
        return True
    return False


async def resume_workflow(self, workflow_id: str) -> bool:
    """Reprend un workflow en pause"""
    if workflow_id not in self.active_workflows:
        return False
    workflow_def = self.active_workflows[workflow_id]
    if workflow_def.status == WorkflowStatus.PAUSED:
        workflow_def.status = WorkflowStatus.PENDING
        if workflow_id not in self.workflow_queue:
            self.workflow_queue.append(workflow_id)
        logger.info(f"Workflow repris: {workflow_id}")
        return True
    return False


def set_progress_callback(self, workflow_id: str, callback: Callable[[str, int], None]):
    """Définit un callback de progression"""
    self.progress_callbacks[workflow_id] = callback


def set_completion_callback(self, workflow_id: str, callback: Callable[[WorkflowResult], None]):
    """Définit un callback de fin"""
    self.completion_callbacks[workflow_id] = callback


def get_stats(self) -> Dict[str, Any]:
    """Retourne les statistiques"""
    uptime = (datetime.utcnow() - self.stats["uptime_start"]).total_seconds()
    return {
        **self.stats, "uptime_seconds": uptime, "active_workflows": len(self.active_workflows),
        "queued_workflows": len(self.workflow_queue), "active_tasks": len(self.active_tasks),
        "modules_status": {
            "collector": self.collector.is_healthy() if self.collector else False,
            "analyzer": self.analyzer.is_healthy() if self.analyzer else False,
            "generator": self.generator.is_healthy() if self.generator else False
        }
    }


def get_module_stats(self) -> Dict[str, Dict[str, Any]]:
    """Retourne les statistiques des modules"""
    return {
        "collector": self.collector.get_stats() if self.collector else {},
        "analyzer": self.analyzer.get_stats() if self.analyzer else {},
        "generator": self.generator.get_stats() if self.generator else {}
    }


def is_healthy(self) -> bool:
    """Vérifie si le superviseur est en bonne santé"""
    if not self.is_ready:
        return False
    return all([
        self.collector and self.collector.is_healthy(),
        self.analyzer and self.analyzer.is_healthy(),
        self.generator and self.generator.is_healthy()
    ])


async def shutdown(self):
    """Arrête proprement le superviseur"""
    logger.info("🛑 Arrêt du superviseur...")
    self.is_running = False
    for workflow_id in list(self.active_workflows.keys()):
        await self.cancel_workflow(workflow_id)
    self.active_workflows.clear()
    self.active_tasks.clear()
    self.workflow_queue.clear()
    self.progress_callbacks.clear()
    self.completion_callbacks.clear()
    logger.info("✅ Superviseur arrêté")


# === FONCTIONS UTILITAIRES ===

async def quick_vulnerability_scan(target: str, scan_type: str = "quick") -> Dict[str, Any]:
    """Scan rapide"""
    supervisor = Supervisor()
    try:
        result = await supervisor.run_scan(target, scan_type)
        return {
            "success": True, "target": target,
            "vulnerabilities_found": len(result.vulnerabilities),
            "scan_duration": result.duration,
            "vulnerabilities": [vuln.to_dict() for vuln in result.vulnerabilities]
        }
    except Exception as e:
        return {"success": False, "error": str(e), "target": target}
    finally:
        await supervisor.shutdown()


def create_supervisor(config: Optional[Dict[str, Any]] = None) -> Supervisor:
    """Factory pour créer un superviseur"""
    return Supervisor(config)