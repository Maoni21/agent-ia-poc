"""
Worker Celery pour l'exécution SSH automatisée du plan de remédiation.

Flow:
1. Récupérer RemediationPlan + Asset + credentials SSH
2. Connexion SSH
3. Pour chaque étape du plan :
   - Créer RemediationExecution
   - Exécuter la commande via SSH
   - Si erreur → rollback + stop
   - Mettre à jour la progression
4. Marquer le plan comme terminé
5. Lancer le worker de validation
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List

from src.workers.celery_app import celery_app
from src.database.init_db import SessionLocal
from src.database.models import Asset, Scan, RemediationPlan, RemediationExecution
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


@celery_app.task(name="execute_remediation_plan", bind=True)
def execute_remediation_plan(self, plan_id: str) -> Dict[str, Any]:
    """
    Tâche Celery : exécute le plan de remédiation step-by-step via SSH.
    """
    db = SessionLocal()
    ssh_manager = None

    try:
        plan_uuid = uuid.UUID(plan_id)
        plan: RemediationPlan | None = (
            db.query(RemediationPlan)
            .filter(RemediationPlan.id == plan_uuid)
            .first()
        )
        if not plan:
            logger.error("Plan introuvable: %s", plan_id)
            return {"status": "error", "message": "Plan introuvable"}

        scan = db.query(Scan).filter(Scan.id == plan.scan_id).first()
        if not scan:
            logger.error("Scan introuvable pour le plan %s", plan_id)
            return {"status": "error"}

        asset: Asset | None = db.query(Asset).filter(Asset.id == scan.asset_id).first()
        if not asset:
            logger.error("Asset introuvable pour le plan %s", plan_id)
            return {"status": "error"}

        # Décrypter les credentials SSH
        from src.utils.crypto import decrypt_value
        from src.utils.ssh_manager import SSHManager, SSHConnectionError

        ssh_username = asset.ssh_username
        ssh_password = decrypt_value(asset.ssh_password) if asset.ssh_password else None
        ssh_private_key = decrypt_value(asset.ssh_private_key) if asset.ssh_private_key else None
        ssh_host = str(asset.ip_address)
        ssh_port = getattr(asset, "ssh_port", None) or 22

        if not ssh_username:
            logger.error("Credentials SSH manquants pour l'asset %s", asset.id)
            plan.status = "failed"
            db.commit()
            return {"status": "error", "message": "Credentials SSH non configurés"}

        # Connexion SSH
        ssh_manager = SSHManager(
            host=ssh_host,
            port=ssh_port,
            username=ssh_username,
            password=ssh_password,
            private_key=ssh_private_key,
        )

        try:
            ssh_manager.connect()
        except SSHConnectionError as e:
            logger.error("Connexion SSH échouée pour le plan %s: %s", plan_id, e)
            plan.status = "failed"
            db.commit()
            return {"status": "error", "message": str(e)}

        # Marquer comme en cours
        plan.status = "executing"
        plan.started_at = datetime.utcnow()
        db.commit()

        # Récupérer les étapes du plan
        execution_plan = plan.execution_plan or {}
        phases = execution_plan.get("phases", [])

        all_steps: List[Dict[str, Any]] = []
        for phase in phases:
            all_steps.extend(phase.get("steps", []))

        total_steps = len(all_steps)
        if total_steps == 0:
            logger.warning("Aucune étape dans le plan %s", plan_id)
            plan.status = "completed"
            plan.completed_at = datetime.utcnow()
            db.commit()
            return {"status": "completed", "total_steps": 0}

        logger.info("Début exécution: %d étapes pour le plan %s", total_steps, plan_id)

        completed_count = 0
        failed = False

        for step in all_steps:
            step_number = step.get("step_number", 0)
            step_name = step.get("title") or step.get("action") or f"Étape {step_number}"
            command = step.get("command", "")
            rollback_cmd = step.get("rollback", "")

            # Créer l'enregistrement d'exécution
            execution = RemediationExecution(
                id=uuid.uuid4(),
                remediation_plan_id=plan.id,
                step_number=step_number,
                step_name=step_name,
                script_content=command,
                rollback_script=rollback_cmd,
                status="running",
                started_at=datetime.utcnow(),
            )
            db.add(execution)
            db.commit()

            # Mise à jour Celery
            self.update_state(
                state="PROGRESS",
                meta={
                    "current_step": step_number,
                    "total_steps": total_steps,
                    "step_name": step_name,
                    "progress": int(completed_count / total_steps * 100),
                },
            )

            # Exécuter la commande via SSH
            try:
                if not command or command.startswith("#"):
                    # Commande placeholder → marquer comme skipped
                    execution.status = "skipped"
                    execution.exit_code = 0
                    execution.stdout = "(skipped - commande placeholder)"
                else:
                    stdout, stderr, exit_code = ssh_manager.execute_command(
                        command,
                        timeout=step.get("timeout", 300),
                    )
                    execution.stdout = stdout[:10000] if stdout else ""
                    execution.stderr = stderr[:5000] if stderr else ""
                    execution.exit_code = exit_code

                    if exit_code != 0:
                        logger.warning(
                            "Étape %d échouée (exit_code=%d): %s",
                            step_number, exit_code, stderr[:200],
                        )
                        # Rollback si disponible
                        if rollback_cmd and not rollback_cmd.startswith("#"):
                            try:
                                ssh_manager.execute_command(rollback_cmd, timeout=120)
                                execution.status = "rolled_back"
                            except Exception as rb_err:
                                logger.error("Rollback échoué pour étape %d: %s", step_number, rb_err)
                                execution.status = "failed"
                        else:
                            execution.status = "failed"

                        failed = True
                    else:
                        execution.status = "completed"
                        completed_count += 1

            except Exception as e:
                logger.error("Exception lors de l'exécution de l'étape %d: %s", step_number, e)
                execution.status = "failed"
                execution.stderr = str(e)
                execution.exit_code = -1
                failed = True

            execution.completed_at = datetime.utcnow()
            if execution.started_at:
                execution.duration = int(
                    (execution.completed_at - execution.started_at).total_seconds()
                )
            db.add(execution)
            db.commit()

            if failed:
                logger.error("Plan %s interrompu à l'étape %d", plan_id, step_number)
                break

        # Finaliser le plan
        plan.status = "completed" if not failed else "failed"
        plan.completed_at = datetime.utcnow()
        db.add(plan)
        db.commit()

        logger.info(
            "Plan %s terminé: status=%s completed=%d/%d",
            plan_id, plan.status, completed_count, total_steps,
        )

        # Lancer le scan de validation si succès
        if not failed:
            try:
                from src.workers.validation_worker import run_validation_scan
                run_validation_scan.delay(plan_id)
            except Exception as e:
                logger.error("Impossible de lancer la validation: %s", e)

        return {
            "status": plan.status,
            "completed_steps": completed_count,
            "total_steps": total_steps,
        }

    except Exception as e:
        logger.error("Erreur inattendue pour le plan %s: %s", plan_id, e, exc_info=True)
        try:
            if plan:
                plan.status = "failed"
                plan.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
        return {"status": "error", "message": str(e)}

    finally:
        if ssh_manager:
            ssh_manager.disconnect()
        db.close()


__all__ = ["execute_remediation_plan"]
