"""
Tâche Celery pour exécuter un script de remédiation via SSH (Semaines 9-10).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy.orm import Session

from src.workers.celery_app import celery_app
from src.core.executor import SSHExecutor
from src.database.init_db import SessionLocal
from src.database.models import RemediationScript
from src.integrations.webhooks import send_webhook_event
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _get_db() -> Session:
    return SessionLocal()


@celery_app.task(name="execute_remediation_script", bind=True)
def execute_remediation_script(self, script_id: str, ssh_params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Exécute un RemediationScript sur un asset via SSH.

    ssh_params attendus:
    - host
    - port (optionnel, 22 par défaut)
    - username
    - password
    - executed_by (UUID string de l'utilisateur)
    """
    db = _get_db()
    try:
        script_uuid = uuid.UUID(script_id)
    except ValueError:
        logger.error("ID de script invalide: %s", script_id)
        return {"status": "error", "message": "ID script invalide"}

    script: RemediationScript | None = (
        db.query(RemediationScript).filter(RemediationScript.id == script_uuid).first()
    )
    if not script:
        logger.error("Script %s introuvable", script_id)
        return {"status": "error", "message": "Script introuvable"}

    # Marquer comme running
    script.execution_status = "running"
    db.commit()

    host = ssh_params.get("host")
    username = ssh_params.get("username")
    password = ssh_params.get("password")
    port = int(ssh_params.get("port") or 22)

    if not host or not username or not password:
        logger.error("Paramètres SSH manquants pour le script %s", script_id)
        script.execution_status = "failed"
        script.execution_output = "Paramètres SSH manquants"
        db.commit()
        return {"status": "failed", "message": "Paramètres SSH manquants"}

    executor = SSHExecutor(
        hostname=host,
        username=username,
        password=password,
        port=port,
    )

    try:
        result = executor.execute(
            script_content=script.script_content,
            rollback_script=script.rollback_script,
            requires_sudo=script.requires_sudo,
        )

        script.executed_at = datetime.utcnow()
        exec_by = ssh_params.get("executed_by")
        if exec_by:
            try:
                script.executed_by = uuid.UUID(exec_by)
            except ValueError:
                pass

        script.exit_code = result.exit_code
        # Concaténer les sorties dans execution_output
        output_parts = [
            "=== STDOUT ===",
            result.stdout,
            "=== STDERR ===",
            result.stderr,
        ]
        if result.rollback_executed:
            output_parts.extend(
                [
                    "=== ROLLBACK STDOUT ===",
                    result.rollback_stdout or "",
                    "=== ROLLBACK STDERR ===",
                    result.rollback_stderr or "",
                ]
            )
        script.execution_output = "\n".join(output_parts)

        script.execution_status = "completed" if result.success else "failed"

        db.commit()

        # Webhook remediation_completed
        send_webhook_event(
            db,
            organization_id=script.organization_id,
            event_type="remediation_completed",
            payload={
                "script_id": str(script.id),
                "vulnerability_id": str(script.vulnerability_id) if script.vulnerability_id else None,
                "status": script.execution_status,
                "exit_code": script.exit_code,
                "created_at": datetime.utcnow().isoformat(),
            },
        )

        return {
            "status": script.execution_status,
            "exit_code": script.exit_code,
        }

    except Exception as exc:  # pragma: no cover - log only
        logger.error("Erreur exécution script %s: %s", script_id, exc)
        script.execution_status = "failed"
        script.execution_output = f"Erreur: {exc}"
        script.exit_code = -1
        db.commit()
        return {"status": "failed", "message": str(exc)}
    finally:
        db.close()


__all__ = ["execute_remediation_script"]

