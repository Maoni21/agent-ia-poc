"""
Routes pour la gestion des plans de remédiation et leur exécution.

Endpoints:
- GET  /api/v1/scripts                                 : liste tous les scripts générés
- GET  /api/v1/scripts/{script_id}                     : détail d'un script (RemediationExecution)
- GET  /api/v1/remediation-plan/{scan_id}              : récupère le plan généré
- POST /api/v1/remediation-plan/{plan_id}/approve      : approuve et lance l'exécution
- GET  /api/v1/remediation-execution/{plan_id}/status  : statut de l'exécution
- POST /api/v1/assets/{asset_id}/test-ssh              : teste la connexion SSH
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db, SessionLocal
from src.database.models import (
    Asset, Scan, Vulnerability, RemediationPlan, RemediationExecution
)
from src.api.dependencies import get_current_user, require_permission
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["remediation"])
ws_router = APIRouter()


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _calculate_security_score(vulns: List[Vulnerability]) -> int:
    """
    Calcule un score de sécurité de 0 à 100 à partir des vulnérabilités.
    Plus le score est élevé, meilleure est la sécurité.
    """
    if not vulns:
        return 100

    weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    penalty = sum(weights.get(v.severity, 0) for v in vulns)
    score = max(0, 100 - penalty)
    return score


# ──────────────────────────────────────────────────────────────────────────────
# Test SSH
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/assets/{asset_id}/test-ssh",
    dependencies=[Depends(require_permission("assets:read"))],
)
def test_ssh_connection(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Teste la connexion SSH d'un asset et vérifie les droits sudo.
    """
    org_id = current_user["organization_id"]

    try:
        asset_uuid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="asset_id invalide")

    asset: Optional[Asset] = (
        db.query(Asset)
        .filter(Asset.id == asset_uuid, Asset.organization_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=404, detail="Asset introuvable")

    if not asset.ssh_username:
        raise HTTPException(status_code=400, detail="Aucune configuration SSH pour cet asset")

    try:
        from src.utils.ssh_manager import SSHManager
        from src.utils.crypto import decrypt_value

        password = decrypt_value(asset.ssh_password) if asset.ssh_password else None
        private_key = decrypt_value(asset.ssh_private_key) if asset.ssh_private_key else None
        ssh_host = str(asset.ip_address)
        ssh_port = getattr(asset, "ssh_port", None) or 22

        manager = SSHManager(
            host=ssh_host,
            port=ssh_port,
            username=asset.ssh_username,
            password=password,
            private_key=private_key,
        )
        result = manager.test_connection()
        return {
            "asset_id": asset_id,
            "connected": result["connected"],
            "sudo_available": result["sudo_available"],
            "whoami": result.get("whoami"),
            "error": result.get("error"),
        }
    except Exception as e:
        logger.error("Erreur test SSH pour asset %s: %s", asset_id, e)
        return {
            "asset_id": asset_id,
            "connected": False,
            "sudo_available": False,
            "error": str(e),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Scripts générés (RemediationExecution)
# ──────────────────────────────────────────────────────────────────────────────

@router.get(
    "/scripts",
    dependencies=[Depends(require_permission("scans:read"))],
)
def list_scripts(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne tous les scripts de remédiation générés pour l'organisation,
    issus des étapes d'exécution (RemediationExecution).
    """
    org_id = current_user["organization_id"]

    # Joindre RemediationExecution → RemediationPlan pour filtrer par org
    query = (
        db.query(RemediationExecution, RemediationPlan, Scan)
        .join(RemediationPlan, RemediationExecution.remediation_plan_id == RemediationPlan.id)
        .join(Scan, RemediationPlan.scan_id == Scan.id)
        .filter(RemediationPlan.organization_id == org_id)
    )

    if status:
        query = query.filter(RemediationExecution.status == status)

    total = query.count()
    rows = (
        query
        .order_by(RemediationExecution.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    scripts = []
    for execution, plan, scan in rows:
        scripts.append({
            "id": str(execution.id),
            "step_number": execution.step_number,
            "step_name": execution.step_name,
            "script_content": execution.script_content,
            "rollback_script": execution.rollback_script,
            "status": execution.status,
            "exit_code": execution.exit_code,
            "duration": execution.duration,
            "stdout": execution.stdout,
            "stderr": execution.stderr,
            "started_at": execution.started_at.isoformat() if execution.started_at else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "created_at": execution.created_at.isoformat() if execution.created_at else None,
            "plan_id": str(plan.id),
            "plan_status": plan.status,
            "scan_id": str(scan.id),
            "asset_id": str(scan.asset_id) if scan.asset_id else None,
        })

    return {
        "scripts": scripts,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get(
    "/scripts/{script_id}",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_script(
    script_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne le détail d'un script de remédiation par son ID.
    """
    org_id = current_user["organization_id"]

    try:
        script_uuid = uuid.UUID(script_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="script_id invalide")

    row = (
        db.query(RemediationExecution, RemediationPlan, Scan)
        .join(RemediationPlan, RemediationExecution.remediation_plan_id == RemediationPlan.id)
        .join(Scan, RemediationPlan.scan_id == Scan.id)
        .filter(
            RemediationExecution.id == script_uuid,
            RemediationPlan.organization_id == org_id,
        )
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Script introuvable")

    execution, plan, scan = row
    return {
        "id": str(execution.id),
        "step_number": execution.step_number,
        "step_name": execution.step_name,
        "script_content": execution.script_content,
        "rollback_script": execution.rollback_script,
        "status": execution.status,
        "exit_code": execution.exit_code,
        "duration": execution.duration,
        "stdout": execution.stdout,
        "stderr": execution.stderr,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        "created_at": execution.created_at.isoformat() if execution.created_at else None,
        "plan_id": str(plan.id),
        "plan_status": plan.status,
        "scan_id": str(scan.id),
        "asset_id": str(scan.asset_id) if scan.asset_id else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Plan de remédiation
# ──────────────────────────────────────────────────────────────────────────────

@router.get(
    "/remediation-plan/{scan_id}",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_remediation_plan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Récupère le plan de remédiation généré pour un scan.
    """
    org_id = current_user["organization_id"]

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="scan_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.scan_id == scan_uuid, RemediationPlan.organization_id == org_id)
        .order_by(RemediationPlan.created_at.desc())
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Aucun plan de remédiation trouvé pour ce scan")

    return _serialize_plan(plan)


@router.get(
    "/remediation-plan/by-id/{plan_id}",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_remediation_plan_by_id(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Récupère un plan de remédiation par son ID.
    """
    org_id = current_user["organization_id"]

    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="plan_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.id == plan_uuid, RemediationPlan.organization_id == org_id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Plan de remédiation introuvable")

    return _serialize_plan(plan)


def _serialize_plan(plan: RemediationPlan) -> Dict[str, Any]:
    """Sérialise un plan de remédiation pour l'API."""
    execution_plan = plan.execution_plan or {}
    phases = execution_plan.get("phases", [])

    # Calculer les totaux
    total_steps = sum(len(p.get("steps", [])) for p in phases)

    return {
        "plan_id": str(plan.id),
        "scan_id": str(plan.scan_id),
        "status": plan.status,
        "executive_summary": execution_plan.get("executive_summary", {
            "priority": "UNKNOWN",
            "total_fixes": total_steps,
            "estimated_duration": plan.estimated_duration or 0,
            "estimated_downtime": plan.estimated_downtime or 0,
        }),
        "phases": phases,
        "estimated_duration": plan.estimated_duration,
        "estimated_downtime": plan.estimated_downtime,
        "created_at": plan.created_at.isoformat() if plan.created_at else None,
        "approved_at": plan.approved_at.isoformat() if plan.approved_at else None,
        "started_at": plan.started_at.isoformat() if plan.started_at else None,
        "completed_at": plan.completed_at.isoformat() if plan.completed_at else None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Approbation et exécution
# ──────────────────────────────────────────────────────────────────────────────

@router.post(
    "/remediation-plan/{plan_id}/approve",
    dependencies=[Depends(require_permission("assets:update"))],
)
def approve_remediation_plan(
    plan_id: str,
    body: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Approuve un plan de remédiation et lance l'exécution automatisée.

    Body JSON:
    - confirmed (bool, obligatoire) : doit être true
    - security_code (str, optionnel) : code de sécurité à 6 chiffres
    """
    org_id = current_user["organization_id"]

    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="plan_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.id == plan_uuid, RemediationPlan.organization_id == org_id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Plan introuvable")

    if plan.status not in ("pending_approval", "analyzing"):
        raise HTTPException(
            status_code=400,
            detail=f"Ce plan ne peut plus être approuvé (statut: {plan.status})",
        )

    if not body.get("confirmed"):
        raise HTTPException(status_code=400, detail="L'approbation doit être confirmée explicitement")

    # Mettre à jour le plan
    plan.status = "approved"
    plan.approved_by = current_user.get("id")
    plan.approved_at = datetime.utcnow()
    db.commit()

    # Lancer le worker d'exécution
    try:
        from src.workers.remediation_worker import execute_remediation_plan
        execute_remediation_plan.delay(str(plan.id))
        plan.status = "executing"
        plan.started_at = datetime.utcnow()
        db.commit()
    except Exception as e:
        logger.error("Impossible de lancer le worker de remédiation: %s", e)

    logger.info("Plan de remédiation approuvé et exécution lancée: plan=%s", plan_id)

    return {
        "plan_id": plan_id,
        "status": plan.status,
        "message": "Plan approuvé. Exécution en cours...",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Statut de l'exécution
# ──────────────────────────────────────────────────────────────────────────────

@router.get(
    "/remediation-execution/{plan_id}/status",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_execution_status(
    plan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne le statut détaillé de l'exécution d'un plan.
    """
    org_id = current_user["organization_id"]

    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="plan_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.id == plan_uuid, RemediationPlan.organization_id == org_id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Plan introuvable")

    executions = (
        db.query(RemediationExecution)
        .filter(RemediationExecution.remediation_plan_id == plan.id)
        .order_by(RemediationExecution.step_number)
        .all()
    )

    total_steps = len(executions)
    completed_steps = [e for e in executions if e.status == "completed"]
    current_step = next(
        (e for e in executions if e.status == "running"),
        next((e for e in executions if e.status == "pending"), None),
    )

    overall_progress = int(len(completed_steps) / total_steps * 100) if total_steps > 0 else 0

    return {
        "plan_id": plan_id,
        "status": plan.status,
        "overall_progress": overall_progress,
        "current_step": current_step.step_number if current_step else None,
        "total_steps": total_steps,
        "step_name": current_step.step_name if current_step else None,
        "started_at": plan.started_at.isoformat() if plan.started_at else None,
        "completed_at": plan.completed_at.isoformat() if plan.completed_at else None,
        "estimated_time_remaining": max(
            0, ((total_steps - len(completed_steps)) * 90)  # ~90s par step
        ),
        "completed_steps": [
            {
                "step": e.step_number,
                "name": e.step_name,
                "status": e.status,
                "duration": e.duration,
                "exit_code": e.exit_code,
            }
            for e in completed_steps
        ],
        "all_steps": [
            {
                "step": e.step_number,
                "name": e.step_name,
                "status": e.status,
                "stdout": e.stdout,
                "stderr": e.stderr,
                "exit_code": e.exit_code,
                "duration": e.duration,
            }
            for e in executions
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# WebSocket temps réel pour l'exécution
# ──────────────────────────────────────────────────────────────────────────────

@ws_router.websocket("/ws/remediation/{plan_id}")
async def websocket_remediation_progress(websocket: WebSocket, plan_id: str):
    """
    WebSocket qui publie la progression de l'exécution du plan en temps réel.
    Polling de la base de données toutes les 2 secondes.
    """
    await websocket.accept()

    try:
        plan_uuid = uuid.UUID(plan_id)
    except ValueError:
        await websocket.close(code=1008, reason="plan_id invalide")
        return

    try:
        while True:
            db: Session = SessionLocal()
            try:
                plan = db.query(RemediationPlan).filter(RemediationPlan.id == plan_uuid).first()
                if not plan:
                    await websocket.send_json({
                        "type": "error",
                        "data": {"message": "Plan introuvable"},
                    })
                    break

                executions = (
                    db.query(RemediationExecution)
                    .filter(RemediationExecution.remediation_plan_id == plan.id)
                    .order_by(RemediationExecution.step_number)
                    .all()
                )

                total_steps = len(executions)
                completed = [e for e in executions if e.status == "completed"]
                current = next((e for e in executions if e.status == "running"), None)

                # Dernière entrée de log
                last_log = None
                if current:
                    last_log = f"[{datetime.utcnow().strftime('%H:%M:%S')}] Exécution: {current.step_name}..."
                elif completed:
                    last_e = completed[-1]
                    last_log = f"[{datetime.utcnow().strftime('%H:%M:%S')}] ✅ {last_e.step_name} terminé"

                await websocket.send_json({
                    "type": "remediation_progress",
                    "data": {
                        "plan_id": plan_id,
                        "status": plan.status,
                        "overall_progress": int(len(completed) / total_steps * 100) if total_steps > 0 else 0,
                        "current_step": current.step_number if current else None,
                        "total_steps": total_steps,
                        "step_name": current.step_name if current else None,
                        "log_entry": last_log,
                        "completed_steps": [
                            {"step": e.step_number, "name": e.step_name, "status": e.status}
                            for e in completed
                        ],
                    },
                })

                if plan.status in ("completed", "failed", "cancelled"):
                    break

            finally:
                db.close()

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error("Erreur WebSocket remédiation %s: %s", plan_id, e)
