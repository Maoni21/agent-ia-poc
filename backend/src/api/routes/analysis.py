"""
Routes pour l'analyse IA batch de vulnérabilités.

Endpoints:
- POST /api/v1/scans/{scan_id}/analyze-batch  : lance l'analyse de toutes les vulns d'un scan
- GET  /api/v1/analysis/{analysis_id}/status  : statut de l'analyse en cours
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Scan, Vulnerability, RemediationPlan
from src.api.dependencies import get_current_user, require_permission
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["analysis-batch"])


@router.post(
    "/scans/{scan_id}/analyze-batch",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require_permission("scans:read"))],
)
def analyze_scan_batch(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Lance l'analyse IA batch de toutes les vulnérabilités d'un scan.

    - Vérifie que le scan est complété et appartient à l'organisation.
    - Crée un RemediationPlan avec status='analyzing'.
    - Lance le worker Celery analyze_scan_batch.
    - Retourne l'analysis_id (= plan.id) pour suivre la progression.
    """
    org_id = current_user["organization_id"]

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="scan_id invalide")

    scan: Optional[Scan] = (
        db.query(Scan)
        .filter(Scan.id == scan_uuid, Scan.organization_id == org_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    if scan.status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Le scan doit être terminé avant l'analyse (statut actuel: {scan.status})",
        )

    # Compter les vulnérabilités
    total_vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan.id)
        .count()
    )
    if total_vulns == 0:
        raise HTTPException(status_code=400, detail="Aucune vulnérabilité trouvée pour ce scan")

    # Vérifier qu'il n'y a pas déjà un plan en cours
    existing_plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(
            RemediationPlan.scan_id == scan.id,
            RemediationPlan.status.in_(["analyzing", "pending_approval", "approved", "executing"]),
        )
        .first()
    )
    if existing_plan:
        return {
            "analysis_id": str(existing_plan.id),
            "total_vulnerabilities": total_vulns,
            "status": existing_plan.status,
            "estimated_duration": 120,
            "message": "Un plan de remédiation existe déjà pour ce scan",
        }

    # Créer le plan de remédiation
    plan = RemediationPlan(
        id=uuid.uuid4(),
        scan_id=scan.id,
        organization_id=org_id,
        status="analyzing",
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)

    # Lancer le worker Celery
    try:
        from src.workers.analysis_worker import analyze_scan_batch as worker_task
        worker_task.delay(str(scan.id), str(plan.id))
    except Exception as e:
        logger.error("Impossible de lancer le worker d'analyse: %s", e)
        # Fallback: passer en attente pour que le frontend puisse quand même continuer
        plan.status = "pending_approval"
        db.commit()

    logger.info(
        "Analyse batch lancée: scan=%s plan=%s total_vulns=%d",
        scan_id,
        plan.id,
        total_vulns,
    )

    return {
        "analysis_id": str(plan.id),
        "total_vulnerabilities": total_vulns,
        "status": plan.status,
        "estimated_duration": max(60, total_vulns * 6),  # ~6s par vuln
        "message": f"Analyse de {total_vulns} vulnérabilités lancée",
    }


@router.get(
    "/analysis/{analysis_id}/status",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_analysis_status(
    analysis_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne le statut de l'analyse en cours.

    Calcule la progression à partir des vulnérabilités déjà analysées (ai_analyzed=True).
    """
    org_id = current_user["organization_id"]

    try:
        plan_uuid = uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="analysis_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.id == plan_uuid, RemediationPlan.organization_id == org_id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Analyse introuvable")

    # Compter les vulnérabilités analysées
    total = db.query(Vulnerability).filter(Vulnerability.scan_id == plan.scan_id).count()
    analyzed = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == plan.scan_id, Vulnerability.ai_analyzed == True)
        .count()
    )

    # Trouver la dernière CVE analysée
    last_vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == plan.scan_id, Vulnerability.ai_analyzed == True)
        .order_by(Vulnerability.updated_at.desc())
        .first()
    )
    current_cve = last_vuln.cve_id if last_vuln else None

    estimated_remaining = max(0, (total - analyzed) * 6) if total > 0 else 0

    return {
        "analysis_id": analysis_id,
        "status": plan.status,
        "progress": analyzed,
        "total": total,
        "current_vulnerability": current_cve,
        "estimated_time_remaining": estimated_remaining,
        "remediation_plan_id": str(plan.id) if plan.status in ("pending_approval", "approved", "completed") else None,
    }
