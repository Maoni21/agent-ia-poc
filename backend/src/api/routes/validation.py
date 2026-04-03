"""
Routes pour les scans de validation post-remédiation.

Endpoints:
- GET /api/v1/validation/{remediation_plan_id}  : résultats du scan de validation
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import RemediationPlan, ValidationScan, Vulnerability, Scan
from src.api.dependencies import get_current_user, require_permission
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["validation"])


@router.get(
    "/validation/{remediation_plan_id}",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_validation_results(
    remediation_plan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne les résultats du scan de validation post-remédiation.
    """
    org_id = current_user["organization_id"]

    try:
        plan_uuid = uuid.UUID(remediation_plan_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="remediation_plan_id invalide")

    plan: Optional[RemediationPlan] = (
        db.query(RemediationPlan)
        .filter(RemediationPlan.id == plan_uuid, RemediationPlan.organization_id == org_id)
        .first()
    )
    if not plan:
        raise HTTPException(status_code=404, detail="Plan de remédiation introuvable")

    validation: Optional[ValidationScan] = (
        db.query(ValidationScan)
        .filter(ValidationScan.remediation_plan_id == plan.id)
        .order_by(ValidationScan.created_at.desc())
        .first()
    )

    if not validation:
        # Pas encore de validation, retourner un statut en attente
        return {
            "plan_id": remediation_plan_id,
            "status": "pending",
            "message": "Le scan de validation n'a pas encore démarré",
            "before_score": None,
            "after_score": None,
            "improvement": None,
        }

    improvement = (
        (validation.after_score - validation.before_score)
        if validation.before_score is not None and validation.after_score is not None
        else None
    )

    fixed_vulns = validation.fixed_vulnerabilities or []
    remaining_vulns = validation.remaining_vulnerabilities or []

    # Compter par sévérité
    fixed_by_severity = _count_by_severity(fixed_vulns)
    remaining_by_severity = _count_by_severity(remaining_vulns)

    return {
        "validation_scan_id": str(validation.id),
        "plan_id": remediation_plan_id,
        "status": validation.status,
        "before_score": validation.before_score,
        "after_score": validation.after_score,
        "improvement": improvement,
        "fixed_vulnerabilities": fixed_vulns,
        "remaining_vulnerabilities": remaining_vulns,
        "summary": {
            "total_fixed": len(fixed_vulns),
            "total_remaining": len(remaining_vulns),
            "fixed_by_severity": fixed_by_severity,
            "remaining_by_severity": remaining_by_severity,
        },
        "created_at": validation.created_at.isoformat() if validation.created_at else None,
    }


def _count_by_severity(vulns: List[dict]) -> Dict[str, int]:
    """Compte les vulnérabilités par sévérité."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        sev = (v.get("severity") or "LOW").upper()
        if sev in counts:
            counts[sev] += 1
    return counts
