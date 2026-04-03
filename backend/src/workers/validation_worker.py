"""
Worker Celery pour le scan de validation post-remédiation.

Flow:
1. Récupérer le RemediationPlan + Asset original
2. Calculer le score de sécurité avant (depuis le scan original)
3. Lancer un nouveau scan de validation via execute_scan
4. Comparer les résultats avant/après
5. Créer un enregistrement ValidationScan
6. Notifier via WebSocket
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime
from typing import Any, Dict, List

from src.workers.celery_app import celery_app
from src.database.init_db import SessionLocal
from src.database.models import (
    Asset, Scan, Vulnerability, RemediationPlan, ValidationScan
)
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Score de sécurité : poids par sévérité
_SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


def _compute_score(vulns: List[Vulnerability]) -> int:
    """Calcule un score de sécurité de 0 à 100."""
    if not vulns:
        return 100
    penalty = sum(_SEVERITY_WEIGHTS.get(v.severity, 0) for v in vulns)
    return max(0, 100 - penalty)


def _compare_vulns(
    before: List[Vulnerability],
    after: List[Vulnerability],
) -> tuple[List[Dict], List[Dict]]:
    """
    Compare les vulnérabilités avant et après.
    Retourne (fixed_list, remaining_list).
    """
    after_cves = {v.cve_id for v in after if v.cve_id}
    after_titles = {v.title for v in after}

    fixed = []
    for v in before:
        # Considérée comme corrigée si elle n'apparaît plus (par CVE ou par titre)
        is_gone = (
            (v.cve_id and v.cve_id not in after_cves)
            or (not v.cve_id and v.title not in after_titles)
        )
        if is_gone:
            fixed.append({
                "cve_id": v.cve_id,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score else None,
                "status": "fixed",
            })

    remaining = [
        {
            "cve_id": v.cve_id,
            "title": v.title,
            "severity": v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score else None,
            "reason": "Nécessite une intervention manuelle" if v.severity in ("LOW", "INFO") else "Potentiellement non corrigé",
        }
        for v in after
    ]

    return fixed, remaining


@celery_app.task(name="run_validation_scan", bind=True)
def run_validation_scan(self, plan_id: str) -> Dict[str, Any]:
    """
    Tâche Celery : lance un scan de validation après remédiation.
    """
    db = SessionLocal()
    try:
        plan_uuid = uuid.UUID(plan_id)
        plan: RemediationPlan | None = (
            db.query(RemediationPlan)
            .filter(RemediationPlan.id == plan_uuid)
            .first()
        )
        if not plan:
            logger.error("Plan introuvable pour la validation: %s", plan_id)
            return {"status": "error"}

        original_scan = db.query(Scan).filter(Scan.id == plan.scan_id).first()
        if not original_scan:
            logger.error("Scan original introuvable: %s", plan.scan_id)
            return {"status": "error"}

        # Score avant
        before_vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == original_scan.id)
            .all()
        )
        before_score = _compute_score(before_vulns)

        logger.info(
            "Validation: score avant=%d, lancement scan sur asset=%s",
            before_score,
            original_scan.asset_id,
        )

        # Créer l'entrée ValidationScan
        validation = ValidationScan(
            id=uuid.uuid4(),
            remediation_plan_id=plan.id,
            before_score=before_score,
            status="scanning",
        )
        db.add(validation)
        db.commit()

        # Créer un nouveau scan de validation
        new_scan = Scan(
            id=uuid.uuid4(),
            organization_id=plan.organization_id,
            asset_id=original_scan.asset_id,
            scan_type="quick",
            status="queued",
            progress=0,
            created_at=datetime.utcnow(),
        )
        db.add(new_scan)
        db.commit()

        validation.scan_id = new_scan.id
        db.commit()

        # Lancer le scan
        from src.workers.scan_worker import execute_scan
        task = execute_scan.delay(str(new_scan.id))

        # Attendre la fin du scan (max 10 minutes)
        max_wait = 600
        waited = 0
        poll_interval = 5

        while waited < max_wait:
            db.expire(new_scan)
            db.refresh(new_scan)
            if new_scan.status in ("completed", "failed", "cancelled"):
                break
            time.sleep(poll_interval)
            waited += poll_interval

        if new_scan.status != "completed":
            logger.warning("Scan de validation non terminé dans les délais: %s", new_scan.id)
            validation.status = "failed"
            db.commit()
            return {"status": "error", "message": "Scan de validation timeout"}

        # Score après
        after_vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == new_scan.id)
            .all()
        )
        after_score = _compute_score(after_vulns)

        # Comparer
        fixed, remaining = _compare_vulns(before_vulns, after_vulns)

        # Mettre à jour la validation
        validation.after_score = after_score
        validation.fixed_vulnerabilities = fixed
        validation.remaining_vulnerabilities = remaining
        validation.status = "completed"
        db.add(validation)
        db.commit()

        improvement = after_score - before_score
        logger.info(
            "Validation terminée: score %d → %d (+%d), corrigées=%d, restantes=%d",
            before_score, after_score, improvement, len(fixed), len(remaining),
        )

        return {
            "status": "completed",
            "before_score": before_score,
            "after_score": after_score,
            "improvement": improvement,
            "fixed_count": len(fixed),
            "remaining_count": len(remaining),
        }

    except Exception as e:
        logger.error("Erreur lors de la validation du plan %s: %s", plan_id, e, exc_info=True)
        try:
            if validation:
                validation.status = "failed"
                db.commit()
        except Exception:
            pass
        return {"status": "error", "message": str(e)}

    finally:
        db.close()


__all__ = ["run_validation_scan"]
