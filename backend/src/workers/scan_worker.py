"""
Tâche Celery pour exécuter un scan (Semaine 7).

Workflow :
- Le backend crée un enregistrement Scan en base (status='queued')
- Cette tâche est appelée avec scan_id
- Elle exécute le scan via Collector.scan_target(...)
- Met à jour le Scan (progress, status, nmap_output, métriques)
- Crée les Vulnerability associées
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from src.workers.celery_app import celery_app
from src.core.collector import Collector, CollectorException, ScanResult, VulnerabilityInfo
from src.database.init_db import SessionLocal
from src.database.models import Scan, Vulnerability
from src.integrations.webhooks import send_webhook_event
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _get_db() -> Session:
    return SessionLocal()


def _update_scan_progress(db: Session, scan: Scan, progress: int, status: str | None = None) -> None:
    scan.progress = int(progress)
    if status:
        scan.status = status
    scan.updated_at = datetime.utcnow()
    db.add(scan)
    db.commit()


def _persist_scan_result(db: Session, scan: Scan, result: ScanResult) -> None:
    """
    Met à jour l'objet Scan + crée les Vulnerability associées à partir d'un ScanResult.
    """
    # Mettre à jour les champs du scan
    scan.completed_at = result.completed_at
    scan.duration_seconds = int(result.duration)
    scan.total_ports_scanned = len(result.open_ports)
    scan.open_ports_count = len(result.open_ports)
    scan.vulnerabilities_found = len(result.vulnerabilities)

    # Compter les vulnérabilités par sévérité
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for vuln_info in result.vulnerabilities:
        sev = (vuln_info.severity or "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    scan.critical_count = severity_counts["CRITICAL"]
    scan.high_count = severity_counts["HIGH"]
    scan.medium_count = severity_counts["MEDIUM"]
    scan.low_count = severity_counts["LOW"]
    scan.info_count = severity_counts["INFO"]

    # Stocker les données brutes du scan
    scan.nmap_output = result.scan_parameters.get("raw_output") if isinstance(
        result.scan_parameters, dict
    ) else None
    scan.scan_results = result.to_dict()
    scan.status = "completed"
    scan.progress = 100

    # Créer les vulnérabilités associées
    critical_found = False
    for vuln in result.vulnerabilities:
        if vuln.severity.upper() == "CRITICAL":
            critical_found = True
        _create_vulnerability_from_info(db, scan, vuln)

    db.add(scan)
    db.commit()

    # Webhooks
    send_webhook_event(
        db,
        organization_id=scan.organization_id,
        event_type="scan_completed",
        payload={
            "scan_id": str(scan.id),
            "asset_id": str(scan.asset_id),
            "status": scan.status,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "critical_count": scan.critical_count,
            "created_at": datetime.utcnow().isoformat(),
        },
    )

    if critical_found:
        send_webhook_event(
            db,
            organization_id=scan.organization_id,
            event_type="critical_vulnerability",
            payload={
                "scan_id": str(scan.id),
                "asset_id": str(scan.asset_id),
                "created_at": datetime.utcnow().isoformat(),
            },
        )


def _create_vulnerability_from_info(db: Session, scan: Scan, info: VulnerabilityInfo) -> None:
    """
    Transforme un VulnerabilityInfo (Collector) en enregistrement Vulnerability SQLAlchemy.
    """
    v = Vulnerability(
        id=uuid.uuid4(),
        scan_id=scan.id,
        organization_id=scan.organization_id,
        cve_id=info.cve_ids[0] if info.cve_ids else None,
        title=info.name,
        description=info.description,
        severity=info.severity.upper(),
        cvss_score=info.cvss_score,
        affected_package=info.affected_service,
        port=info.affected_port,
        protocol="tcp",
        detection_method=info.detection_method,
        confidence=info.confidence or "medium",
        references=[{"type": "reference", "url": r} for r in (info.references or [])],
    )
    db.add(v)


@celery_app.task(name="execute_scan", bind=True)
def execute_scan(self, scan_id: str) -> dict[str, Any]:
    """
    Tâche Celery principale pour exécuter un scan asynchrone.
    """
    db = _get_db()
    try:
        scan_uuid = uuid.UUID(scan_id)
        scan: Scan | None = db.query(Scan).filter(Scan.id == scan_uuid).first()
        if not scan:
            logger.error("Scan %s introuvable en base", scan_id)
            return {"status": "error", "message": "Scan introuvable"}

        asset = scan.asset
        if not asset:
            logger.error("Asset associé au scan %s introuvable", scan_id)
            scan.status = "failed"
            db.commit()
            return {"status": "error", "message": "Asset introuvable"}

        # Marquer le scan comme en cours
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.progress = 0
        db.commit()

        logger.info("Celery: début du scan %s sur la cible %s", scan_id, asset.ip_address)

        def progress_callback(p: int) -> None:
            try:
                _update_scan_progress(db, scan, p, status="running")
                self.update_state(state="PROGRESS", meta={"progress": int(p)})
            except Exception as e:  # pragma: no cover - log only
                logger.warning("Erreur mise à jour progression scan %s: %s", scan_id, e)

        async def _run_scan() -> ScanResult:
            collector = Collector()
            return await collector.scan_target(
                target=str(asset.ip_address),
                scan_type=scan.scan_type or "full",
                progress_callback=progress_callback,
            )

        result: ScanResult = asyncio.run(_run_scan())

        _persist_scan_result(db, scan, result)

        logger.info("Celery: scan %s terminé avec succès", scan_id)
        return {"status": "completed", "scan_id": scan_id}

    except CollectorException as e:
        logger.error("Erreur Collector pour le scan %s: %s", scan_id, e)
        _update_scan_progress(db, scan, progress=0, status="failed")
        return {"status": "failed", "message": str(e)}
    except Exception as e:  # pragma: no cover - log only
        logger.error("Erreur inattendue lors du scan %s: %s", scan_id, e)
        _update_scan_progress(db, scan, progress=0, status="failed")
        return {"status": "failed", "message": str(e)}
    finally:
        db.close()


__all__ = ["execute_scan"]

