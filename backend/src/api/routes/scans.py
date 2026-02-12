"""
Système de scans (Phase 2 – Semaine 7).

Endpoints:
- POST /api/v1/scans       : crée un scan et lance une tâche Celery
- GET  /api/v1/scans       : liste des scans du tenant
- GET  /api/v1/scans/{id}  : détails d'un scan + vulnérabilités

WebSocket:
- /ws/scans/{id}           : progression en temps réel (polling DB)
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db, SessionLocal
from src.database.models import Asset, Scan, Vulnerability
from src.api.dependencies import get_current_user, require_permission
from src.api.middleware.tenant_filter import tenant_scoped_query
from src.api.schemas import ScanStatus as ApiScanStatus
from src.workers.scan_worker import execute_scan

router = APIRouter(prefix="/api/v1", tags=["scans"])
ws_router = APIRouter()


class ScanCreatePayload:
    """Schéma léger pour la création de scan (utilise Pydantic dans schemas si besoin)."""

    def __init__(self, asset_id: str, scan_type: str = "full") -> None:
        self.asset_id = asset_id
        self.scan_type = scan_type


def _validate_scan_type(scan_type: str) -> None:
    allowed = {"quick", "full", "stealth", "compliance", "custom"}
    if scan_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"scan_type invalide. Valeurs possibles: {', '.join(sorted(allowed))}",
        )


@router.post(
    "/scans",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("scans:create"))],
)
def create_scan(
    data: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Crée un scan pour un asset et lance la tâche Celery.

    Body JSON:
    - asset_id (UUID string, obligatoire)
    - scan_type (quick, full, stealth, compliance, custom)
    """
    asset_id = data.get("asset_id")
    scan_type = data.get("scan_type", "full")

    if not asset_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="asset_id est obligatoire",
        )

    _validate_scan_type(scan_type)

    org_id = current_user["organization_id"]

    try:
        asset_uuid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="asset_id invalide")

    # Vérifier que l'asset appartient bien à l'organization
    asset: Optional[Asset] = (
        db.query(Asset)
        .filter(Asset.id == asset_uuid, Asset.organization_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset introuvable")

    scan = Scan(
        id=uuid.uuid4(),
        organization_id=org_id,
        asset_id=asset.id,
        scan_type=scan_type,
        status="queued",
        progress=0,
        started_at=None,
        created_at=datetime.utcnow(),
    )

    db.add(scan)
    db.commit()

    # Lancer la tâche Celery
    execute_scan.delay(str(scan.id))

    return {
        "id": str(scan.id),
        "asset_id": str(scan.asset_id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "progress": scan.progress,
        "created_at": scan.created_at.isoformat(),
    }


@router.get(
    "/scans",
    dependencies=[Depends(require_permission("scans:read"))],
)
def list_scans(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Liste les scans de l'organization courante.
    """
    query = tenant_scoped_query(Scan, db, current_user)
    scans = (
        query.order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    results: List[Dict[str, Any]] = []
    for scan in scans:
        results.append(
            {
                "id": str(scan.id),
                "asset_id": str(scan.asset_id),
                "scan_type": scan.scan_type,
                "status": scan.status,
                "progress": scan.progress,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "vulnerabilities_found": scan.vulnerabilities_found,
                "risk_score": float(scan.risk_score) if scan.risk_score is not None else None,
            }
        )

    return results


@router.get(
    "/scans/{scan_id}",
    dependencies=[Depends(require_permission("scans:read"))],
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Détails d'un scan + liste des vulnérabilités associées.
    """
    org_id = current_user["organization_id"]

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="scan_id invalide")

    scan: Optional[Scan] = (
        db.query(Scan)
        .filter(Scan.id == scan_uuid, Scan.organization_id == org_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan introuvable")

    vulns: List[Vulnerability] = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.scan_id == scan.id,
            Vulnerability.organization_id == org_id,
        )
        .all()
    )

    return {
        "id": str(scan.id),
        "asset_id": str(scan.asset_id),
        "scan_type": scan.scan_type,
        "status": scan.status,
        "progress": scan.progress,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "vulnerabilities": [
            {
                "id": str(v.id),
                "cve_id": v.cve_id,
                "title": v.title,
                "description": v.description,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "port": v.port,
                "service": v.service,
                "status": v.status,
            }
            for v in vulns
        ],
    }


# === WebSocket progression temps réel basé sur la base de données ===


@ws_router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_progress_db(websocket: WebSocket, scan_id: str):
    """
    WebSocket très simple qui publie la progression d'un scan
    en lisant périodiquement la BDD.
    """
    await websocket.accept()

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.close(code=1008, reason="scan_id invalide")
        return

    try:
        while True:
            db: Session = SessionLocal()
            try:
                scan: Optional[Scan] = db.query(Scan).filter(Scan.id == scan_uuid).first()
                if not scan:
                    await websocket.send_json(
                        {
                            "type": "progress_update",
                            "data": {
                                "scan_id": scan_id,
                                "status": "not_found",
                                "progress": 0,
                                "current_step": "",
                                "message": "Scan introuvable",
                                "estimated_time_remaining": 0,
                            },
                        }
                    )
                    await asyncio.sleep(5)
                    continue

                data = {
                    "scan_id": scan_id,
                    "status": scan.status,
                    "progress": scan.progress or 0,
                    "current_step": "",  # Collector ne fournit pas encore d'étape textuelle
                    "message": "",
                    "estimated_time_remaining": 0,
                }

                await websocket.send_json({"type": "progress_update", "data": data})

                if scan.status in {"completed", "failed", "cancelled"}:
                    break

                await asyncio.sleep(2)
            finally:
                db.close()

    except WebSocketDisconnect:
        pass
    except Exception as e:  # pragma: no cover - log only
        await websocket.close(code=1011, reason=str(e))

