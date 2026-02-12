"""
Analyse IA & génération de scripts (Phase 2 – Semaine 8).

Endpoints:
- POST /api/v1/vulnerabilities/{id}/analyze        : Analyse IA d'une vulnérabilité
- POST /api/v1/vulnerabilities/{id}/generate-script: Génère un script de remédiation
- GET  /api/v1/remediation-scripts/{id}            : Récupère un script de remédiation
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Vulnerability, RemediationScript
from src.api.dependencies import get_current_user, require_permission
from src.core.analyzer import Analyzer
from src.core.generator import Generator
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])


async def _get_analyzer() -> Analyzer:
    return Analyzer()


async def _get_generator() -> Generator:
    return Generator()


def _get_vulnerability_for_tenant(
    db: Session,
    vuln_id: str,
    org_id: uuid.UUID,
) -> Vulnerability:
    try:
        vuln_uuid = uuid.UUID(vuln_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Identifiant de vulnérabilité invalide",
        )

    vuln: Optional[Vulnerability] = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.id == vuln_uuid,
            Vulnerability.organization_id == org_id,
        )
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnérabilité introuvable")
    return vuln


@router.post(
    "/vulnerabilities/{vuln_id}/analyze",
    dependencies=[Depends(require_permission("vulnerabilities:update"))],
)
async def analyze_vulnerability(
    vuln_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Analyse IA d'une vulnérabilité.

    - Récupère la vulnérabilité en BDD (scoped par organization_id)
    - Appelle Analyzer.analyze_vulnerabilities_batch(...)
    - Sauvegarde le résultat dans vulnerability.ai_analysis / ai_priority_score / ai_analyzed
    """
    org_id = current_user["organization_id"]
    vuln = _get_vulnerability_for_tenant(db, vuln_id, org_id)

    analyzer = await _get_analyzer()

    vuln_payload = {
        "vulnerability_id": str(vuln.id),
        "name": vuln.title,
        "severity": vuln.severity,
        "cvss_score": float(vuln.cvss_score) if vuln.cvss_score is not None else None,
        "description": vuln.description or "",
        "affected_service": vuln.service or "",
        "affected_port": vuln.port,
        "cve_id": vuln.cve_id,
    }

    try:
        result = await analyzer.analyze_vulnerabilities_batch(
            vulnerabilities_data=[vuln_payload],
            target_system="Unknown System",
        )
    except Exception as e:
        logger.error("Erreur analyse IA pour vuln %s: %s", vuln_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse IA: {e}",
        )

    # On récupère la première vuln analysée
    if not result.vulnerabilities:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analyse IA vide",
        )

    analysis = result.vulnerabilities[0].to_dict()

    vuln.ai_analyzed = True
    vuln.ai_analysis = analysis
    vuln.ai_priority_score = analysis.get("priority_score")
    db.add(vuln)
    db.commit()

    return {
        "success": True,
        "analysis": analysis,
    }


@router.post(
    "/vulnerabilities/{vuln_id}/generate-script",
    dependencies=[Depends(require_permission("remediation:create"))],
)
async def generate_script_for_vulnerability(
    vuln_id: str,
    body: Dict[str, Any] | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Génère un script de remédiation pour une vulnérabilité donnée.

    Body optionnel:
    - target_system (ex: ubuntu-22.04)
    - script_type   (bash, ansible, powershell, python)
    """
    org_id = current_user["organization_id"]
    vuln = _get_vulnerability_for_tenant(db, vuln_id, org_id)

    generator = await _get_generator()

    payload = body or {}
    target_system = payload.get("target_system", "ubuntu-22.04")
    script_type = payload.get("script_type", "bash")

    vuln_details = {
        "vulnerability_id": str(vuln.id),
        "name": vuln.title,
        "severity": vuln.severity,
        "cvss_score": float(vuln.cvss_score) if vuln.cvss_score is not None else None,
        "description": vuln.description or "",
        "affected_service": vuln.service or "",
        "affected_port": vuln.port,
        "cve_id": vuln.cve_id,
    }

    try:
        script_result = await generator.generate_fix_script(
            vulnerability_id=str(vuln.id),
            vulnerability_details=vuln_details,
            target_system=target_system,
            risk_tolerance="low",
        )
    except Exception as e:
        logger.error("Erreur génération script pour vuln %s: %s", vuln_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la génération du script: {e}",
        )

    data = script_result.to_dict()

    # Créer un RemediationScript en base
    script = RemediationScript(
        id=uuid.uuid4(),
        vulnerability_id=vuln.id,
        organization_id=org_id,
        script_type=script_type,
        script_content=data.get("fix_script") or "",
        rollback_script=data.get("rollback_script"),
        target_os=target_system,
        risk_level=data.get("risk_level", "MEDIUM").upper(),
        execution_status="pending",
        generated_by=data.get("ai_model_used"),
        generation_prompt="auto",  # pour simplifier
        requires_approval=True,
    )

    db.add(script)
    db.commit()
    db.refresh(script)

    return {
        "success": True,
        "script_id": str(script.id),
        "script_type": script.script_type,
        "target_os": script.target_os,
        "risk_level": script.risk_level,
    }


@router.get(
    "/remediation-scripts/{script_id}",
    dependencies=[Depends(require_permission("remediation:create"))],
)
def get_remediation_script(
    script_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Récupère un script de remédiation pour l'afficher dans le frontend.
    """
    org_id = current_user["organization_id"]

    try:
        script_uuid = uuid.UUID(script_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Identifiant de script invalide",
        )

    script: Optional[RemediationScript] = (
        db.query(RemediationScript)
        .filter(
            RemediationScript.id == script_uuid,
            RemediationScript.organization_id == org_id,
        )
        .first()
    )
    if not script:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Script introuvable")

    return {
        "id": str(script.id),
        "vulnerability_id": str(script.vulnerability_id) if script.vulnerability_id else None,
        "script_type": script.script_type,
        "script_content": script.script_content,
        "rollback_script": script.rollback_script,
        "target_os": script.target_os,
        "risk_level": script.risk_level,
        "requires_reboot": script.requires_reboot,
        "requires_sudo": script.requires_sudo,
        "execution_status": script.execution_status,
        "created_at": script.created_at.isoformat(),
    }


@router.post(
    "/remediation-scripts/{script_id}/approve",
    dependencies=[Depends(require_permission("remediation:approve"))],
)
def approve_remediation_script(
    script_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Approuve un script de remédiation (workflow d'approbation simple).
    """
    org_id = current_user["organization_id"]

    try:
        script_uuid = uuid.UUID(script_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Identifiant de script invalide",
        )

    script: Optional[RemediationScript] = (
        db.query(RemediationScript)
        .filter(
            RemediationScript.id == script_uuid,
            RemediationScript.organization_id == org_id,
        )
        .first()
    )
    if not script:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Script introuvable")

    script.requires_approval = False
    script.approved_by = uuid.UUID(str(current_user["id"]))
    script.approved_at = datetime.utcnow()
    script.execution_status = "approved"
    db.commit()

    return {"success": True, "status": script.execution_status}


from src.workers.executor_worker import execute_remediation_script


@router.post(
    "/remediation-scripts/{script_id}/execute",
    dependencies=[Depends(require_permission("remediation:execute"))],
)
def execute_remediation_script_endpoint(
    script_id: str,
    body: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Lance l'exécution d'un script de remédiation via SSH (tâche Celery).

    Body JSON:
    - host
    - port (optionnel, défaut 22)
    - username
    - password
    """
    org_id = current_user["organization_id"]

    try:
        script_uuid = uuid.UUID(script_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Identifiant de script invalide",
        )

    script: Optional[RemediationScript] = (
        db.query(RemediationScript)
        .filter(
            RemediationScript.id == script_uuid,
            RemediationScript.organization_id == org_id,
        )
        .first()
    )
    if not script:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Script introuvable")

    if script.requires_approval and script.execution_status != "approved":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Script non approuvé",
        )

    host = body.get("host")
    username = body.get("username")
    password = body.get("password")
    port = body.get("port", 22)

    if not host or not username or not password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Paramètres SSH manquants (host, username, password)",
        )

    ssh_params = {
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "executed_by": str(current_user["id"]),
    }

    execute_remediation_script.delay(script_id, ssh_params)

    # On marque simplement "running" côté API; le worker mettra le statut final
    script.execution_status = "running"
    db.commit()

    return {"success": True, "status": script.execution_status}



