"""
CRUD API pour les projets de remédiation.

Endpoints :
- GET    /api/v1/remediation-projects
- POST   /api/v1/remediation-projects
- GET    /api/v1/remediation-projects/{id}
- PUT    /api/v1/remediation-projects/{id}
- DELETE /api/v1/remediation-projects/{id}
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import RemediationProject
from src.api.dependencies import get_current_user
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1/remediation-projects", tags=["remediation-projects"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class RemediationProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    priority: str = "medium"
    due_date: Optional[datetime] = None
    total_vulns: int = 0


class RemediationProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    due_date: Optional[datetime] = None
    total_vulns: Optional[int] = None
    resolved_vulns: Optional[int] = None


def _project_to_dict(project: RemediationProject) -> Dict[str, Any]:
    progress = 0
    if project.total_vulns and project.total_vulns > 0:
        progress = int((project.resolved_vulns / project.total_vulns) * 100)

    days_remaining = None
    if project.due_date:
        delta = project.due_date - datetime.utcnow()
        days_remaining = delta.days

    return {
        "id": str(project.id),
        "name": project.name,
        "description": project.description,
        "status": project.status,
        "priority": project.priority,
        "due_date": project.due_date.isoformat() if project.due_date else None,
        "days_remaining": days_remaining,
        "total_vulns": project.total_vulns,
        "resolved_vulns": project.resolved_vulns,
        "progress": progress,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("")
def list_projects(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Liste tous les projets de remédiation de l'organisation."""
    org_id = current_user["organization_id"]
    projects = (
        db.query(RemediationProject)
        .filter(RemediationProject.organization_id == org_id)
        .order_by(RemediationProject.created_at.desc())
        .all()
    )
    return [_project_to_dict(p) for p in projects]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_project(
    body: RemediationProjectCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Crée un nouveau projet de remédiation."""
    org_id = current_user["organization_id"]

    project = RemediationProject(
        organization_id=org_id,
        name=body.name,
        description=body.description,
        priority=body.priority,
        due_date=body.due_date,
        total_vulns=body.total_vulns,
        resolved_vulns=0,
        status="open",
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return _project_to_dict(project)


@router.get("/{project_id}")
def get_project(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Récupère un projet par son ID."""
    org_id = current_user["organization_id"]
    project = (
        db.query(RemediationProject)
        .filter(
            RemediationProject.id == project_id,
            RemediationProject.organization_id == org_id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Projet introuvable")
    return _project_to_dict(project)


@router.put("/{project_id}")
def update_project(
    project_id: uuid.UUID,
    body: RemediationProjectUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Met à jour un projet de remédiation."""
    org_id = current_user["organization_id"]
    project = (
        db.query(RemediationProject)
        .filter(
            RemediationProject.id == project_id,
            RemediationProject.organization_id == org_id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Projet introuvable")

    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(project, field, value)

    db.commit()
    db.refresh(project)
    return _project_to_dict(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """Supprime un projet de remédiation."""
    org_id = current_user["organization_id"]
    project = (
        db.query(RemediationProject)
        .filter(
            RemediationProject.id == project_id,
            RemediationProject.organization_id == org_id,
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Projet introuvable")

    db.delete(project)
    db.commit()
