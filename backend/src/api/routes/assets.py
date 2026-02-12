"""
CRUD Assets (Phase 2 – Semaines 5-6).

Endpoints:
- GET    /api/v1/assets        : liste des assets du tenant
- POST   /api/v1/assets        : créer un asset
- GET    /api/v1/assets/{id}   : détails
- PUT    /api/v1/assets/{id}   : mise à jour
- DELETE /api/v1/assets/{id}   : suppression
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Asset
from src.api.dependencies import get_current_user, require_permission
from src.api.middleware.tenant_filter import tenant_scoped_query, tenant_scoped
from src.api.schemas import AssetCreate, AssetUpdate, AssetResponse

router = APIRouter(prefix="/api/v1", tags=["assets"])


def _validate_ip(ip: str) -> None:
  """Valide que `ip` est une IPv4 ou IPv6 correcte."""
  try:
      ipaddress.ip_address(ip)
  except ValueError:
      raise HTTPException(
          status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
          detail="Adresse IP invalide (IPv4/IPv6 attendue)",
      )


@router.get(
    "/assets",
    response_model=List[AssetResponse],
    dependencies=[Depends(require_permission("assets:read"))],
)
def list_assets(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[AssetResponse]:
    """
    Liste des assets de l'organization (filtré par current_user.organization_id).
    """
    query = tenant_scoped_query(Asset, db, current_user)
    assets = query.order_by(Asset.created_at.desc()).all()
    return [AssetResponse.from_orm(a) for a in assets]


@router.post(
    "/assets",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("assets:create"))],
)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AssetResponse:
    """
    Crée un nouvel asset.

    Règles:
    - IP valide (IPv4/IPv6)
    - Pas de doublon d'IP dans la même organization
    """
    _validate_ip(payload.ip_address)

    org_id = current_user["organization_id"]

    # Vérifier doublon IP dans l'organization
    existing = (
        db.query(Asset)
        .filter(
            Asset.organization_id == org_id,
            Asset.ip_address == payload.ip_address,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un asset avec cette adresse IP existe déjà dans l'organisation.",
        )

    tags = [t.strip() for t in (payload.tags or []) if t.strip()]

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        mac_address=payload.mac_address,
        asset_type=payload.asset_type,
        os=payload.os,
        os_version=payload.os_version,
        environment=payload.environment,
        business_criticality=payload.business_criticality,
        datacenter=payload.datacenter,
        cloud_provider=payload.cloud_provider,
        region=payload.region,
        is_active=True,
        monitoring_enabled=True,
        notes=payload.notes,
        tags=tags,
    )

    try:
        db.add(asset)
        db.commit()
        db.refresh(asset)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de créer l'asset (contrainte en base).",
        )

    return AssetResponse.from_orm(asset)


@router.get(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_permission("assets:read"))],
)
def get_asset(
    asset=Depends(tenant_scoped(Asset)),
) -> AssetResponse:
    """
    Détails d'un asset (vérifie automatiquement le tenant).
    """
    return AssetResponse.from_orm(asset)


@router.put(
    "/assets/{asset_id}",
    response_model=AssetResponse,
    dependencies=[Depends(require_permission("assets:update"))],
)
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> AssetResponse:
    """
    Met à jour un asset.

    - Toujours limité à l'organization du user
    - IP valide si changée
    - Pas de doublon IP dans la même organization
    """
    org_id = current_user["organization_id"]

    asset: Asset | None = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset introuvable")

    if payload.ip_address and payload.ip_address != asset.ip_address:
        _validate_ip(payload.ip_address)
        # Vérifier doublon IP
        existing = (
            db.query(Asset)
            .filter(
                Asset.organization_id == org_id,
                Asset.ip_address == payload.ip_address,
                Asset.id != asset.id,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Un autre asset possède déjà cette adresse IP dans l'organisation.",
            )
        asset.ip_address = payload.ip_address

    # Mise à jour des autres champs
    for field in [
        "hostname",
        "mac_address",
        "asset_type",
        "os",
        "os_version",
        "environment",
        "business_criticality",
        "datacenter",
        "cloud_provider",
        "region",
        "notes",
        "is_active",
        "monitoring_enabled",
    ]:
        value = getattr(payload, field, None)
        if value is not None:
            setattr(asset, field, value)

    if payload.tags is not None:
        asset.tags = [t.strip() for t in payload.tags if t.strip()]

    db.commit()
    db.refresh(asset)

    return AssetResponse.from_orm(asset)


@router.delete(
    "/assets/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("assets:delete"))],
)
def delete_asset(
    asset_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    """
    Supprime un asset (toujours limité à l'organization du user).
    """
    org_id = current_user["organization_id"]

    asset: Asset | None = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.organization_id == org_id)
        .first()
    )
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset introuvable")

    db.delete(asset)
    db.commit()

