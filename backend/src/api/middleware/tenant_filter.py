"""
Multi‑tenancy (Phase 1 – Semaine 3).

Objectif :
- Règle globale : chaque requête doit être limitée à current_user.organization_id.
- Fournir un décorateur/dépendance réutilisable pour que les endpoints soient
  automatiquement « tenant‑scoped ».

Ce module sera utilisé par les futurs endpoints SQLAlchemy (assets, scans, etc.).
"""

from __future__ import annotations

import uuid
from typing import Callable, Dict, Type

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Base
from src.api.dependencies import get_current_user


def tenant_scoped_query(model: Type[Base], db: Session, current_user: Dict) -> "Session.query":
    """
    Retourne une requête SQLAlchemy déjà filtrée sur organization_id.

    Usage typique :
        query = tenant_scoped_query(Asset, db, current_user)
        assets = query.all()
    """
    org_id = current_user.get("organization_id")
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Utilisateur sans organization_id, accès interdit",
        )
    return db.query(model).filter(model.organization_id == org_id)


def tenant_scoped(model: Type[Base]) -> Callable:
    """
    Fabrique une dépendance FastAPI qui charge une ressource par son id,
    en vérifiant qu'elle appartient bien à current_user.organization_id.

    Exemple dans un endpoint :

        from src.database.models import Asset
        from src.api.middleware.tenant_filter import tenant_scoped

        @router.get("/assets/{asset_id}")
        def get_asset(asset = Depends(tenant_scoped(Asset))):
            return asset
    """

    async def _dependency(
        resource_id: uuid.UUID,
        db: Session = Depends(get_db),
        current_user: Dict = Depends(get_current_user),
    ):
        org_id = current_user.get("organization_id")
        if not org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Utilisateur sans organization_id, accès interdit",
            )

        instance = (
            db.query(model)
            .filter(
                model.id == resource_id,
                model.organization_id == org_id,
            )
            .first()
        )
        if not instance:
            # On ne révèle pas l'existence éventuelle d'une ressource d'un autre tenant
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ressource introuvable")

        return instance

    return _dependency


__all__ = ["tenant_scoped_query", "tenant_scoped"]

