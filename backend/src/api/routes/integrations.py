"""
Intégrations (Phase 3 – Semaine 11).

- Webhooks: CRUD des subscriptions
- API Keys: création / liste / suppression
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import WebhookSubscription, APIKey
from src.api.dependencies import get_current_user, require_role
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["integrations"])


# === WEBHOOKS ===


@router.get(
    "/webhooks",
    dependencies=[Depends(require_role("admin"))],
)
def list_webhooks(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    org_id = current_user["organization_id"]
    subs = (
        db.query(WebhookSubscription)
        .filter(WebhookSubscription.organization_id == org_id)
        .order_by(WebhookSubscription.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(s.id),
            "url": s.url,
            "events": s.events,
            "is_active": s.is_active,
            "last_delivery_at": s.last_delivery_at.isoformat() if s.last_delivery_at else None,
        }
        for s in subs
    ]


@router.post(
    "/webhooks",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
def create_webhook(
    body: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    org_id = current_user["organization_id"]

    url = (body.get("url") or "").strip()
    events = body.get("events") or []

    if not url:
        raise HTTPException(status_code=422, detail="URL webhook obligatoire")

    if not isinstance(events, list) or not events:
        raise HTTPException(status_code=422, detail="Liste d'événements obligatoire")

    sub = WebhookSubscription(
        id=uuid.uuid4(),
        organization_id=org_id,
        url=url,
        events=events,
        is_active=True,
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)

    return {
        "id": str(sub.id),
        "url": sub.url,
        "events": sub.events,
        "is_active": sub.is_active,
    }


@router.delete(
    "/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
def delete_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    org_id = current_user["organization_id"]

    try:
        webhook_uuid = uuid.UUID(webhook_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Identifiant invalide")

    sub: Optional[WebhookSubscription] = (
        db.query(WebhookSubscription)
        .filter(
            WebhookSubscription.id == webhook_uuid,
            WebhookSubscription.organization_id == org_id,
        )
        .first()
    )
    if not sub:
        raise HTTPException(status_code=404, detail="Webhook introuvable")

    db.delete(sub)
    db.commit()


# === API KEYS ===


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _generate_api_key() -> str:
    # Clé style "sk_live_" + random
    prefix = "sk_live_"
    random_part = secrets.token_urlsafe(32)
    return prefix + random_part


@router.get(
    "/api-keys",
    dependencies=[Depends(require_role("admin"))],
)
def list_api_keys(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    org_id = current_user["organization_id"]
    keys = (
        db.query(APIKey)
        .filter(APIKey.organization_id == org_id)
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(k.id),
            "name": k.name,
            "key_prefix": k.key_prefix,
            "scopes": k.scopes,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "usage_count": k.usage_count,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        }
        for k in keys
    ]


@router.post(
    "/api-keys",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role("admin"))],
)
def create_api_key(
    body: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    org_id = current_user["organization_id"]
    user_id = current_user["id"]

    name = (body.get("name") or "").strip()
    scopes = body.get("scopes") or []

    if not name:
        raise HTTPException(status_code=422, detail="Nom d'API key obligatoire")

    if not isinstance(scopes, list) or not scopes:
        raise HTTPException(status_code=422, detail="Au moins un scope est requis")

    plain_key = _generate_api_key()
    key_hash = _hash_api_key(plain_key)
    key_prefix = plain_key[:12]

    api_key = APIKey(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=name,
        scopes=scopes,
        is_active=True,
        created_at=datetime.utcnow(),
        created_by=user_id,
    )
    db.add(api_key)
    db.commit()

    # On NE retourne la clé en clair qu'une seule fois ici
    return {
        "id": str(api_key.id),
        "name": api_key.name,
        "key": plain_key,
        "key_prefix": api_key.key_prefix,
        "scopes": api_key.scopes,
        "is_active": api_key.is_active,
    }


@router.delete(
    "/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_role("admin"))],
)
def delete_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> None:
    org_id = current_user["organization_id"]

    try:
        key_uuid = uuid.UUID(key_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Identifiant invalide")

    api_key: Optional[APIKey] = (
        db.query(APIKey)
        .filter(APIKey.id == key_uuid, APIKey.organization_id == org_id)
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key introuvable")

    db.delete(api_key)
    db.commit()


