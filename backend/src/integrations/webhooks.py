"""
Système de webhooks (Phase 3 – Semaine 11).

- Table webhook_subscriptions (gérée via SQLAlchemy)
- Envoi de POST sur les URLs configurées quand un événement se produit
- Retry simple en cas d'échec
"""

from __future__ import annotations

import json
import time
from typing import Dict, Any, List

import httpx
from sqlalchemy.orm import Session

from src.database.models import WebhookSubscription
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


WEBHOOK_EVENTS = {
    "scan_completed",
    "critical_vulnerability",
    "remediation_completed",
}


def _get_subscriptions_for_event(
    db: Session,
    organization_id,
    event_type: str,
) -> List[WebhookSubscription]:
    return (
        db.query(WebhookSubscription)
        .filter(
            WebhookSubscription.organization_id == organization_id,
            WebhookSubscription.is_active.is_(True),
            WebhookSubscription.events.any(event_type),
        )
        .all()
    )


def send_webhook_event(
    db: Session,
    organization_id,
    event_type: str,
    payload: Dict[str, Any],
    max_retries: int = 3,
) -> None:
    """
    Envoie un événement de webhook à toutes les URLs abonnées pour cette organization.
    """
    if event_type not in WEBHOOK_EVENTS:
        logger.debug("Événement webhook inconnu: %s", event_type)
        return

    subscriptions = _get_subscriptions_for_event(db, organization_id, event_type)
    if not subscriptions:
        return

    body = {
        "event": event_type,
        "data": payload,
    }

    for sub in subscriptions:
        url = sub.url
        for attempt in range(1, max_retries + 1):
            try:
                logger.info("Envoi webhook %s vers %s (tentative %s)", event_type, url, attempt)
                response = httpx.post(url, json=body, timeout=10)
                if response.status_code >= 200 and response.status_code < 300:
                    sub.last_delivery_at = payload.get("created_at") or None
                    db.add(sub)
                    db.commit()
                    break
                else:
                    logger.warning(
                        "Webhook %s vers %s a échoué (%s): %s",
                        event_type,
                        url,
                        response.status_code,
                        response.text,
                    )
            except Exception as exc:
                logger.warning("Erreur envoi webhook vers %s: %s", url, exc)

            time.sleep(2 * attempt)  # backoff simple


__all__ = ["send_webhook_event", "WEBHOOK_EVENTS"]

