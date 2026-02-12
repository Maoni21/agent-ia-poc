"""
Configuration Celery pour les tâches asynchrones (scans, IA, etc.).

Utilisé notamment pour la Semaine 7 : exécution des scans en arrière-plan.
"""

from __future__ import annotations

import os

from celery import Celery

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)

celery_app = Celery(
    "vulnerability_agent",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    include=[
        "src.workers.scan_worker",
        "src.workers.executor_worker",
    ],
)

__all__ = ["celery_app"]

