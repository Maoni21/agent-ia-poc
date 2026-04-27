"""
Worker Celery pour l'enrichissement quotidien des vulnérabilités.

Programmé via Celery Beat pour tourner tous les jours à 2h du matin.
"""

from celery import shared_task
from sqlalchemy.orm import Session

from src.database.init_db import SessionLocal
from src.services.enrichment import VulnerabilityEnrichment
from src.database.models import Organization
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


@shared_task(name="enrich_vulnerabilities_daily")
def enrich_vulnerabilities_daily():
    """
    Tâche quotidienne : enrichit toutes les vulnérabilités de toutes les organisations
    avec les données CISA KEV et EPSS.

    Exemple de configuration Celery Beat :
        CELERY_BEAT_SCHEDULE = {
            'enrich-daily': {
                'task': 'enrich_vulnerabilities_daily',
                'schedule': crontab(hour=2, minute=0),
            },
        }
    """
    db: Session = SessionLocal()
    enrichment = VulnerabilityEnrichment()

    try:
        organizations = db.query(Organization).all()
        total_stats = {"total": 0, "enriched": 0, "failed": 0}

        for org in organizations:
            logger.info("Enriching vulnerabilities for org %s", org.name)
            stats = enrichment.enrich_all_vulnerabilities(str(org.id), db)
            total_stats["total"] += stats["total"]
            total_stats["enriched"] += stats["enriched"]
            total_stats["failed"] += stats["failed"]

        logger.info(
            "Enrichment completed: %d/%d enriched, %d failed",
            total_stats["enriched"],
            total_stats["total"],
            total_stats["failed"],
        )
        return total_stats

    except Exception as e:
        logger.error("Error in enrichment worker: %s", e)
        raise

    finally:
        db.close()


@shared_task(name="enrich_single_vulnerability")
def enrich_single_vulnerability(vulnerability_id: str):
    """
    Enrichit une seule vulnérabilité (appelé après un scan pour enrichissement immédiat).
    """
    db: Session = SessionLocal()
    enrichment = VulnerabilityEnrichment()

    try:
        from src.database.models import Vulnerability

        vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()

        if not vuln:
            logger.warning("Vulnerability %s not found", vulnerability_id)
            return False

        success = enrichment.enrich_vulnerability(vuln, db)
        logger.info("Enriched vulnerability %s: %s", vulnerability_id, success)
        return success

    except Exception as e:
        logger.error("Error enriching vulnerability %s: %s", vulnerability_id, e)
        return False

    finally:
        db.close()
