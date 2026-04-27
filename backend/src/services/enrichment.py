"""
Service d'enrichissement des vulnérabilités avec sources externes.
"""

import requests
from datetime import datetime, date
from typing import Dict, Any, Optional, List

from sqlalchemy.orm import Session

from src.database.models import Vulnerability
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class VulnerabilityEnrichment:
    """Enrichit les vulnérabilités avec données externes (CISA KEV, EPSS)."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API = "https://api.first.org/data/v1/epss"

    def __init__(self):
        self.kev_cache: Optional[Dict] = None
        self.kev_cache_date: Optional[date] = None

    def fetch_cisa_kev_catalog(self) -> Dict[str, Dict]:
        """
        Télécharge le catalogue CISA KEV (cache journalier).

        Returns:
            {"CVE-2021-44790": {"date_added": "2021-12-10", "due_date": "2021-12-24"}, ...}
        """
        today = datetime.utcnow().date()

        if self.kev_cache and self.kev_cache_date == today:
            return self.kev_cache

        logger.info("Fetching CISA KEV catalog...")
        try:
            response = requests.get(self.CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()

            kev_dict: Dict[str, Dict] = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    kev_dict[cve_id] = {
                        "date_added": vuln.get("dateAdded"),
                        "due_date": vuln.get("dueDate"),
                        "required_action": vuln.get("requiredAction"),
                    }

            self.kev_cache = kev_dict
            self.kev_cache_date = today
            logger.info("Fetched %d CVEs from CISA KEV", len(kev_dict))
            return kev_dict

        except Exception as e:
            logger.error("Error fetching CISA KEV: %s", e)
            return {}

    def check_cisa_kev(self, cve_id: str) -> Dict[str, Any]:
        """Vérifie si un CVE est dans le catalogue CISA KEV."""
        if not cve_id:
            return {"kev": False}

        kev_catalog = self.fetch_cisa_kev_catalog()
        if cve_id in kev_catalog:
            return {
                "kev": True,
                "date_added": kev_catalog[cve_id].get("date_added"),
                "due_date": kev_catalog[cve_id].get("due_date"),
            }
        return {"kev": False}

    def get_epss_score(self, cve_id: str) -> Optional[Dict[str, float]]:
        """
        Récupère le score EPSS pour un CVE.

        Returns:
            {"epss_score": 0.925, "percentile": 0.99} ou None
        """
        if not cve_id:
            return None

        try:
            url = f"{self.EPSS_API}?cve={cve_id}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data.get("data") and len(data["data"]) > 0:
                epss_data = data["data"][0]
                return {
                    "epss_score": float(epss_data.get("epss", 0)),
                    "percentile": float(epss_data.get("percentile", 0)),
                }
        except Exception as e:
            logger.warning("Error fetching EPSS for %s: %s", cve_id, e)

        return None

    def enrich_vulnerability(
        self,
        vulnerability: Vulnerability,
        db: Session,
    ) -> bool:
        """
        Enrichit une vulnérabilité avec CISA KEV et EPSS.

        Returns:
            True si succès, False sinon
        """
        if not vulnerability.cve_id:
            return False

        try:
            kev_data = self.check_cisa_kev(vulnerability.cve_id)
            vulnerability.cisa_kev = kev_data["kev"]

            epss_data = self.get_epss_score(vulnerability.cve_id)
            if epss_data:
                vulnerability.epss_score = epss_data["epss_score"]
                vulnerability.epss_percentile = epss_data["percentile"]

            db.commit()
            logger.info(
                "Enriched %s: KEV=%s, EPSS=%s",
                vulnerability.cve_id,
                kev_data["kev"],
                epss_data,
            )
            return True

        except Exception as e:
            logger.error("Error enriching vulnerability %s: %s", vulnerability.id, e)
            db.rollback()
            return False

    def enrich_all_vulnerabilities(
        self,
        organization_id: str,
        db: Session,
    ) -> Dict[str, int]:
        """
        Enrichit toutes les vulnérabilités ouvertes d'une organisation.

        Returns:
            {"total": 100, "enriched": 95, "failed": 5}
        """
        vulns: List[Vulnerability] = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.organization_id == organization_id,
                Vulnerability.status == "open",
                Vulnerability.cve_id.isnot(None),
            )
            .all()
        )

        stats = {"total": len(vulns), "enriched": 0, "failed": 0}

        for vuln in vulns:
            if self.enrich_vulnerability(vuln, db):
                stats["enriched"] += 1
            else:
                stats["failed"] += 1

        return stats
