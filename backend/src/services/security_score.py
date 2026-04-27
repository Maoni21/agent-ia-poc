"""
Service de calcul du score de sécurité global.
"""

from datetime import datetime, timedelta
from typing import Dict, Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from src.database.models import Vulnerability, Asset, Scan


class SecurityScoreCalculator:
    """Calcule le score de sécurité global de l'organisation."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 5.0,
        "MEDIUM": 2.0,
        "LOW": 0.5,
    }

    def __init__(self, db: Session):
        self.db = db

    def calculate_score(self, organization_id: str) -> float:
        """
        Calcule le score de sécurité actuel (0-100).

        100 = Aucune vulnérabilité, 0 = Risque critique maximal.
        """
        vulns = (
            self.db.query(Vulnerability)
            .filter(
                Vulnerability.organization_id == organization_id,
                Vulnerability.status == "open",
            )
            .all()
        )

        assets_count = (
            self.db.query(func.count(Asset.id))
            .filter(
                Asset.organization_id == organization_id,
                Asset.is_active.is_(True),
            )
            .scalar()
        ) or 1

        if not vulns:
            return 100.0

        penalty = 0.0
        for vuln in vulns:
            base_penalty = self.SEVERITY_WEIGHTS.get(vuln.severity.upper(), 1.0)
            multiplier = 1.0
            if vuln.cisa_kev:
                multiplier *= 1.5
            if vuln.exploit_available:
                multiplier *= 1.3
            if vuln.epss_score and vuln.epss_score > 0.7:
                multiplier *= 1.2
            penalty += base_penalty * multiplier

        score = max(0.0, 100.0 - penalty / assets_count)
        return round(score, 1)

    def calculate_historical_score(
        self,
        organization_id: str,
        target_date: datetime,
    ) -> float:
        """Calcule le score à une date passée (pour le trending)."""
        closest_scan = (
            self.db.query(Scan)
            .filter(
                Scan.organization_id == organization_id,
                Scan.completed_at <= target_date,
                Scan.status == "completed",
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )

        if not closest_scan:
            return 100.0

        vulns = (
            self.db.query(Vulnerability)
            .filter(Vulnerability.scan_id == closest_scan.id)
            .all()
        )

        assets_count = (
            self.db.query(func.count(Asset.id))
            .filter(
                Asset.organization_id == organization_id,
                Asset.is_active.is_(True),
            )
            .scalar()
        ) or 1

        if not vulns:
            return 100.0

        penalty = 0.0
        for vuln in vulns:
            base_penalty = self.SEVERITY_WEIGHTS.get(vuln.severity.upper(), 1.0)
            multiplier = 1.0
            if vuln.cisa_kev:
                multiplier *= 1.5
            if vuln.exploit_available:
                multiplier *= 1.3
            if vuln.epss_score and vuln.epss_score > 0.7:
                multiplier *= 1.2
            penalty += base_penalty * multiplier

        score = max(0.0, 100.0 - penalty / assets_count)
        return round(score, 1)

    def get_trend(self, organization_id: str) -> Dict[str, Any]:
        """
        Compare le score actuel avec celui d'il y a 7 jours.

        Returns:
            {
                "current": 67.0,
                "last_week": 75.0,
                "trend": -8.0,
                "direction": "down",
                "risk_level": "HIGH"
            }
        """
        current_score = self.calculate_score(organization_id)
        week_ago = datetime.utcnow() - timedelta(days=7)
        last_week_score = self.calculate_historical_score(organization_id, week_ago)
        trend = current_score - last_week_score

        return {
            "current": current_score,
            "last_week": last_week_score,
            "trend": round(trend, 1),
            "direction": "up" if trend > 0 else "down" if trend < 0 else "stable",
            "risk_level": self._get_risk_level(current_score),
        }

    def _get_risk_level(self, score: float) -> str:
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM"
        elif score >= 40:
            return "HIGH"
        else:
            return "CRITICAL"
