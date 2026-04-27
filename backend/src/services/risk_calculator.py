"""
Service de calcul du risque par asset.
"""

from typing import List, Dict, Any

from sqlalchemy.orm import Session

from src.database.models import Asset, Scan, Vulnerability
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


class AssetRiskCalculator:
    """Calcule le score de risque des assets."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 10.0,
        "HIGH": 5.0,
        "MEDIUM": 2.0,
        "LOW": 0.5,
    }

    def __init__(self, db: Session):
        self.db = db

    def _get_open_vulns_for_asset(self, asset_id) -> List[Vulnerability]:
        """Récupère les vulnérabilités ouvertes d'un asset."""
        return (
            self.db.query(Vulnerability)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .filter(
                Scan.asset_id == asset_id,
                Vulnerability.status == "open",
            )
            .all()
        )

    def calculate_asset_risk(self, asset: Asset) -> float:
        """
        Calcule le score de risque d'un asset.

        Formule: base_score * multipliers (KEV ×1.5, exploit ×1.3, EPSS>0.7 ×1.2)

        Returns:
            Score de risque (plus élevé = plus risqué)
        """
        vulns = self._get_open_vulns_for_asset(asset.id)

        if not vulns:
            return 0.0

        risk_score = 0.0
        for vuln in vulns:
            base_score = self.SEVERITY_WEIGHTS.get(vuln.severity.upper(), 1.0)
            multiplier = 1.0
            if vuln.cisa_kev:
                multiplier *= 1.5
            if vuln.exploit_available:
                multiplier *= 1.3
            if vuln.epss_score and vuln.epss_score > 0.7:
                multiplier *= 1.2
            risk_score += base_score * multiplier

        return round(risk_score, 2)

    def get_top_risky_assets(
        self,
        organization_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Retourne les N assets les plus à risque.

        Returns:
            [
                {
                    "id": "uuid",
                    "hostname": "web-prod-01",
                    "ip_address": "192.168.1.10",
                    "risk_score": 892.5,
                    "critical_vulns": 23,
                    "high_vulns": 45,
                    "total_vulns": 120
                },
                ...
            ]
        """
        assets = (
            self.db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.is_active.is_(True),
            )
            .all()
        )

        assets_with_risk = []
        for asset in assets:
            risk_score = self.calculate_asset_risk(asset)
            vulns = self._get_open_vulns_for_asset(asset.id)

            critical_count = sum(1 for v in vulns if v.severity == "CRITICAL")
            high_count = sum(1 for v in vulns if v.severity == "HIGH")

            assets_with_risk.append(
                {
                    "id": str(asset.id),
                    "hostname": asset.hostname or str(asset.ip_address),
                    "ip_address": str(asset.ip_address),
                    "risk_score": risk_score,
                    "critical_vulns": critical_count,
                    "high_vulns": high_count,
                    "total_vulns": len(vulns),
                }
            )

        assets_with_risk.sort(key=lambda x: x["risk_score"], reverse=True)
        return assets_with_risk[:limit]
