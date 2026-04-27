"""
Service de calcul du MTTR (Mean Time To Remediate).

Calcule le délai moyen de résolution des vulnérabilités par sévérité
et compare avec les benchmarks de l'industrie.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.database.models import Vulnerability


# Benchmarks industrie en jours (source : Tenable / Ponemon Institute)
INDUSTRY_BENCHMARKS = {
    "CRITICAL": 7,    # 7 jours pour les critiques
    "HIGH":     30,   # 30 jours pour les HIGH
    "MEDIUM":   90,   # 90 jours pour les MEDIUM
    "LOW":      180,  # 180 jours pour les LOW
}


class MTTRCalculator:
    """Calcule le Mean Time to Remediate par sévérité."""

    def __init__(self, db: Session):
        self.db = db

    def _calculate_mttr_for_severity(
        self,
        organization_id: str,
        severity: str,
    ) -> Optional[float]:
        """
        Calcule le MTTR en jours pour une sévérité donnée.

        Utilise les vulnérabilités résolues avec resolved_at renseigné.
        """
        vulns = (
            self.db.query(Vulnerability)
            .filter(
                Vulnerability.organization_id == organization_id,
                Vulnerability.severity == severity,
                Vulnerability.status == "resolved",
                Vulnerability.resolved_at.isnot(None),
            )
            .all()
        )

        if not vulns:
            return None

        total_days = 0.0
        valid_count = 0

        for vuln in vulns:
            if vuln.resolved_at and vuln.first_detected_at:
                delta = (vuln.resolved_at - vuln.first_detected_at).total_seconds()
                days = delta / 86400
                if days >= 0:
                    total_days += days
                    valid_count += 1

        if valid_count == 0:
            return None

        return round(total_days / valid_count, 1)

    def get_mttr_by_severity(self, organization_id: str) -> List[Dict[str, Any]]:
        """
        Retourne le MTTR par sévérité avec comparaison industrie.

        Returns:
            [
                {
                    "severity": "CRITICAL",
                    "mttr_days": 12.5,
                    "benchmark_days": 7,
                    "status": "ABOVE_BENCHMARK",
                    "resolved_count": 45
                },
                ...
            ]
        """
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        results = []

        for severity in severities:
            mttr = self._calculate_mttr_for_severity(organization_id, severity)
            benchmark = INDUSTRY_BENCHMARKS[severity]

            resolved_count = (
                self.db.query(func.count(Vulnerability.id))
                .filter(
                    Vulnerability.organization_id == organization_id,
                    Vulnerability.severity == severity,
                    Vulnerability.status == "resolved",
                )
                .scalar()
            ) or 0

            if mttr is None:
                status = "NO_DATA"
            elif mttr <= benchmark:
                status = "WITHIN_BENCHMARK"
            elif mttr <= benchmark * 1.5:
                status = "SLIGHTLY_ABOVE"
            else:
                status = "ABOVE_BENCHMARK"

            results.append(
                {
                    "severity": severity,
                    "mttr_days": mttr,
                    "benchmark_days": benchmark,
                    "status": status,
                    "resolved_count": resolved_count,
                }
            )

        return results

    def get_overall_mttr(self, organization_id: str) -> Dict[str, Any]:
        """
        Retourne le MTTR global et les statistiques agrégées.

        Returns:
            {
                "overall_mttr_days": 28.3,
                "by_severity": [...],
                "total_resolved": 234,
                "benchmark_comparison": "ABOVE_BENCHMARK"
            }
        """
        by_severity = self.get_mttr_by_severity(organization_id)

        # MTTR global = moyenne pondérée des sévérités avec données
        valid = [s for s in by_severity if s["mttr_days"] is not None]
        overall = round(sum(s["mttr_days"] for s in valid) / len(valid), 1) if valid else None

        total_resolved = sum(s["resolved_count"] for s in by_severity)

        # Statut global basé sur le CRITICAL
        critical_entry = next((s for s in by_severity if s["severity"] == "CRITICAL"), None)
        overall_status = critical_entry["status"] if critical_entry else "NO_DATA"

        return {
            "overall_mttr_days": overall,
            "by_severity": by_severity,
            "total_resolved": total_resolved,
            "benchmark_comparison": overall_status,
            "industry_benchmarks": INDUSTRY_BENCHMARKS,
        }
