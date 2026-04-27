"""
Service de calcul de la conformité réglementaire.

Frameworks supportés : PCI DSS, ISO 27001, SOC 2, GDPR.
Le score de conformité est calculé à partir des vulnérabilités ouvertes
et de leur sévérité, en appliquant les règles spécifiques à chaque framework.
"""

from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func

from src.database.models import Vulnerability, Asset


# Règles de conformité par framework
COMPLIANCE_FRAMEWORKS = {
    "PCI DSS": {
        "description": "Payment Card Industry Data Security Standard",
        "max_critical": 0,
        "max_high": 0,
        "penalty_medium": True,
        "controls": [
            "Aucune vulnérabilité CRITICAL",
            "Aucune vulnérabilité HIGH",
            "Patch management à jour",
            "Accès réseau restreint",
        ],
    },
    "ISO 27001": {
        "description": "Information Security Management",
        "max_critical": 0,
        "max_high": 5,
        "penalty_medium": False,
        "controls": [
            "Aucune vulnérabilité CRITICAL",
            "Vulnérabilités HIGH < 5",
            "Politique de sécurité définie",
            "Gestion des incidents",
        ],
    },
    "SOC 2": {
        "description": "Service Organization Control 2",
        "max_critical": 0,
        "max_high": 3,
        "penalty_medium": False,
        "controls": [
            "Aucune vulnérabilité CRITICAL",
            "Vulnérabilités HIGH < 3",
            "Monitoring continu",
            "Contrôle d'accès",
        ],
    },
    "GDPR": {
        "description": "General Data Protection Regulation",
        "max_critical": 0,
        "max_high": 2,
        "penalty_medium": False,
        "controls": [
            "Aucune vulnérabilité CRITICAL",
            "Vulnérabilités HIGH < 2",
            "Chiffrement des données",
            "Notification de violation",
        ],
    },
}


class ComplianceCalculator:
    """Calcule le statut de conformité par framework réglementaire."""

    def __init__(self, db: Session):
        self.db = db

    def _get_vuln_counts(self, organization_id: str) -> Dict[str, int]:
        """Retourne le nombre de vulnérabilités ouvertes par sévérité."""
        rows = (
            self.db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .filter(
                Vulnerability.organization_id == organization_id,
                Vulnerability.status == "open",
            )
            .group_by(Vulnerability.severity)
            .all()
        )
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for sev, count in rows:
            key = (sev or "").upper()
            if key in counts:
                counts[key] = count
        return counts

    def _evaluate_framework(
        self,
        framework_name: str,
        rules: Dict,
        counts: Dict[str, int],
    ) -> Dict[str, Any]:
        """
        Évalue la conformité pour un framework donné.

        Returns:
            {
                "framework": "PCI DSS",
                "status": "NON_COMPLIANT",
                "score": 42,
                "issues": ["12 vulnérabilités CRITICAL détectées"],
                "controls_passed": 1,
                "controls_total": 4
            }
        """
        issues = []
        controls_passed = 0
        controls_total = len(rules["controls"])

        # Contrôle 1 : pas de CRITICAL
        if counts["CRITICAL"] <= rules["max_critical"]:
            controls_passed += 1
        else:
            issues.append(f"{counts['CRITICAL']} vulnérabilité(s) CRITICAL détectée(s)")

        # Contrôle 2 : HIGH sous le seuil
        if counts["HIGH"] <= rules["max_high"]:
            controls_passed += 1
        else:
            issues.append(f"{counts['HIGH']} vulnérabilité(s) HIGH (max autorisé : {rules['max_high']})")

        # Contrôles fixes (policy, monitoring, etc.) → considérés comme passés si pas de CRITICAL
        remaining = controls_total - 2
        if counts["CRITICAL"] == 0:
            controls_passed += remaining
        else:
            controls_passed += remaining // 2

        # Score : pourcentage de contrôles passés
        score = int((controls_passed / controls_total) * 100) if controls_total > 0 else 0

        # Statut
        if counts["CRITICAL"] > rules["max_critical"] or counts["HIGH"] > rules["max_high"]:
            status = "NON_COMPLIANT"
        elif score >= 80:
            status = "COMPLIANT"
        else:
            status = "PARTIAL"

        return {
            "framework": framework_name,
            "description": rules["description"],
            "status": status,
            "score": score,
            "issues": issues,
            "controls_passed": controls_passed,
            "controls_total": controls_total,
            "controls": rules["controls"],
        }

    def get_compliance_status(self, organization_id: str) -> List[Dict[str, Any]]:
        """
        Retourne le statut de conformité pour tous les frameworks.

        Returns:
            [
                {
                    "framework": "PCI DSS",
                    "status": "NON_COMPLIANT",
                    "score": 42,
                    "issues": [...],
                    "controls_passed": 1,
                    "controls_total": 4
                },
                ...
            ]
        """
        counts = self._get_vuln_counts(organization_id)
        results = []
        for name, rules in COMPLIANCE_FRAMEWORKS.items():
            result = self._evaluate_framework(name, rules, counts)
            results.append(result)
        return results
