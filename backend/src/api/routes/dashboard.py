"""
Endpoints du dashboard de sécurité (CDC Tenable niveau 100%).

Endpoints disponibles :
- GET /api/v1/dashboard/stats              → statistiques générales
- GET /api/v1/dashboard/security-score     → score 0-100 avec trending
- GET /api/v1/dashboard/top-risky-assets   → top N assets à risque
- GET /api/v1/dashboard/vulnerability-trends → tendances par sévérité (30j)
- GET /api/v1/dashboard/severity-distribution → répartition par sévérité
- GET /api/v1/dashboard/top-vulnerabilities-by-assets → top CVEs
"""

from __future__ import annotations

from datetime import datetime, timedelta, date
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, cast, Date
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Asset, Scan, Vulnerability
from src.api.dependencies import get_current_user
from src.services.security_score import SecurityScoreCalculator
from src.services.risk_calculator import AssetRiskCalculator
from src.utils.logger import setup_logger


logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/stats")
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
  """
  Statistiques agrégées pour le dashboard de sécurité.

  Retourne :
  {
    "total_assets": 25,
    "active_assets": 23,
    "total_scans": 150,
    "scans_this_month": 42,
    "total_vulnerabilities": 234,
    "open_vulnerabilities": 180,
    "by_severity": {
      "CRITICAL": 12,
      "HIGH": 45,
      "MEDIUM": 89,
      "LOW": 34
    },
    "avg_risk_score": 6.7,
    "trend_30_days": [
      {"date": "2026-01-13", "vulnerabilities": 200, "risk_score": 7.2},
      ...
    ]
  }
  """
  try:
    org_id = current_user["organization_id"]

    # --- Assets ---
    total_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.organization_id == org_id)
        .scalar()
    ) or 0

    active_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.organization_id == org_id, Asset.is_active.is_(True))
        .scalar()
    ) or 0

    # --- Scans ---
    total_scans = (
        db.query(func.count(Scan.id))
        .filter(Scan.organization_id == org_id)
        .scalar()
    ) or 0

    now = datetime.utcnow()
    month_start = datetime(now.year, now.month, 1)

    scans_this_month = (
        db.query(func.count(Scan.id))
        .filter(
            Scan.organization_id == org_id,
            Scan.created_at >= month_start,
        )
        .scalar()
    ) or 0

    # --- Vulnérabilités globales ---
    total_vulns = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.organization_id == org_id)
        .scalar()
    ) or 0

    open_vulns = (
        db.query(func.count(Vulnerability.id))
        .filter(
            Vulnerability.organization_id == org_id,
            Vulnerability.status == "open",
        )
        .scalar()
    ) or 0

    # --- Répartition par sévérité ---
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .filter(Vulnerability.organization_id == org_id)
        .group_by(Vulnerability.severity)
        .all()
    )
    for sev, count in rows:
      sev_norm = (sev or "").upper()
      if sev_norm in severity_counts:
        severity_counts[sev_norm] += count

    # --- Score de risque moyen ---
    # On utilise ici la moyenne de Scan.risk_score quand disponible, sinon 0.
    avg_risk = (
        db.query(func.avg(Scan.risk_score))
        .filter(
            Scan.organization_id == org_id,
            Scan.risk_score.isnot(None),
        )
        .scalar()
    )
    avg_risk_score = float(avg_risk) if avg_risk is not None else 0.0

    # --- Trend 30 jours (vulnérabilités + risk score moyen) ---
    cutoff = now - timedelta(days=30)
    trend_rows = (
        db.query(
            cast(Vulnerability.first_detected_at, Date).label("day"),
            func.count(Vulnerability.id).label("vuln_count"),
            func.avg(Vulnerability.cvss_score).label("avg_cvss"),
        )
        .filter(
            Vulnerability.organization_id == org_id,
            Vulnerability.first_detected_at >= cutoff,
        )
        .group_by("day")
        .order_by("day")
        .all()
    )

    trend_30_days: List[Dict[str, Any]] = []
    for row in trend_rows:
      day: date = row.day
      vuln_count: int = row.vuln_count or 0
      avg_cvss = float(row.avg_cvss) if row.avg_cvss is not None else 0.0
      trend_30_days.append(
          {
              "date": day.isoformat(),
              "vulnerabilities": vuln_count,
              "risk_score": avg_cvss,
          }
      )

    return {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "total_scans": total_scans,
        "scans_this_month": scans_this_month,
        "total_vulnerabilities": total_vulns,
        "open_vulnerabilities": open_vulns,
        "by_severity": severity_counts,
        "avg_risk_score": round(avg_risk_score, 2),
        "trend_30_days": trend_30_days,
    }

  except Exception as e:  # pragma: no cover - log only
    logger.error("Erreur dashboard stats: %s", e)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Erreur lors du calcul des statistiques du dashboard",
    )


# ============================================================================
# ENDPOINT : Security Score (0-100) avec trending
# ============================================================================


@router.get("/security-score")
def get_security_score(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retourne le score de sécurité global avec trending semaine.

    Response:
    {
        "current": 67.0,
        "last_week": 75.0,
        "trend": -8.0,
        "direction": "down",
        "risk_level": "HIGH"
    }
    """
    try:
        org_id = current_user["organization_id"]
        calculator = SecurityScoreCalculator(db)
        return calculator.get_trend(org_id)
    except Exception as e:
        logger.error("Erreur security score: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors du calcul du score de sécurité",
        )


# ============================================================================
# ENDPOINT : Top N assets les plus à risque
# ============================================================================


@router.get("/top-risky-assets")
def get_top_risky_assets(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Retourne les N assets les plus à risque (trié par risk score).

    Response:
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
    try:
        org_id = current_user["organization_id"]
        calculator = AssetRiskCalculator(db)
        return calculator.get_top_risky_assets(org_id, limit)
    except Exception as e:
        logger.error("Erreur top risky assets: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors du calcul des assets à risque",
        )


# ============================================================================
# ENDPOINT : Vulnerability trends par sévérité (30 jours)
# ============================================================================


@router.get("/vulnerability-trends")
def get_vulnerability_trends(
    days: int = Query(default=30, ge=7, le=90),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Tendances des vulnérabilités par sévérité sur N jours.

    Response:
    [
        {"date": "2026-04-01", "critical": 5, "high": 12, "medium": 30, "low": 8},
        ...
    ]
    """
    try:
        org_id = current_user["organization_id"]
        cutoff = datetime.utcnow() - timedelta(days=days)

        rows = (
            db.query(
                cast(Vulnerability.first_detected_at, Date).label("day"),
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count"),
            )
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.first_detected_at >= cutoff,
            )
            .group_by("day", Vulnerability.severity)
            .order_by("day")
            .all()
        )

        # Regrouper par date
        by_date: Dict[str, Dict] = {}
        for row in rows:
            day_str = row.day.isoformat()
            if day_str not in by_date:
                by_date[day_str] = {
                    "date": day_str,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }
            sev = (row.severity or "").lower()
            if sev in by_date[day_str]:
                by_date[day_str][sev] += row.count

        return sorted(by_date.values(), key=lambda x: x["date"])

    except Exception as e:
        logger.error("Erreur vulnerability trends: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors du calcul des tendances",
        )


# ============================================================================
# ENDPOINT : Distribution des vulnérabilités par sévérité
# ============================================================================


@router.get("/severity-distribution")
def get_severity_distribution(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Répartition des vulnérabilités ouvertes par sévérité.

    Response:
    [
        {"name": "CRITICAL", "value": 12, "color": "#ef4444"},
        {"name": "HIGH",     "value": 45, "color": "#f97316"},
        {"name": "MEDIUM",   "value": 89, "color": "#eab308"},
        {"name": "LOW",      "value": 34, "color": "#22c55e"}
    ]
    """
    try:
        org_id = current_user["organization_id"]

        rows = (
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.status == "open",
            )
            .group_by(Vulnerability.severity)
            .all()
        )

        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
            "INFO": "#6b7280",
        }

        result = []
        for sev, count in rows:
            sev_norm = (sev or "").upper()
            result.append(
                {
                    "name": sev_norm,
                    "value": count,
                    "color": color_map.get(sev_norm, "#6b7280"),
                }
            )

        # Trier par ordre de sévérité
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        result.sort(key=lambda x: order.index(x["name"]) if x["name"] in order else 99)
        return result

    except Exception as e:
        logger.error("Erreur severity distribution: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors du calcul de la distribution",
        )


# ============================================================================
# ENDPOINT : Top CVEs par nombre d'assets affectés
# ============================================================================


@router.get("/top-vulnerabilities-by-assets")
def get_top_vulnerabilities_by_assets(
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """
    Top CVEs classés par nombre d'assets distincts affectés.

    Response:
    [
        {"cve": "CVE-2021-44228", "assets": 15, "severity": "CRITICAL"},
        ...
    ]
    """
    try:
        org_id = current_user["organization_id"]

        rows = (
            db.query(
                Vulnerability.cve_id,
                Vulnerability.severity,
                func.count(func.distinct(Scan.asset_id)).label("asset_count"),
            )
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.status == "open",
                Vulnerability.cve_id.isnot(None),
            )
            .group_by(Vulnerability.cve_id, Vulnerability.severity)
            .order_by(func.count(func.distinct(Scan.asset_id)).desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "cve": row.cve_id,
                "assets": row.asset_count,
                "severity": (row.severity or "").upper(),
            }
            for row in rows
        ]

    except Exception as e:
        logger.error("Erreur top vulnerabilities by assets: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors du calcul du top vulnérabilités",
        )

