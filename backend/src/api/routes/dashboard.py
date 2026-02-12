"""
Endpoint de statistiques globales pour le dashboard (CDC 2 – Semaine 3).

GET /api/v1/dashboard/stats
- Filtré par organization (multi-tenant)
- Agrège les métriques clés pour le frontend
"""

from __future__ import annotations

from datetime import datetime, timedelta, date
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, cast, Date
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Asset, Scan, Vulnerability
from src.api.dependencies import get_current_user
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


