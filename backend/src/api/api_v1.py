from __future__ import annotations

"""
Regroupe toutes les routes HTTP de l'API v1 basées sur PostgreSQL (assets, scans,
vulnérabilités, intégrations, statistiques dashboard).

Les sous-routers définissent déjà le préfixe `/api/v1`, donc ce router racine
n'ajoute **aucun** préfixe supplémentaire pour éviter les doublons du type
`/api/v1/api/v1/...`.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Scan, Vulnerability, RemediationScript
from src.api.dependencies import get_current_user
from src.core.analyzer import Analyzer

from src.api.routes.assets import router as assets_router
from src.api.routes.scans import router as scans_router
from src.api.routes.vulnerabilities import router as vulns_router
from src.api.routes.integrations import router as integrations_router
from src.api.routes.dashboard import router as dashboard_router
from src.utils.logger import setup_logger


logger = setup_logger(__name__)

# Router racine v1 (sans préfixe supplémentaire)
router = APIRouter()

# Sous-routers métier (déjà préfixés en /api/v1)
router.include_router(assets_router)
router.include_router(scans_router)
router.include_router(vulns_router)
router.include_router(integrations_router)
router.include_router(dashboard_router)


# === STOCKAGE EN MÉMOIRE POUR LES GROUPES DE VULNÉRABILITÉS (POC) ===

VULNERABILITY_GROUPS: Dict[str, Dict[str, Any]] = {}


async def _get_analyzer() -> Analyzer:
    return Analyzer()


# === ROUTES STATISTIQUES POUR DASHBOARD (/api/v1/stats/...) ===


@router.get("/api/v1/stats/overview", tags=["stats"])
async def get_overview_stats(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Statistiques globales pour le dashboard (PostgreSQL + multi-tenant).
    """
    try:
        org_id = current_user["organization_id"]

        # Total scans
        total_scans = (
            db.query(func.count(Scan.id))
            .filter(Scan.organization_id == org_id)
            .scalar()
        ) or 0

        # Scans récents (30 derniers jours)
        now = datetime.utcnow()
        cutoff = now - timedelta(days=30)
        recent_scans = (
            db.query(func.count(Scan.id))
            .filter(
                Scan.organization_id == org_id,
                Scan.created_at >= cutoff,
            )
            .scalar()
        ) or 0

        # Vulnérabilités
        total_vulns = (
            db.query(func.count(Vulnerability.id))
            .filter(Vulnerability.organization_id == org_id)
            .scalar()
        ) or 0

        critical_vulns = (
            db.query(func.count(Vulnerability.id))
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.severity == "CRITICAL",
            )
            .scalar()
        ) or 0

        # Moyenne CVSS
        avg_cvss = (
            db.query(func.avg(Vulnerability.cvss_score))
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.cvss_score.isnot(None),
            )
            .scalar()
        )
        average_cvss = round(float(avg_cvss), 2) if avg_cvss is not None else 0.0

        # Total scripts
        total_scripts = (
            db.query(func.count(RemediationScript.id))
            .filter(RemediationScript.organization_id == org_id)
            .scalar()
        ) or 0

        return {
            "total_scans": total_scans,
            "recent_scans": recent_scans,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "total_scripts": total_scripts,
            "average_cvss": average_cvss,
        }
    except Exception as e:  # pragma: no cover - log only
        logger.error("Erreur stats overview: %s", e)
        raise HTTPException(status_code=500, detail="Erreur statistiques overview")


@router.get("/api/v1/stats/severity-distribution", tags=["stats"])
async def get_severity_distribution(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Répartition des vulnérabilités par sévérité pour le dashboard (PostgreSQL).
    """
    try:
        org_id = current_user["organization_id"]

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        rows = (
            db.query(Vulnerability.severity, func.count(Vulnerability.id))
            .filter(Vulnerability.organization_id == org_id)
            .group_by(Vulnerability.severity)
            .all()
        )

        for severity, count in rows:
            sev = (severity or "UNKNOWN").upper()
            if sev in counts:
                counts[sev] += count
            else:
                counts["UNKNOWN"] += count

        labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        values = [counts[l] for l in labels]
        colors = ["#DC2626", "#F97316", "#FACC15", "#22C55E", "#9CA3AF"]

        return {
            "labels": labels,
            "values": values,
            "colors": colors,
        }
    except Exception as e:  # pragma: no cover - log only
        logger.error("Erreur stats severity-distribution: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Erreur statistiques severity-distribution",
        )


@router.get("/api/v1/stats/timeline", tags=["stats"])
async def get_timeline_stats(
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Timeline des scans sur 30 jours (PostgreSQL, multi-tenant).
    Renvoie un format compatible avec Chart.js (labels + datasets).
    """
    try:
        org_id = current_user["organization_id"]
        now = datetime.utcnow()
        cutoff = now - timedelta(days=30)

        scans = (
            db.query(Scan)
            .filter(
                Scan.organization_id == org_id,
                Scan.created_at >= cutoff,
            )
            .order_by(Scan.created_at.asc())
            .all()
        )

        timeline_counts: Dict[str, int] = {}
        for scan in scans:
            day = (scan.completed_at or scan.created_at).date().isoformat()
            timeline_counts[day] = timeline_counts.get(day, 0) + 1

        labels = sorted(timeline_counts.keys())
        values = [timeline_counts[d] for d in labels]

        return {
            "labels": labels,
            "datasets": [
                {
                    "label": "Scans par jour",
                    "data": values,
                    "borderColor": "#2563EB",
                    "backgroundColor": "rgba(37, 99, 235, 0.3)",
                    "fill": True,
                    "tension": 0.3,
                }
            ],
        }
    except Exception as e:  # pragma: no cover - log only
        logger.error("Erreur stats timeline: %s", e)
        raise HTTPException(status_code=500, detail="Erreur statistiques timeline")


@router.get("/api/v1/stats/top-vulnerabilities", tags=["stats"])
async def get_top_vulnerabilities(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Top vulnérabilités pour le dashboard (PostgreSQL).
    """
    try:
        org_id = current_user["organization_id"]

        vulns: List[Vulnerability] = (
            db.query(Vulnerability)
            .filter(Vulnerability.organization_id == org_id)
            .order_by(Vulnerability.cvss_score.desc().nullslast())
            .limit(limit)
            .all()
        )

        top = [
            {
                "vulnerability_id": str(v.id),
                "name": v.title,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else 0.0,
                "description": v.description or "",
                "affected_service": v.service or "",
            }
            for v in vulns
        ]

        return {"vulnerabilities": top}
    except Exception as e:  # pragma: no cover - log only
        logger.error("Erreur stats top-vulnerabilities: %s", e)
        raise HTTPException(
            status_code=500,
            detail="Erreur statistiques top-vulnerabilities",
        )


# === ENDPOINTS MINIMAUX POUR L'HISTORIQUE D'ANALYSE IA ===


@router.get("/api/v1/analysis-history", tags=["analysis"])
async def list_analysis_history(
    limit: int = Query(50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Endpoint minimal pour l'historique des analyses IA.

    Pour le moment il renvoie simplement une liste vide, ce qui permet au
    frontend d'afficher une page "Aucune analyse IA enregistrée".
    """
    _ = current_user  # réservé pour usage futur (multi-tenant)
    return {
        "analyses": [],
        "total": 0,
        "count": 0,
        "limit": limit,
    }


@router.get("/api/v1/analysis-history/{analysis_id}", tags=["analysis"])
async def get_analysis_history_item(
    analysis_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Détail d'une analyse IA.

    Implémentation minimale : on renvoie une 404 explicite tant qu'aucun
    stockage d'historique n'est en place.
    """
    _ = current_user  # réservé pour usage futur
    raise HTTPException(
        status_code=404,
        detail=f"Aucune analyse IA trouvée pour id={analysis_id}",
    )


# === ENDPOINTS MINIMAUX POUR LES GROUPES DE VULNÉRABILITÉS ===


@router.get("/api/v1/vulnerability-groups", tags=["vulnerability-groups"])
async def list_vulnerability_groups(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Liste des groupes de vulnérabilités (stockage en mémoire, scoping par organization_id).
    """
    org_id = str(current_user["organization_id"])
    groups = [
        g for g in VULNERABILITY_GROUPS.values() if g.get("organization_id") == org_id
    ]
    groups.sort(key=lambda g: g.get("created_at", ""), reverse=True)
    return {"groups": groups}


@router.post("/api/v1/vulnerability-groups", tags=["vulnerability-groups"])
async def create_vulnerability_group(
    body: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Création d'un groupe en mémoire (POC multi-tenant).

    On stocke:
    - group_id
    - organization_id
    - name / description
    - vulnerability_ids (liste d'IDs de vulnérabilités internes)
    """
    org_id = current_user["organization_id"]
    group_id = str(uuid.uuid4())

    vulnerability_ids = body.get("vulnerability_ids") or []
    if not isinstance(vulnerability_ids, list):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="vulnerability_ids doit être une liste",
        )

    group = {
        "group_id": group_id,
        "organization_id": str(org_id),
        "name": body.get("name", ""),
        "description": body.get("description", ""),
        "vulnerability_ids": vulnerability_ids,
        "vulnerability_count": len(vulnerability_ids),
        "created_at": datetime.utcnow().isoformat(),
    }

    VULNERABILITY_GROUPS[group_id] = group
    return group


@router.get("/api/v1/vulnerability-groups/{group_id}", tags=["vulnerability-groups"])
async def get_vulnerability_group(
    group_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Détail d'un groupe de vulnérabilités, avec la liste des vulnérabilités associées.
    """
    org_id = current_user["organization_id"]
    group = VULNERABILITY_GROUPS.get(group_id)
    if not group or group.get("organization_id") != str(org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Groupe introuvable"
        )

    vuln_ids = group.get("vulnerability_ids") or []
    valid_uuids = []
    for raw_id in vuln_ids:
        try:
            valid_uuids.append(uuid.UUID(str(raw_id)))
        except ValueError:
            continue

    vulns: List[Vulnerability] = []
    if valid_uuids:
        vulns = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.organization_id == org_id,
                Vulnerability.id.in_(valid_uuids),
            )
            .order_by(Vulnerability.cvss_score.desc().nullslast())
            .all()
        )

    serialized_vulns = []
    for v in vulns:
        serialized_vulns.append(
            {
                "id": str(v.id),
                "scan_id": str(v.scan_id),
                "cve_id": v.cve_id,
                "title": v.title,
                "description": v.description,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "port": v.port,
                "service": v.service,
                "status": v.status,
                "ai_analyzed": v.ai_analyzed,
                "ai_priority_score": v.ai_priority_score,
            }
        )

    return {
        "group_id": group["group_id"],
        "name": group["name"],
        "description": group["description"],
        "created_at": group["created_at"],
        "vulnerability_ids": vuln_ids,
        "vulnerability_count": len(vuln_ids),
        "vulnerabilities": serialized_vulns,
    }


@router.delete("/api/v1/vulnerability-groups/{group_id}", tags=["vulnerability-groups"])
async def delete_vulnerability_group(
    group_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Suppression d'un groupe (en mémoire).
    """
    org_id = str(current_user["organization_id"])
    group = VULNERABILITY_GROUPS.get(group_id)
    if not group or group.get("organization_id") != org_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Groupe introuvable"
        )

    VULNERABILITY_GROUPS.pop(group_id, None)
    return {"deleted": True, "group_id": group_id}


@router.post("/api/v1/analyze/group/{group_id}", tags=["analysis"])
async def analyze_vulnerability_group(
    group_id: str,
    target_system: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Analyse IA d'un groupe de vulnérabilités.

    - Récupère le groupe en mémoire (scopé par organization_id)
    - Charge les vulnérabilités correspondantes en base
    - Appelle Analyzer.analyze_vulnerabilities_batch(...)
    - Met à jour ai_analysis / ai_priority_score pour chaque vulnérabilité
    - Retourne un résumé + plan de remédiation global
    """
    org_id = current_user["organization_id"]
    group = VULNERABILITY_GROUPS.get(group_id)
    if not group or group.get("organization_id") != str(org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Groupe introuvable"
        )

    vuln_ids = group.get("vulnerability_ids") or []
    if not vuln_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Aucune vulnérabilité dans ce groupe",
        )

    # Filtrer uniquement les IDs UUID valides correspondant à des vulnérabilités de l'organisation
    valid_uuids = []
    for raw_id in vuln_ids:
        try:
            valid_uuids.append(uuid.UUID(str(raw_id)))
        except ValueError:
            # On ignore les entrées qui ne sont pas des UUID internes
            continue

    if not valid_uuids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Aucun ID de vulnérabilité interne valide dans ce groupe",
        )

    vulns = (
        db.query(Vulnerability)
        .filter(
            Vulnerability.organization_id == org_id,
            Vulnerability.id.in_(valid_uuids),
        )
        .all()
    )
    if not vulns:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Aucune vulnérabilité trouvée pour ce groupe",
        )

    analyzer = await _get_analyzer()

    vulns_payload = []
    for v in vulns:
        vulns_payload.append(
            {
                "vulnerability_id": str(v.id),
                "name": v.title,
                "severity": v.severity,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
                "description": v.description or "",
                "service": v.service or "",
                "port": v.port,
                "cve_id": v.cve_id,
            }
        )

    try:
        result = await analyzer.analyze_vulnerabilities_batch(
            vulnerabilities_data=vulns_payload,
            target_system=target_system or "Unknown System",
        )
    except Exception as e:
        logger.error("Erreur analyse IA pour groupe %s: %s", group_id, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse IA du groupe: {e}",
        )

    # Mettre à jour les vulnérabilités avec les résultats IA
    analyzed_by_id: Dict[str, Any] = {}
    for v in result.vulnerabilities:
        vid = str(v.vulnerability_id)
        analyzed_by_id[vid] = v.to_dict() if hasattr(v, "to_dict") else dict(v)

    for v in vulns:
        key = str(v.id)
        analysis = analyzed_by_id.get(key)
        if not analysis:
            continue
        v.ai_analyzed = True
        v.ai_analysis = analysis
        v.ai_priority_score = analysis.get("priority_score")
        db.add(v)

    db.commit()

    # Préparer une vue simplifiée de l'analyse par vulnérabilité pour le frontend
    analyzed_vulns: List[Dict[str, Any]] = []
    for v in result.vulnerabilities:
        data = v.to_dict() if hasattr(v, "to_dict") else dict(v)
        analyzed_vulns.append(
            {
                "vulnerability_id": data.get("vulnerability_id"),
                "name": data.get("name"),
                "severity": data.get("severity"),
                "cvss_score": data.get("cvss_score"),
                "impact_analysis": data.get("impact_analysis"),
                "business_impact": data.get("business_impact"),
                "ai_explanation": data.get("ai_explanation"),
                "recommended_actions": data.get("recommended_actions") or [],
            }
        )

    return {
        "analysis_id": result.analysis_id,
        "target_system": result.target_system,
        "analysis_summary": result.analysis_summary,
        "remediation_plan": result.remediation_plan,
        "ai_model_used": result.ai_model_used,
        "confidence_score": result.confidence_score,
        "vulnerability_count": len(vulns),
        "vulnerabilities": analyzed_vulns,
        "message": f"Analyse IA du groupe '{group.get('name')}' terminée avec succès.",
    }


