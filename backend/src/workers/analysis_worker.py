"""
Worker Celery pour l'analyse IA batch de toutes les vulnérabilités d'un scan.

Flow:
1. Récupérer toutes les vulnérabilités du scan
2. Pour chaque vuln : appeler Analyzer.analyze_vulnerability()
3. Sauvegarder le résultat dans vulnerability.ai_analysis
4. Générer le plan de remédiation global
5. Mettre à jour RemediationPlan avec le plan généré
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List

from src.workers.celery_app import celery_app
from src.database.init_db import SessionLocal
from src.database.models import Scan, Vulnerability, RemediationPlan
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _build_remediation_plan_from_analyses(
    analyzed_vulns: List[Dict[str, Any]],
    scan: Scan,
) -> Dict[str, Any]:
    """
    Construit un plan de remédiation structuré en phases à partir des analyses.
    """
    # Séparer par sévérité
    critical = [v for v in analyzed_vulns if v.get("severity") == "CRITICAL"]
    high = [v for v in analyzed_vulns if v.get("severity") == "HIGH"]
    medium = [v for v in analyzed_vulns if v.get("severity") == "MEDIUM"]
    low = [v for v in analyzed_vulns if v.get("severity") in ("LOW", "INFO")]

    step_counter = 1
    phases = []

    def _make_step(vuln: Dict[str, Any], step_num: int) -> Dict[str, Any]:
        """Construit une étape à partir d'une analyse de vulnérabilité."""
        actions = vuln.get("recommended_actions") or []
        command = actions[0] if actions else f"# Remédiation manuelle requise pour {vuln.get('cve_id', 'vuln')}"
        rollback = vuln.get("rollback_script") or "# Rollback manuel requis"
        return {
            "step_number": step_num,
            "vulnerability_id": vuln.get("vulnerability_id"),
            "cve_id": vuln.get("cve_id"),
            "severity": vuln.get("severity"),
            "title": vuln.get("name") or vuln.get("title", ""),
            "action": vuln.get("ai_explanation") or f"Corriger {vuln.get('cve_id', 'la vulnérabilité')}",
            "command": command,
            "risk": vuln.get("impact_analysis") or "Impact potentiel inconnu",
            "duration": 3,
            "rollback": rollback,
        }

    if critical:
        steps = []
        for v in critical:
            steps.append(_make_step(v, step_counter))
            step_counter += 1
        phases.append({"phase_number": 1, "name": "Critique (À faire en premier)", "steps": steps})

    if high:
        steps = []
        for v in high:
            steps.append(_make_step(v, step_counter))
            step_counter += 1
        phases.append({"phase_number": 2, "name": "Haute priorité", "steps": steps})

    if medium:
        steps = []
        for v in medium:
            steps.append(_make_step(v, step_counter))
            step_counter += 1
        phases.append({"phase_number": 3, "name": "Priorité moyenne", "steps": steps})

    if low:
        steps = []
        for v in low:
            steps.append(_make_step(v, step_counter))
            step_counter += 1
        phases.append({"phase_number": 4, "name": "Faible priorité", "steps": steps})

    total_steps = step_counter - 1
    priority = "CRITICAL" if critical else ("HIGH" if high else ("MEDIUM" if medium else "LOW"))
    estimated_duration = total_steps * 3  # ~3 min par étape

    return {
        "executive_summary": {
            "priority": priority,
            "total_fixes": total_steps,
            "estimated_duration": estimated_duration,
            "estimated_downtime": max(5, len(critical) * 2),
            "description": (
                f"Votre serveur présente {len(critical)} vulnérabilités critiques "
                f"et {len(high)} haute priorité nécessitant une action immédiate."
                if critical else
                f"Plan de remédiation pour {total_steps} vulnérabilités détectées."
            ),
        },
        "phases": phases,
    }


@celery_app.task(name="analyze_scan_batch", bind=True)
def analyze_scan_batch(self, scan_id: str, plan_id: str) -> Dict[str, Any]:
    """
    Tâche Celery : analyse batch de toutes les vulnérabilités d'un scan.
    """
    db = SessionLocal()
    try:
        scan_uuid = uuid.UUID(scan_id)
        plan_uuid = uuid.UUID(plan_id)

        scan: Scan | None = db.query(Scan).filter(Scan.id == scan_uuid).first()
        plan: RemediationPlan | None = db.query(RemediationPlan).filter(RemediationPlan.id == plan_uuid).first()

        if not scan or not plan:
            logger.error("Scan ou Plan introuvable: scan=%s plan=%s", scan_id, plan_id)
            return {"status": "error"}

        vulns = (
            db.query(Vulnerability)
            .filter(Vulnerability.scan_id == scan.id)
            .all()
        )

        if not vulns:
            logger.warning("Aucune vulnérabilité pour le scan %s", scan_id)
            plan.status = "pending_approval"
            plan.execution_plan = {"phases": [], "executive_summary": {"priority": "LOW", "total_fixes": 0}}
            db.commit()
            return {"status": "completed", "total": 0}

        total = len(vulns)
        logger.info("Analyse batch: %d vulnérabilités pour le scan %s", total, scan_id)

        # Importer le vrai Analyzer
        try:
            from src.core.analyzer import Analyzer
            analyzer = Analyzer()
        except Exception as e:
            logger.error("Impossible d'instancier l'Analyzer: %s", e)
            analyzer = None

        analyzed_vulns = []

        for i, vuln in enumerate(vulns):
            vuln_dict = {
                "vulnerability_id": str(vuln.id),
                "name": vuln.title,
                "severity": vuln.severity,
                "cvss_score": float(vuln.cvss_score) if vuln.cvss_score else None,
                "description": vuln.description or "",
                "service": vuln.service or "",
                "port": vuln.port,
                "cve_id": vuln.cve_id,
            }

            if analyzer:
                try:
                    # Analyse IA via l'Analyzer existant (batch de 1)
                    result = asyncio.run(
                        analyzer.analyze_vulnerabilities_batch(
                            vulnerabilities_data=[vuln_dict],
                            target_system=f"{scan.asset.hostname or scan.asset.ip_address}",
                        )
                    )
                    if result and result.vulnerabilities:
                        v_analysis = result.vulnerabilities[0]
                        analysis_data = v_analysis.to_dict() if hasattr(v_analysis, "to_dict") else dict(v_analysis)
                        vuln.ai_analyzed = True
                        vuln.ai_analysis = analysis_data
                        vuln.ai_priority_score = analysis_data.get("priority_score", 50)
                        vuln_dict.update(analysis_data)
                except Exception as e:
                    logger.warning("Erreur analyse IA vuln %s: %s", vuln.cve_id, e)

            analyzed_vulns.append(vuln_dict)
            db.add(vuln)

            # Mise à jour progression (tous les 5 ou à la fin)
            if (i + 1) % 5 == 0 or i == total - 1:
                db.commit()
                self.update_state(
                    state="PROGRESS",
                    meta={"progress": i + 1, "total": total, "current": vuln.cve_id},
                )

        # Générer le plan de remédiation
        execution_plan = _build_remediation_plan_from_analyses(analyzed_vulns, scan)

        # Mettre à jour le plan
        plan.analysis_result = analyzed_vulns
        plan.execution_plan = execution_plan
        plan.estimated_duration = execution_plan["executive_summary"]["estimated_duration"]
        plan.estimated_downtime = execution_plan["executive_summary"]["estimated_downtime"]
        plan.status = "pending_approval"
        db.add(plan)
        db.commit()

        logger.info("Analyse batch terminée: %d vulnérabilités analysées, plan=%s", total, plan_id)
        return {"status": "completed", "total": total, "plan_id": plan_id}

    except Exception as e:
        logger.error("Erreur lors de l'analyse batch scan=%s: %s", scan_id, e, exc_info=True)
        try:
            if plan:
                plan.status = "pending_approval"
                db.commit()
        except Exception:
            pass
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


__all__ = ["analyze_scan_batch"]
