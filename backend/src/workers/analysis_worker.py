"""
Worker Celery pour l'analyse IA batch de toutes les vulnérabilités d'un scan.

Flow:
1. Récupérer toutes les vulnérabilités du scan
2. Pour chaque vuln :
   a) Analyzer : analyse IA (priorité, impact, actions recommandées)
   b) Generator : génère le VRAI script bash exécutable + rollback
3. Sauvegarder analyse + script dans vulnerability.ai_analysis
4. Assembler le plan de remédiation avec les scripts bash réels
5. Mettre à jour RemediationPlan avec le plan généré
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from src.workers.celery_app import celery_app
from src.database.init_db import SessionLocal
from src.database.models import Scan, Vulnerability, RemediationPlan
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Génération de script bash pour une vulnérabilité
# ──────────────────────────────────────────────────────────────────────────────

async def _generate_script_for_vuln(
    generator,
    vuln_dict: Dict[str, Any],
    target_system: str,
) -> Dict[str, str]:
    """
    Appelle le Generator pour produire un script bash exécutable.
    Retourne {"fix_script": "...", "rollback_script": "...", "risk_level": "..."}
    En cas d'erreur, retourne un fallback avec texte.
    """
    vuln_id = vuln_dict.get("vulnerability_id", "unknown")
    cve_id  = vuln_dict.get("cve_id") or vuln_id

    try:
        result = await generator.generate_fix_script(
            vulnerability_id=vuln_id,
            vulnerability_details={
                "name":             vuln_dict.get("name") or vuln_dict.get("title", ""),
                "severity":         vuln_dict.get("severity", "MEDIUM"),
                "cvss_score":       vuln_dict.get("cvss_score"),
                "description":      vuln_dict.get("description", ""),
                "affected_service": vuln_dict.get("service", ""),
                "port":             vuln_dict.get("port"),
                "cve_id":           cve_id,
                # Enrichissements issus de l'Analyzer (si disponibles)
                "recommended_actions": vuln_dict.get("recommended_actions", []),
                "ai_explanation":   vuln_dict.get("ai_explanation", ""),
            },
            target_system=target_system,
            risk_tolerance="low",
        )

        fix      = result.fix_script or ""
        rollback = result.rollback_script or "# Rollback manuel requis"
        risk     = result.risk_level or "medium"
        duration = result.estimated_execution_time or 3

        logger.info("Script généré pour %s (%d chars)", cve_id, len(fix))
        return {
            "fix_script":      fix,
            "rollback_script": rollback,
            "risk_level":      risk,
            "duration":        duration,
            "script_generated": True,
        }

    except Exception as e:
        logger.warning("Erreur génération script pour %s: %s — fallback texte", cve_id, e)
        # Fallback : utilise la première action recommandée comme commande
        actions = vuln_dict.get("recommended_actions") or []
        fallback_cmd = (
            actions[0]
            if actions
            else f"# Remédiation manuelle requise pour {cve_id}\n# Consulter : https://nvd.nist.gov/vuln/detail/{cve_id}"
        )
        rollback_fallback = vuln_dict.get("rollback_script") or "# Rollback manuel requis"
        return {
            "fix_script":      fallback_cmd,
            "rollback_script": rollback_fallback,
            "risk_level":      "medium",
            "duration":        3,
            "script_generated": False,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Construction du plan de remédiation
# ──────────────────────────────────────────────────────────────────────────────

def _build_remediation_plan_from_analyses(
    analyzed_vulns: List[Dict[str, Any]],
    scan: Scan,
) -> Dict[str, Any]:
    """
    Construit un plan de remédiation structuré en phases.
    Les vulns doivent déjà avoir 'fix_script' et 'rollback_script' injectés.
    """
    critical = [v for v in analyzed_vulns if v.get("severity") == "CRITICAL"]
    high     = [v for v in analyzed_vulns if v.get("severity") == "HIGH"]
    medium   = [v for v in analyzed_vulns if v.get("severity") == "MEDIUM"]
    low      = [v for v in analyzed_vulns if v.get("severity") in ("LOW", "INFO")]

    step_counter = 1
    phases = []

    def _make_step(vuln: Dict[str, Any], step_num: int) -> Dict[str, Any]:
        """
        Construit une étape du plan.
        Priorité : fix_script (bash généré) > recommended_actions > placeholder
        """
        fix_script = vuln.get("fix_script", "").strip()
        rollback   = vuln.get("rollback_script", "# Rollback manuel requis").strip()

        # Si le script bash est vide, fallback sur les actions recommandées
        if not fix_script:
            actions    = vuln.get("recommended_actions") or []
            fix_script = (
                actions[0]
                if actions
                else f"# Remédiation manuelle requise pour {vuln.get('cve_id', 'vuln')}"
            )

        return {
            "step_number":     step_num,
            "vulnerability_id": vuln.get("vulnerability_id"),
            "cve_id":          vuln.get("cve_id"),
            "severity":        vuln.get("severity"),
            "title":           vuln.get("name") or vuln.get("title", ""),
            "action":          vuln.get("ai_explanation") or f"Corriger {vuln.get('cve_id', 'la vulnérabilité')}",
            "command":         fix_script,    # ← vrai script bash exécutable
            "rollback":        rollback,      # ← vrai script rollback
            "risk":            vuln.get("impact_analysis") or vuln.get("risk_level") or "Impact potentiel inconnu",
            "duration":        vuln.get("duration") or 3,
            "script_generated": vuln.get("script_generated", False),
        }

    phase_defs = [
        (1, "Critique (À faire en premier)", critical),
        (2, "Haute priorité",                high),
        (3, "Priorité moyenne",              medium),
        (4, "Faible priorité",               low),
    ]

    for phase_num, phase_name, vuln_list in phase_defs:
        if vuln_list:
            steps = []
            for v in vuln_list:
                steps.append(_make_step(v, step_counter))
                step_counter += 1
            phases.append({"phase_number": phase_num, "name": phase_name, "steps": steps})

    total_steps      = step_counter - 1
    priority         = "CRITICAL" if critical else ("HIGH" if high else ("MEDIUM" if medium else "LOW"))
    estimated_duration = total_steps * 3  # ~3 min par étape
    scripts_count    = sum(1 for v in analyzed_vulns if v.get("script_generated"))

    return {
        "executive_summary": {
            "priority":           priority,
            "total_fixes":        total_steps,
            "estimated_duration": estimated_duration,
            "estimated_downtime": max(5, len(critical) * 2),
            "scripts_generated":  scripts_count,
            "description": (
                f"Votre serveur présente {len(critical)} vulnérabilités critiques "
                f"et {len(high)} haute priorité. "
                f"{scripts_count}/{total_steps} scripts bash générés automatiquement."
                if critical else
                f"Plan de remédiation pour {total_steps} vulnérabilités. "
                f"{scripts_count}/{total_steps} scripts bash générés automatiquement."
            ),
        },
        "phases": phases,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Tâche Celery principale
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="analyze_scan_batch", bind=True)
def analyze_scan_batch(self, scan_id: str, plan_id: str) -> Dict[str, Any]:
    """
    Tâche Celery : analyse batch + génération de scripts bash pour chaque vuln.
    """
    db = SessionLocal()
    plan: Optional[RemediationPlan] = None

    try:
        scan_uuid = uuid.UUID(scan_id)
        plan_uuid = uuid.UUID(plan_id)

        scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
        plan = db.query(RemediationPlan).filter(RemediationPlan.id == plan_uuid).first()

        if not scan or not plan:
            logger.error("Scan ou Plan introuvable: scan=%s plan=%s", scan_id, plan_id)
            return {"status": "error"}

        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()

        if not vulns:
            logger.warning("Aucune vulnérabilité pour le scan %s", scan_id)
            plan.status = "pending_approval"
            plan.execution_plan = {"phases": [], "executive_summary": {"priority": "LOW", "total_fixes": 0}}
            db.commit()
            return {"status": "completed", "total": 0}

        total = len(vulns)
        logger.info("Analyse batch: %d vulnérabilités pour le scan %s", total, scan_id)

        # Récupérer le nom du système cible
        target_system = "ubuntu"
        if scan.asset:
            os_name = getattr(scan.asset, "operating_system", None) or ""
            if "debian" in os_name.lower():
                target_system = "debian"
            elif "centos" in os_name.lower() or "rhel" in os_name.lower():
                target_system = "centos"
            elif "windows" in os_name.lower():
                target_system = "windows"

        # Instancier Analyzer et Generator
        analyzer = None
        generator = None

        try:
            from src.core.analyzer import Analyzer
            analyzer = Analyzer()
            logger.info("Analyzer initialisé")
        except Exception as e:
            logger.error("Impossible d'instancier l'Analyzer: %s", e)

        try:
            from src.core.generator import Generator
            generator = Generator()
            logger.info("Generator initialisé")
        except Exception as e:
            logger.error("Impossible d'instancier le Generator: %s", e)

        analyzed_vulns = []

        for i, vuln in enumerate(vulns):
            vuln_dict = {
                "vulnerability_id": str(vuln.id),
                "name":             vuln.title,
                "severity":         vuln.severity,
                "cvss_score":       float(vuln.cvss_score) if vuln.cvss_score else None,
                "description":      vuln.description or "",
                "service":          vuln.service or "",
                "port":             vuln.port,
                "cve_id":           vuln.cve_id,
            }

            # ── Étape 1 : Analyse IA (Analyzer) ──────────────────────────────
            if analyzer:
                try:
                    result = asyncio.run(
                        analyzer.analyze_vulnerabilities_batch(
                            vulnerabilities_data=[vuln_dict],
                            target_system=str(
                                getattr(scan.asset, "hostname", None)
                                or getattr(scan.asset, "ip_address", "")
                            ),
                        )
                    )
                    if result and result.vulnerabilities:
                        v_analysis = result.vulnerabilities[0]
                        analysis_data = (
                            v_analysis.to_dict() if hasattr(v_analysis, "to_dict") else dict(v_analysis)
                        )
                        vuln.ai_analyzed = True
                        vuln.ai_analysis = analysis_data
                        vuln.ai_priority_score = analysis_data.get("priority_score", 50)
                        vuln_dict.update(analysis_data)
                except Exception as e:
                    logger.warning("Erreur Analyzer pour %s: %s", vuln.cve_id, e)

            # ── Étape 2 : Génération script bash (Generator) ──────────────────
            if generator:
                script_data = asyncio.run(
                    _generate_script_for_vuln(generator, vuln_dict, target_system)
                )
                vuln_dict.update(script_data)

                # Stocker le script dans l'analyse IA de la vuln
                if vuln.ai_analysis:
                    vuln.ai_analysis = {**(vuln.ai_analysis or {}), **script_data}
                else:
                    vuln.ai_analysis = script_data
            else:
                # Pas de Generator : fallback texte
                actions = vuln_dict.get("recommended_actions") or []
                vuln_dict["fix_script"] = (
                    actions[0]
                    if actions
                    else f"# Remédiation manuelle requise pour {vuln.cve_id or vuln.id}"
                )
                vuln_dict["rollback_script"] = "# Rollback manuel requis"
                vuln_dict["script_generated"] = False

            analyzed_vulns.append(vuln_dict)
            db.add(vuln)

            # Commit + progression tous les 5 ou à la fin
            if (i + 1) % 5 == 0 or i == total - 1:
                db.commit()
                self.update_state(
                    state="PROGRESS",
                    meta={"progress": i + 1, "total": total, "current": vuln.cve_id},
                )

            logger.info(
                "[%d/%d] %s — analyse: %s, script: %s",
                i + 1, total,
                vuln.cve_id or str(vuln.id),
                "✓" if vuln.ai_analyzed else "✗",
                "✓" if vuln_dict.get("script_generated") else "✗",
            )

        # ── Assembler le plan de remédiation ──────────────────────────────────
        execution_plan = _build_remediation_plan_from_analyses(analyzed_vulns, scan)

        scripts_generated = execution_plan["executive_summary"].get("scripts_generated", 0)
        logger.info(
            "Plan assemblé : %d étapes, %d/%d scripts bash générés",
            execution_plan["executive_summary"]["total_fixes"],
            scripts_generated,
            total,
        )

        plan.analysis_result  = analyzed_vulns
        plan.execution_plan   = execution_plan
        plan.estimated_duration = execution_plan["executive_summary"]["estimated_duration"]
        plan.estimated_downtime = execution_plan["executive_summary"]["estimated_downtime"]
        plan.status = "pending_approval"
        db.add(plan)
        db.commit()

        logger.info("Analyse batch terminée : %d vulns analysées, plan=%s", total, plan_id)
        return {
            "status":           "completed",
            "total":            total,
            "plan_id":          plan_id,
            "scripts_generated": scripts_generated,
        }

    except Exception as e:
        logger.error("Erreur analyse batch scan=%s: %s", scan_id, e, exc_info=True)
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
