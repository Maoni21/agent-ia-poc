"""
Endpoints API v2 pour le dashboard HTML historique (scan temps réel, IA, scripts, PDF).

Ce module est une adaptation de `src/web/scan_api.py` sous forme de `APIRouter`
intégré dans l'application FastAPI principale du backend.
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks

from config import get_config
from src.core.supervisor import Supervisor, WorkflowType
from src.utils.logger import setup_logger

from .schemas import (
    AnalysisRequest,
    ScriptGenerationRequest,
)


logger = setup_logger(__name__)

router = APIRouter(prefix="/api/v2", tags=["v2-dashboard"])

# Configuration des chemins de workflows (identique à scan_api.py)
BASE_DIR = Path(__file__).parent.parent.parent  # /backend/src/..
DATA_DIR = BASE_DIR / "data"
WORKFLOWS_DIR = DATA_DIR / "workflow_results"

# Ancien emplacement (pour compat)
ALT_WORKFLOWS_DIR = BASE_DIR / "src" / "web" / "data" / "workflow_results"

# Instance globale du superviseur (partagée pour les endpoints v2)
supervisor_instance: Optional[Supervisor] = None

# Stockage des scans actifs (en mémoire)
active_scans: Dict[str, Dict[str, Any]] = {}

# WebSockets actifs par scan
active_websockets: Dict[str, List[WebSocket]] = {}


def _get_workflow_search_dirs() -> List[Path]:
    """Retourne la liste des répertoires où chercher les fichiers workflow."""
    search_dirs: List[Path] = []
    if WORKFLOWS_DIR.exists():
        search_dirs.append(WORKFLOWS_DIR)
    if ALT_WORKFLOWS_DIR.exists():
        search_dirs.append(ALT_WORKFLOWS_DIR)
    return search_dirs


def find_vulnerabilities_by_ids(vulnerability_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Recherche les vulnérabilités correspondantes aux IDs fournis
    dans les fichiers de résultats de workflow.
    """
    if not vulnerability_ids:
        return []

    remaining = set(vulnerability_ids)
    selected: List[Dict[str, Any]] = []

    search_dirs = _get_workflow_search_dirs()

    for workflows_dir in search_dirs:
        for workflow_file in workflows_dir.glob("*.json"):
            try:
                with open(workflow_file, "r", encoding="utf-8") as f:
                    workflow_data = json.load(f)

                vuln_sources: List[List[Dict[str, Any]]] = []
                analysis_result = workflow_data.get("analysis_result") or {}
                if analysis_result:
                    vuln_sources.append(analysis_result.get("vulnerabilities", []))

                scan_result = workflow_data.get("scan_result") or {}
                if scan_result:
                    vuln_sources.append(scan_result.get("vulnerabilities", []))

                for vuln_list in vuln_sources:
                    for vuln in vuln_list:
                        vuln_dict = vuln if isinstance(vuln, dict) else (
                            vuln.to_dict() if hasattr(vuln, "to_dict") else {}
                        )
                        vid = vuln_dict.get("vulnerability_id")
                        if vid in remaining:
                            selected.append(vuln_dict)
                            remaining.remove(vid)
                            if not remaining:
                                return selected
            except Exception as e:
                logger.warning(f"Erreur lecture workflow {workflow_file}: {e}")
                continue

    if remaining:
        logger.warning(f"Vulnérabilités non trouvées pour IDs: {list(remaining)}")
    return selected


# === ENDPOINTS SCANS ===

@router.post("/scans/launch")
async def launch_scan(request: Dict[str, Any], background_tasks: BackgroundTasks):
    """
    Equivalent v2 : lance un nouveau scan (endpoint utilisé par le dashboard HTML).
    Corps attendu (JSON):
      - target
      - scan_type
      - workflow_type
      - script_type
    """
    from src.core.supervisor import WorkflowType  # import local pour éviter cycles

    try:
        target = (request.get("target") or "").strip()
        if not target:
            raise HTTPException(status_code=400, detail="La cible est requise")

        scan_type = request.get("scan_type", "full")
        workflow_type_str = request.get("workflow_type", "full")
        script_type = request.get("script_type", "bash")

        scan_id = str(uuid.uuid4())

        workflow_type_map = {
            "scan_only": WorkflowType.SCAN_ONLY,
            "scan_and_analyze": WorkflowType.SCAN_AND_ANALYZE,
            "full": WorkflowType.FULL_WORKFLOW,
        }
        workflow_type = workflow_type_map.get(workflow_type_str, WorkflowType.FULL_WORKFLOW)

        active_scans[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "workflow_type": workflow_type_str,
            "status": "pending",
            "progress": 0,
            "current_step": "Initialisation",
            "message": "Préparation du scan...",
            "started_at": datetime.utcnow().isoformat(),
            "workflow_id": None,
            "estimated_time_remaining": 600,
        }

        background_tasks.add_task(
            run_scan_workflow,
            scan_id,
            target,
            scan_type,
            workflow_type,
            script_type,
        )

        logger.info(f"Scan lancé (v2): {scan_id} pour {target}")

        return {
            "success": True,
            "scan_id": scan_id,
            "message": "Scan lancé avec succès",
            "workflow_id": None,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lancement scan v2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def list_scans(limit: int = 50):
    """Liste tous les scans (actifs et terminés) pour le dashboard."""
    try:
        scans_list: List[Dict[str, Any]] = []

        # Scans actifs (en mémoire)
        for scan_id, scan_data in active_scans.items():
            scans_list.append(
                {
                    "scan_id": scan_id,
                    "target": scan_data.get("target", "N/A"),
                    "scan_type": scan_data.get("scan_type", "unknown"),
                    "status": scan_data.get("status", "unknown"),
                    "progress": scan_data.get("progress", 0),
                    "current_step": scan_data.get("current_step", "N/A"),
                    "started_at": scan_data.get("started_at"),
                    "vulnerabilities_found": scan_data.get("vulnerabilities_found", 0),
                    "workflow_id": scan_data.get("workflow_id"),
                }
            )

        # Scans terminés depuis les fichiers workflow
        search_dirs = _get_workflow_search_dirs()
        for workflows_dir in search_dirs:
            for workflow_file in workflows_dir.glob("*.json"):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        workflow_data = json.load(f)
                        workflow_id = workflow_file.stem

                    found_in_active = any(
                        scan_data.get("workflow_id") == workflow_id
                        for scan_data in active_scans.values()
                    )
                    if found_in_active:
                        continue

                    scan_result = workflow_data.get("scan_result", {})
                    analysis_result = workflow_data.get("analysis_result", {})

                    vulnerabilities_count = 0
                    if analysis_result:
                        vulnerabilities_count = len(
                            analysis_result.get("vulnerabilities", [])
                        )
                    elif scan_result:
                        vulnerabilities_count = len(
                            scan_result.get("vulnerabilities", [])
                        )

                    scans_list.append(
                        {
                            "scan_id": workflow_id,
                            "target": workflow_data.get("target", "N/A"),
                            "scan_type": workflow_data.get(
                                "workflow_type",
                                workflow_data.get("scan_type", "unknown"),
                            ),
                            "workflow_type": workflow_data.get(
                                "workflow_type", "unknown"
                            ),
                            "status": "completed",
                            "progress": 100,
                            "current_step": "Terminé",
                            "started_at": workflow_data.get(
                                "started_at", workflow_data.get("created_at")
                            ),
                            "completed_at": workflow_data.get("completed_at"),
                            "vulnerabilities_found": vulnerabilities_count,
                            "workflow_id": workflow_id,
                        }
                    )
                except Exception as e:
                    logger.warning(f"Erreur lecture workflow {workflow_file}: {e}")
                    continue

        scans_list.sort(key=lambda x: x.get("started_at", ""), reverse=True)

        return {
            "scans": scans_list[:limit],
            "count": len(scans_list),
            "active_count": len(active_scans),
        }
    except Exception as e:
        logger.error(f"Erreur liste scans v2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Statut d'un scan (utilisé par le dashboard)."""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    return active_scans[scan_id]


@router.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Résultats d'un scan terminé (lecture des fichiers workflow)."""
    # Essayer de retrouver le workflow correspondant
    search_dirs = _get_workflow_search_dirs()
    for workflows_dir in search_dirs:
        workflow_file = workflows_dir / f"{scan_id}.json"
        if workflow_file.exists():
            with open(workflow_file, "r", encoding="utf-8") as f:
                return json.load(f)

    raise HTTPException(status_code=404, detail="Résultats non trouvés")


@router.get("/scans/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """Génère et renvoie un PDF (proxy vers la logique existante)."""
    from fastapi.responses import Response

    # On réutilise la fonction generate_pdf_report de scan_api.py via import direct
    from src.web.scan_api import generate_pdf_report as legacy_generate_pdf_report

    # Chercher un workflow_id correspondant au scan_id (le dashboard utilise souvent workflow_id comme scan_id)
    search_dirs = _get_workflow_search_dirs()
    workflow_id = scan_id
    found = False
    for workflows_dir in search_dirs:
        wf_file = workflows_dir / f"{scan_id}.json"
        if wf_file.exists():
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail="Workflow non trouvé pour ce scan")

    pdf_bytes = await legacy_generate_pdf_report(scan_id, workflow_id)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=rapport_{scan_id}.pdf"
        },
    )


# === ENDPOINTS IA (analyse & scripts) ===

@router.post("/ai/analyze")
async def analyze_selected_vulnerabilities(request: AnalysisRequest):
    """Proxy compatible dashboard vers l'analyse IA existante."""
    global supervisor_instance

    try:
        if not request.vulnerabilities_data:
            raise HTTPException(
                status_code=400, detail="Aucune vulnérabilité fournie pour l'analyse"
            )

        if supervisor_instance is None:
            config = get_config()
            supervisor_instance = Supervisor(config)
            logger.info("✅ Superviseur initialisé (v2 analyse)")

        analysis_result = await supervisor_instance.analyze_vulnerabilities(
            vulnerabilities_data=request.vulnerabilities_data,
            target_system=request.target_system or "Unknown System",
        )

        return (
            analysis_result.to_dict()
            if hasattr(analysis_result, "to_dict")
            else analysis_result
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur analyse IA v2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ai/generate-scripts")
async def generate_scripts_for_vulnerabilities_v2(request: ScriptGenerationRequest):
    """Proxy compatible dashboard pour génération de scripts."""
    global supervisor_instance

    try:
        if not request.vulnerability_id:
            raise HTTPException(
                status_code=400, detail="Aucune vulnérabilité fournie"
            )

        if supervisor_instance is None:
            config = get_config()
            supervisor_instance = Supervisor(config)
            logger.info("✅ Superviseur initialisé (v2 scripts)")

        # Ici on génère un seul script pour une vulnérabilité donnée
        result = await supervisor_instance.generate_fix_script(
            vulnerability_id=request.vulnerability_id,
            target_system=request.target_system or "ubuntu",
        )

        return result.to_dict() if hasattr(result, "to_dict") else result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur génération scripts v2: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# === WEBSOCKET PROGRESSION ===

ws_router = APIRouter()


@ws_router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_progress(websocket: WebSocket, scan_id: str):
    """WebSocket pour la progression temps réel (utilisé par le dashboard)."""
    await websocket.accept()

    if scan_id not in active_websockets:
        active_websockets[scan_id] = []
    active_websockets[scan_id].append(websocket)

    logger.info(f"WebSocket connecté pour scan {scan_id} (v2)")

    try:
        # Envoyer le statut initial si dispo
        if scan_id in active_scans:
            await _send_scan_status(scan_id, active_scans[scan_id])

        while True:
            try:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break
    except Exception as e:
        logger.error(f"Erreur WebSocket {scan_id}: {e}")
    finally:
        if scan_id in active_websockets:
            try:
                active_websockets[scan_id].remove(websocket)
            except ValueError:
                pass
            if not active_websockets[scan_id]:
                del active_websockets[scan_id]
        logger.info(f"WebSocket déconnecté pour scan {scan_id} (v2)")


async def _send_scan_status(scan_id: str, status_data: Dict[str, Any]):
    """Envoie le statut du scan à tous les WebSockets connectés (v2)."""
    if scan_id not in active_websockets:
        return

    message = {
        "type": "progress_update",
        "data": {
            "scan_id": scan_id,
            "status": status_data.get("status"),
            "progress": status_data.get("progress", 0),
            "current_step": status_data.get("current_step", ""),
            "message": status_data.get("message", ""),
            "estimated_time_remaining": status_data.get(
                "estimated_time_remaining", 0
            ),
        },
    }

    disconnected: List[WebSocket] = []
    for websocket in active_websockets.get(scan_id, []):
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Erreur envoi WebSocket (v2): {e}")
            disconnected.append(websocket)

    for ws in disconnected:
        try:
            active_websockets[scan_id].remove(ws)
        except ValueError:
            pass


async def run_scan_workflow(
    scan_id: str,
    target: str,
    scan_type: str,
    workflow_type: WorkflowType,
    script_type: str = "bash",
):
    """Exécute un workflow de scan en arrière-plan (version simplifiée v2)."""
    global supervisor_instance

    try:
        if supervisor_instance is None:
            config = get_config()
            supervisor_instance = Supervisor(config)
            logger.info("✅ Superviseur initialisé (v2 workflow)")

        active_scans[scan_id].update(
            {
                "status": "running",
                "progress": 5,
                "current_step": "Initialisation",
                "message": "Démarrage du scan...",
            }
        )
        await _send_scan_status(scan_id, active_scans[scan_id])

        workflow_id = await supervisor_instance.start_workflow(
            workflow_type=workflow_type,
            target=target,
            parameters={"scan_type": scan_type, "script_type": script_type},
            created_by="dashboard-v2",
        )

        active_scans[scan_id]["workflow_id"] = workflow_id

        # Attendre la fin du workflow
        result = await supervisor_instance.wait_for_workflow(workflow_id, timeout=3600)

        active_scans[scan_id].update(
            {
                "status": "completed",
                "progress": 100,
                "current_step": "Terminé",
                "message": "Scan terminé avec succès",
                "estimated_time_remaining": 0,
                "workflow_id": workflow_id,
                "vulnerabilities_found": getattr(
                    result, "total_vulnerabilities", 0
                )
                if result
                else 0,
            }
        )
        await _send_scan_status(scan_id, active_scans[scan_id])

        logger.info(f"Scan terminé (v2): {scan_id}")

    except Exception as e:
        logger.error(f"Erreur scan {scan_id} (v2): {e}")
        active_scans[scan_id].update(
            {
                "status": "failed",
                "progress": 0,
                "current_step": "Erreur",
                "message": f"Erreur: {str(e)}",
                "estimated_time_remaining": 0,
            }
        )
        await _send_scan_status(scan_id, active_scans[scan_id])

