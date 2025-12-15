"""
API de Scan avec WebSocket pour l'Agent IA de Cybersécurité
Gère le lancement de scans et la progression en temps réel
"""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import sys
import os

# Ajouter le chemin racine au PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config import get_config
from src.core.supervisor import Supervisor, WorkflowType
from src.utils.logger import setup_logger

logger = setup_logger(__name__)

# Configuration
BASE_DIR = Path(__file__).parent.parent.parent  # Remonter à la racine du projet
DATA_DIR = BASE_DIR / "data"
WORKFLOWS_DIR = DATA_DIR / "workflow_results"

# Vérifier aussi dans src/web/data/workflow_results (ancien emplacement)
ALT_WORKFLOWS_DIR = Path(__file__).parent / "data" / "workflow_results"

# Créer l'application FastAPI
app = FastAPI(
    title="CyberSec AI Scan API",
    version="2.0.0",
    description="API pour le lancement de scans avec WebSocket temps réel"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instance globale du superviseur
supervisor_instance: Optional[Supervisor] = None

# Stockage des connexions WebSocket actives
active_websockets: Dict[str, List[WebSocket]] = {}

# Stockage des scans actifs
active_scans: Dict[str, Dict[str, Any]] = {}


# === MODÈLES PYDANTIC ===

class ScanLaunchRequest(BaseModel):
    """Requête de lancement de scan"""
    target: str = Field(..., description="Adresse IP ou domaine à scanner")
    scan_type: str = Field(default="full", description="Type de scan: quick, full, stealth, aggressive")
    workflow_type: str = Field(default="full", description="Type de workflow: scan_only, scan_and_analyze, full")
    script_type: str = Field(default="bash", description="Type de script: bash ou ansible")


class ScanLaunchResponse(BaseModel):
    """Réponse de lancement de scan"""
    success: bool
    scan_id: str
    message: str
    workflow_id: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """Statut d'un scan"""
    scan_id: str
    status: str
    progress: int
    current_step: str
    message: str
    estimated_time_remaining: Optional[int] = None


# === INITIALISATION ===

@app.on_event("startup")
async def startup_event():
    """Initialise le superviseur au démarrage"""
    global supervisor_instance
    try:
        config = get_config()
        supervisor_instance = Supervisor(config)
        logger.info("✅ Superviseur initialisé")
    except Exception as e:
        logger.warning(f"⚠️ Erreur initialisation superviseur: {e}")
        logger.warning("⚠️ Le superviseur sera initialisé lors du premier scan")
        # Ne pas bloquer le démarrage du serveur
        supervisor_instance = None


@app.on_event("shutdown")
async def shutdown_event():
    """Nettoyage à l'arrêt"""
    global supervisor_instance
    if supervisor_instance:
        await supervisor_instance.shutdown()
        logger.info("✅ Superviseur arrêté")


# === ENDPOINTS REST ===

@app.post("/api/v2/scans/launch", response_model=ScanLaunchResponse)
async def launch_scan(request: ScanLaunchRequest, background_tasks: BackgroundTasks):
    """
    Lance un nouveau scan de vulnérabilités
    
    Args:
        request: Paramètres du scan
        background_tasks: Tâches en arrière-plan
        
    Returns:
        ScanLaunchResponse: Informations sur le scan lancé
    """
    try:
        # Valider la cible
        if not request.target:
            raise HTTPException(status_code=400, detail="La cible est requise")
        
        # Générer un ID unique pour le scan
        scan_id = str(uuid.uuid4())
        
        # Mapper le workflow_type
        workflow_type_map = {
            "scan_only": WorkflowType.SCAN_ONLY,
            "scan_and_analyze": WorkflowType.SCAN_AND_ANALYZE,
            "full": WorkflowType.FULL_WORKFLOW
        }
        workflow_type = workflow_type_map.get(request.workflow_type, WorkflowType.FULL_WORKFLOW)
        
        # Initialiser le statut du scan
        active_scans[scan_id] = {
            "scan_id": scan_id,
            "target": request.target,
            "scan_type": request.scan_type,
            "workflow_type": request.workflow_type,
            "status": "pending",
            "progress": 0,
            "current_step": "Initialisation",
            "message": "Préparation du scan...",
            "started_at": datetime.utcnow().isoformat(),
            "workflow_id": None,
            "estimated_time_remaining": 600  # 10 minutes par défaut
        }
        
        # Lancer le scan en arrière-plan
        background_tasks.add_task(
            run_scan_workflow,
            scan_id,
            request.target,
            request.scan_type,
            workflow_type,
            request.script_type
        )
        
        logger.info(f"Scan lancé: {scan_id} pour {request.target}")
        
        return ScanLaunchResponse(
            success=True,
            scan_id=scan_id,
            message="Scan lancé avec succès",
            workflow_id=None
        )
        
    except Exception as e:
        logger.error(f"Erreur lancement scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/scans")
async def list_scans(limit: int = 50):
    """Liste tous les scans (actifs et terminés)"""
    try:
        scans_list = []
        
        # Ajouter les scans actifs
        for scan_id, scan_data in active_scans.items():
            scans_list.append({
                "scan_id": scan_id,
                "target": scan_data.get("target", "N/A"),
                "scan_type": scan_data.get("scan_type", "unknown"),
                "status": scan_data.get("status", "unknown"),
                "progress": scan_data.get("progress", 0),
                "current_step": scan_data.get("current_step", "N/A"),
                "started_at": scan_data.get("started_at"),
                "vulnerabilities_found": scan_data.get("vulnerabilities_found", 0),
                "workflow_id": scan_data.get("workflow_id")
            })
        
        # Ajouter les scans terminés depuis les fichiers workflow (chercher dans les deux emplacements)
        search_dirs = []
        if WORKFLOWS_DIR.exists():
            search_dirs.append(WORKFLOWS_DIR)
        if ALT_WORKFLOWS_DIR.exists():
            search_dirs.append(ALT_WORKFLOWS_DIR)
        
        for workflows_dir in search_dirs:
            for workflow_file in workflows_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        workflow_id = workflow_file.stem
                        
                        # Chercher si ce workflow correspond à un scan actif
                        found_in_active = False
                        for scan_id, scan_data in active_scans.items():
                            if scan_data.get("workflow_id") == workflow_id:
                                found_in_active = True
                                break
                        
                        if not found_in_active:
                            # C'est un scan terminé
                            scan_result = workflow_data.get("scan_result", {})
                            analysis_result = workflow_data.get("analysis_result", {})
                            vulnerabilities_count = len(analysis_result.get("vulnerabilities", [])) if analysis_result else 0
                            
                            # Utiliser le scan_id sauvegardé dans le workflow, sinon le workflow_id
                            saved_scan_id = workflow_data.get("scan_id", workflow_id)
                            
                            scans_list.append({
                                "scan_id": saved_scan_id,  # Utiliser le scan_id original si disponible
                                "target": workflow_data.get("target", "N/A"),
                                "scan_type": workflow_data.get("scan_type", "unknown"),
                                "status": "completed",
                                "progress": 100,
                                "current_step": "Terminé",
                                "started_at": workflow_data.get("started_at", workflow_data.get("created_at")),
                                "completed_at": workflow_data.get("completed_at"),
                                "vulnerabilities_found": vulnerabilities_count,
                                "workflow_id": workflow_id  # Toujours inclure le workflow_id
                            })
                except Exception as e:
                    logger.warning(f"Erreur lecture workflow {workflow_file}: {e}")
                    continue
        
        # Trier par date (plus récent en premier)
        scans_list.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        
        return {
            "scans": scans_list[:limit],
            "count": len(scans_list),
            "active_count": len(active_scans)
        }
    except Exception as e:
        logger.error(f"Erreur liste scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Récupère le statut d'un scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    scan_data = active_scans[scan_id]
    return ScanStatusResponse(**scan_data)


@app.get("/api/v2/scans/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Récupère les résultats d'un scan terminé"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    
    scan_data = active_scans[scan_id]
    
    if scan_data["status"] != "completed":
        raise HTTPException(status_code=409, detail="Scan non terminé")
    
    workflow_id = scan_data.get("workflow_id")
    if workflow_id:
        # Charger depuis le fichier workflow
        workflow_file = WORKFLOWS_DIR / f"{workflow_id}.json"
        if workflow_file.exists():
            with open(workflow_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    
    return {"message": "Résultats non disponibles"}


@app.get("/api/v2/scans/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """Génère et télécharge un rapport PDF"""
    from fastapi.responses import Response
    
    try:
        workflow_id = None
        target_ip = None
        
        # Chercher dans les scans actifs
        if scan_id in active_scans:
            scan_data = active_scans[scan_id]
            workflow_id = scan_data.get("workflow_id")
            target_ip = scan_data.get("target")
        
        # Si pas dans active_scans, chercher dans les fichiers workflow pour trouver le target et workflow_id
        if not target_ip or not workflow_id:
            search_dirs = []
            if WORKFLOWS_DIR.exists():
                search_dirs.append(WORKFLOWS_DIR)
            if ALT_WORKFLOWS_DIR.exists():
                search_dirs.append(ALT_WORKFLOWS_DIR)
            
            for workflows_dir in search_dirs:
                # Essayer avec le scan_id complet comme nom de fichier
                workflow_file = workflows_dir / f"{scan_id}.json"
                if workflow_file.exists():
                    try:
                        with open(workflow_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                            target_ip = workflow_data.get("target")
                            workflow_id = scan_id
                            break
                    except:
                        pass
                
                # Chercher par scan_id sauvegardé dans les workflows
                for wf_file in workflows_dir.glob("*.json"):
                    try:
                        with open(wf_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                            wf_id = workflow_data.get("workflow_id", "")
                            wf_stem = wf_file.stem
                            saved_scan_id = workflow_data.get("scan_id", "")
                            
                            # Si le scan_id correspond au scan_id sauvegardé, workflow_id, ou nom du fichier
                            if saved_scan_id == scan_id or wf_id == scan_id or wf_stem == scan_id:
                                target_ip = workflow_data.get("target")
                                workflow_id = wf_stem
                                logger.info(f"✅ Workflow trouvé par scan_id sauvegardé: {wf_stem} pour scan {scan_id}")
                                break
                    except:
                        continue
                
                if target_ip and workflow_id:
                    break
        
        # Si pas trouvé, chercher dans les fichiers workflow
        if not workflow_id:
            # Chercher dans les deux emplacements possibles
            search_dirs = []
            if WORKFLOWS_DIR.exists():
                search_dirs.append(WORKFLOWS_DIR)
            if ALT_WORKFLOWS_DIR.exists():
                search_dirs.append(ALT_WORKFLOWS_DIR)
            
            for workflows_dir in search_dirs:
                # Essayer avec le scan_id complet
                workflow_file = workflows_dir / f"{scan_id}.json"
                if workflow_file.exists():
                    workflow_id = scan_id
                    logger.info(f"✅ Workflow trouvé directement: {workflow_file}")
                    break
                
                # Chercher dans tous les fichiers workflow par correspondance
                for wf_file in workflows_dir.glob("*.json"):
                    try:
                        with open(wf_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                            wf_id = workflow_data.get("workflow_id", "")
                            wf_stem = wf_file.stem
                            wf_target = workflow_data.get("target", "")
                            
                            # Correspondance par scan_id, workflow_id, ou target
                            scan_prefix = scan_id[:8] if len(scan_id) >= 8 else scan_id
                            
                            # 1. Correspondance exacte workflow_id
                            if wf_id == scan_id or wf_stem == scan_id:
                                workflow_id = wf_stem
                                logger.info(f"✅ Workflow trouvé par ID exact: {wf_stem}")
                                break
                            
                            # 2. Correspondance par préfixe
                            if (wf_id.startswith(scan_prefix) or 
                                scan_id.startswith(wf_id[:8] if len(wf_id) >= 8 else wf_id) or
                                scan_id in wf_stem or
                                wf_stem.startswith(scan_prefix) or
                                scan_prefix in wf_stem):
                                workflow_id = wf_stem
                                logger.info(f"✅ Workflow trouvé par préfixe: {wf_stem} pour scan {scan_id}")
                                break
                            
                            # 3. Correspondance par target IP (si pas encore trouvé)
                            if target_ip and target_ip == wf_target:
                                workflow_id = wf_stem
                                logger.info(f"✅ Workflow trouvé par target IP: {wf_stem} (target: {wf_target})")
                                break
                    except Exception as e:
                        logger.warning(f"Erreur lecture workflow {wf_file}: {e}")
                        continue
                
                if workflow_id:
                    break
            
            # Si toujours pas trouvé et qu'on a un target_ip, chercher le workflow le plus récent pour ce target
            if not workflow_id and target_ip:
                logger.info(f"Recherche du workflow le plus récent pour target {target_ip}")
                most_recent_workflow = None
                most_recent_time = None
                
                for workflows_dir in search_dirs:
                    for wf_file in workflows_dir.glob("*.json"):
                        try:
                            with open(wf_file, 'r', encoding='utf-8') as f:
                                workflow_data = json.load(f)
                                wf_target = workflow_data.get("target", "")
                                if wf_target == target_ip:
                                    completed_at = workflow_data.get("completed_at") or workflow_data.get("started_at")
                                    if completed_at:
                                        if not most_recent_time or completed_at > most_recent_time:
                                            most_recent_time = completed_at
                                            most_recent_workflow = wf_file.stem
                        except:
                            continue
                
                if most_recent_workflow:
                    workflow_id = most_recent_workflow
                    logger.info(f"✅ Workflow le plus récent trouvé pour target {target_ip}: {workflow_id}")
        
        if not workflow_id:
            raise HTTPException(status_code=404, detail="Workflow non trouvé pour ce scan")
        
        # Générer le PDF
        pdf_bytes = await generate_pdf_report(scan_id, workflow_id)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=rapport_{scan_id}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"Erreur génération PDF: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# === WEBSOCKET ===

@app.websocket("/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    """Endpoint WebSocket pour la progression en temps réel"""
    await websocket.accept()
    
    # Ajouter la connexion à la liste
    if scan_id not in active_websockets:
        active_websockets[scan_id] = []
    active_websockets[scan_id].append(websocket)
    
    logger.info(f"WebSocket connecté pour scan {scan_id}")
    
    try:
        # Envoyer le statut initial
        if scan_id in active_scans:
            await send_scan_status(scan_id, active_scans[scan_id])
        
        # Attendre les messages du client (pour ping/pong)
        while True:
            try:
                data = await websocket.receive_text()
                # Ping/Pong pour maintenir la connexion
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break
    except Exception as e:
        logger.error(f"Erreur WebSocket {scan_id}: {e}")
    finally:
        # Retirer la connexion
        if scan_id in active_websockets:
            active_websockets[scan_id].remove(websocket)
            if not active_websockets[scan_id]:
                del active_websockets[scan_id]
        logger.info(f"WebSocket déconnecté pour scan {scan_id}")


async def send_scan_status(scan_id: str, status_data: Dict[str, Any]):
    """Envoie le statut du scan à tous les WebSockets connectés"""
    if scan_id not in active_websockets:
        return
    
    message = {
        "type": "progress_update",
        "data": {
            "scan_id": scan_id,
            "status": status_data["status"],
            "progress": status_data["progress"],
            "current_step": status_data["current_step"],
            "message": status_data["message"],
            "estimated_time_remaining": status_data.get("estimated_time_remaining", 0)
        }
    }
    
    disconnected = []
    for websocket in active_websockets[scan_id]:
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.warning(f"Erreur envoi WebSocket: {e}")
            disconnected.append(websocket)
    
    # Nettoyer les connexions déconnectées
    for ws in disconnected:
        if scan_id in active_websockets:
            active_websockets[scan_id].remove(ws)


# === TÂCHES EN ARRIÈRE-PLAN ===

async def run_scan_workflow(
    scan_id: str,
    target: str,
    scan_type: str,
    workflow_type: WorkflowType,
    script_type: str = "bash"
):
    """Exécute un workflow de scan en arrière-plan"""
    global supervisor_instance
    
    try:
        # Mettre à jour le statut
        active_scans[scan_id].update({
            "status": "running",
            "progress": 5,
            "current_step": "Initialisation",
            "message": "Démarrage du scan..."
        })
        await send_scan_status(scan_id, active_scans[scan_id])
        
        # Lancer le workflow via le superviseur
        workflow_id = await supervisor_instance.start_workflow(
            workflow_type=workflow_type,
            target=target,
            parameters={
                "scan_type": scan_type,
                "script_type": script_type
            },
            created_by="dashboard"
        )
        
        active_scans[scan_id]["workflow_id"] = workflow_id
        # Sauvegarder aussi le scan_id dans le workflow pour référence future
        try:
            workflow_file = WORKFLOWS_DIR / f"{workflow_id}.json"
            if not workflow_file.exists():
                workflow_file = ALT_WORKFLOWS_DIR / f"{workflow_id}.json"
            
            if workflow_file.exists():
                with open(workflow_file, 'r+', encoding='utf-8') as f:
                    workflow_data = json.load(f)
                    workflow_data["scan_id"] = scan_id  # Sauvegarder le scan_id original
                    f.seek(0)
                    json.dump(workflow_data, f, indent=2, ensure_ascii=False)
                    f.truncate()
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder scan_id dans workflow: {e}")
        
        # Mettre à jour la progression pendant l'exécution
        await monitor_workflow_progress(scan_id, workflow_id, workflow_type)
        
        # Attendre la fin du workflow
        result = await supervisor_instance.wait_for_workflow(workflow_id, timeout=3600)
        
        # Vérifier que le workflow a bien été sauvegardé
        workflow_file = WORKFLOWS_DIR / f"{workflow_id}.json"
        if not workflow_file.exists():
            logger.warning(f"⚠️ Fichier workflow {workflow_id}.json non trouvé après completion")
            # Attendre un peu plus pour la sauvegarde
            await asyncio.sleep(2)
        
        # Mettre à jour le statut final
        active_scans[scan_id].update({
            "status": "completed",
            "progress": 100,
            "current_step": "Terminé",
            "message": "Scan terminé avec succès",
            "estimated_time_remaining": 0,
            "workflow_id": workflow_id,  # S'assurer que workflow_id est bien sauvegardé
            "vulnerabilities_found": result.total_vulnerabilities if result else 0
        })
        await send_scan_status(scan_id, active_scans[scan_id])
        
        logger.info(f"Scan terminé: {scan_id}")
        
    except Exception as e:
        logger.error(f"Erreur scan {scan_id}: {e}")
        active_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "current_step": "Erreur",
            "message": f"Erreur: {str(e)}",
            "estimated_time_remaining": 0
        })
        await send_scan_status(scan_id, active_scans[scan_id])


async def monitor_workflow_progress(
    scan_id: str,
    workflow_id: str,
    workflow_type: WorkflowType
):
    """Surveille la progression d'un workflow et met à jour le statut"""
    
    # Étapes selon le type de workflow
    steps = {
        WorkflowType.SCAN_ONLY: [
            ("Initialisation", 5, 10),
            ("Scan Nmap", 10, 90),
            ("Finalisation", 90, 100)
        ],
        WorkflowType.SCAN_AND_ANALYZE: [
            ("Initialisation", 5, 10),
            ("Scan Nmap", 10, 50),
            ("Analyse IA", 50, 90),
            ("Finalisation", 90, 100)
        ],
        WorkflowType.FULL_WORKFLOW: [
            ("Initialisation", 5, 10),
            ("Scan Nmap", 10, 40),
            ("Analyse IA", 40, 70),
            ("Génération Scripts", 70, 95),
            ("Finalisation", 95, 100)
        ]
    }
    
    workflow_steps = steps.get(workflow_type, steps[WorkflowType.FULL_WORKFLOW])
    current_step_index = 0
    
    # Surveiller le workflow jusqu'à ce qu'il soit terminé
    while scan_id in active_scans:
        try:
            # Vérifier le statut du workflow dans le superviseur
            if workflow_id in supervisor_instance.active_workflows:
                workflow_def = supervisor_instance.active_workflows[workflow_id]
                
                # Mettre à jour le statut selon l'état du workflow
                if workflow_def.status.value == "completed":
                    active_scans[scan_id].update({
                        "status": "completed",
                        "progress": 100,
                        "current_step": "Terminé",
                        "message": "Scan terminé avec succès",
                        "estimated_time_remaining": 0
                    })
                    await send_scan_status(scan_id, active_scans[scan_id])
                    break
                elif workflow_def.status.value == "failed":
                    active_scans[scan_id].update({
                        "status": "failed",
                        "progress": 0,
                        "current_step": "Erreur",
                        "message": "Le scan a échoué",
                        "estimated_time_remaining": 0
                    })
                    await send_scan_status(scan_id, active_scans[scan_id])
                    break
            
            # Mettre à jour la progression selon les étapes
            if current_step_index < len(workflow_steps):
                step_name, start_progress, end_progress = workflow_steps[current_step_index]
                
                # Calculer la progression basée sur le temps écoulé
                # (approximation, à améliorer avec de vrais callbacks)
                elapsed_time = (datetime.utcnow() - datetime.fromisoformat(active_scans[scan_id]["started_at"])).total_seconds()
                estimated_duration = 600  # 10 minutes par défaut
                
                # Progression basée sur le temps
                time_progress = min(95, int((elapsed_time / estimated_duration) * 100))
                
                # Progression basée sur les étapes
                step_progress = start_progress + int((end_progress - start_progress) * (current_step_index / len(workflow_steps)))
                
                # Utiliser le maximum des deux
                current_progress = max(time_progress, step_progress)
                
                active_scans[scan_id].update({
                    "current_step": step_name,
                    "progress": min(current_progress, end_progress),
                    "message": f"{step_name} en cours...",
                    "estimated_time_remaining": max(0, int(estimated_duration - elapsed_time))
                })
                
                await send_scan_status(scan_id, active_scans[scan_id])
                
                # Passer à l'étape suivante si on a atteint la fin de l'étape actuelle
                if current_progress >= end_progress:
                    current_step_index += 1
            
            # Attendre avant la prochaine vérification
            await asyncio.sleep(2)
            
        except Exception as e:
            logger.error(f"Erreur monitoring workflow {workflow_id}: {e}")
            await asyncio.sleep(5)  # Attendre plus longtemps en cas d'erreur


# === GÉNÉRATION PDF ===

async def generate_pdf_report(scan_id: str, workflow_id: str) -> bytes:
    """Génère un rapport PDF professionnel"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from io import BytesIO
        
        # Charger les données du workflow (chercher dans les deux emplacements)
        workflow_file = WORKFLOWS_DIR / f"{workflow_id}.json"
        if not workflow_file.exists():
            workflow_file = ALT_WORKFLOWS_DIR / f"{workflow_id}.json"
        
        if not workflow_file.exists():
            raise FileNotFoundError(f"Workflow {workflow_id} non trouvé dans {WORKFLOWS_DIR} ni {ALT_WORKFLOWS_DIR}")
        
        with open(workflow_file, 'r', encoding='utf-8') as f:
            workflow_data = json.load(f)
        
        # Créer le buffer PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.5*inch, bottomMargin=0.5*inch)
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1E40AF'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1E40AF'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Contenu du PDF
        story = []
        
        # Page de garde
        story.append(Spacer(1, 2*inch))
        story.append(Paragraph("RAPPORT DE CYBERSÉCURITÉ", title_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(f"Scan ID: {scan_id}", styles['Normal']))
        story.append(Paragraph(f"Date: {datetime.now().strftime('%d/%m/%Y %H:%M')}", styles['Normal']))
        story.append(PageBreak())
        
        # Résumé exécutif
        story.append(Paragraph("Résumé Exécutif", heading_style))
        
        scan_result = workflow_data.get('scan_result', {})
        analysis_result = workflow_data.get('analysis_result', {})
        
        summary_data = [
            ['Cible scannée', workflow_data.get('target', 'N/A')],
            ['Type de scan', workflow_data.get('workflow_type', 'N/A')],
            ['Date de début', workflow_data.get('started_at', 'N/A')],
            ['Date de fin', workflow_data.get('completed_at', 'N/A')],
            ['Durée totale', f"{workflow_data.get('duration', 0):.1f} secondes"],
            ['Vulnérabilités détectées', workflow_data.get('total_vulnerabilities', 0)],
            ['Vulnérabilités critiques', workflow_data.get('critical_vulnerabilities', 0)],
            ['Scripts générés', workflow_data.get('scripts_generated', 0)]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F3F4F6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Vulnérabilités détectées
        vulnerabilities = []
        if scan_result:
            vulnerabilities = scan_result.get('vulnerabilities', [])
        elif analysis_result:
            vulnerabilities = analysis_result.get('vulnerabilities', [])
        
        if vulnerabilities:
            story.append(Paragraph("Vulnérabilités Détectées", heading_style))
            
            for i, vuln in enumerate(vulnerabilities[:20], 1):  # Limiter à 20 pour le PDF
                severity = vuln.get('severity', 'UNKNOWN')
                bg_color = {
                    'CRITICAL': colors.HexColor('#FEE2E2'),
                    'HIGH': colors.HexColor('#FED7AA'),
                    'MEDIUM': colors.HexColor('#FEF3C7'),
                    'LOW': colors.HexColor('#D1FAE5')
                }.get(severity, colors.lightgrey)
                
                vuln_data = [
                    ['CVE ID', vuln.get('vulnerability_id', 'N/A')],
                    ['Nom', vuln.get('name', 'N/A')],
                    ['Sévérité', f"{severity} (CVSS: {vuln.get('cvss_score', 0)})"],
                    ['Service', vuln.get('affected_service', 'N/A')],
                    ['Description', vuln.get('description', 'N/A')[:200]]
                ]
                
                vuln_table = Table(vuln_data, colWidths=[2*inch, 5*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F3F4F6')),
                    ('BACKGROUND', (1, 0), (1, -1), bg_color),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 0.2*inch))
        
        # Plan de remédiation
        if workflow_data.get('scripts_generated', 0) > 0:
            story.append(PageBreak())
            story.append(Paragraph("Plan de Remédiation", heading_style))
            story.append(Paragraph(
                f"{workflow_data.get('scripts_generated', 0)} scripts de correction ont été générés. "
                "Consultez le dashboard pour les détails complets.",
                styles['Normal']
            ))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} par CyberSec AI",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, alignment=TA_CENTER, textColor=colors.grey)
        ))
        
        # Générer le PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
        
    except ImportError:
        logger.error("ReportLab non installé. Installer avec: pip install reportlab")
        raise HTTPException(status_code=500, detail="ReportLab non installé")
    except Exception as e:
        logger.error(f"Erreur génération PDF: {e}")
        raise


# === POINT D'ENTRÉE ===

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Démarrage de l'API de Scan...")
    print("📡 WebSocket: ws://localhost:8001/ws/scan/{scan_id}")
    print("📖 API Docs: http://localhost:8001/docs")
    
    uvicorn.run(
        "scan_api:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )

