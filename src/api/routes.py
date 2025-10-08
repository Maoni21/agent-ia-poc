"""
Routes API pour l'Agent IA de Cybersécurité

Ce module définit tous les endpoints de l'API REST pour interagir
avec l'agent IA de cybersécurité.
"""

import asyncio
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse, StreamingResponse
import json

from src.database.database import Database
from src.core.supervisor import Supervisor, WorkflowType  # ← Ajouter WorkflowType
from src.utils.logger import setup_logger
from .dependencies import get_database, get_supervisor, get_current_user
from .schemas import (
    ScanRequest,
    ScanResponse,
    AnalysisRequest,
    AnalysisResponse,
    ScriptGenerationRequest,
    ScriptResponse,
    VulnerabilityResponse,
    ReportRequest,
    ReportResponse,
    ScanStatus,
    VulnerabilityModel,
    ScriptModel,
)
from . import APIErrorCodes, ERROR_MESSAGES
from pathlib import Path


# Configuration du logging
logger = setup_logger(__name__)

# Création du router principal
router = APIRouter(prefix="/api/v1")

# Stockage temporaire des tâches en cours (en production, utiliser Redis)
active_tasks: Dict[str, Dict[str, Any]] = {}


# === ROUTES DE SCAN ===

@router.post("/scan", response_model=ScanResponse, tags=["scans"])
async def start_scan(
        scan_request: ScanRequest,
        background_tasks: BackgroundTasks,
        supervisor: Supervisor = Depends(get_supervisor),
        db: Database = Depends(get_database),
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Démarrer un nouveau scan de vulnérabilités

    Args:
        scan_request: Paramètres du scan
        background_tasks: Tâches en arrière-plan
        supervisor: Instance du superviseur
        db: Instance de base de données
        current_user: Utilisateur authentifié

    Returns:
        ScanResponse: Informations sur le scan démarré
    """
    try:
        # Générer un ID unique pour le scan
        scan_id = str(uuid.uuid4())

        # Vérifier si une cible est déjà en cours de scan
        if any(task.get("target") == scan_request.target for task in active_tasks.values()):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": APIErrorCodes.SCAN_ALREADY_RUNNING,
                    "message": ERROR_MESSAGES[APIErrorCodes.SCAN_ALREADY_RUNNING]
                }
            )

        # Enregistrer le scan dans la base de données
        scan_data = {
            "scan_id": scan_id,
            "target": scan_request.target,
            "scan_type": scan_request.scan_type,
            "status": "pending",
            "created_by": current_user.get("user_id"),
            "created_at": datetime.utcnow().isoformat(),
            "parameters": scan_request.dict()
        }

        # TODO: Sauvegarder dans la base de données
        # db.save_scan(scan_data)

        # Ajouter à la liste des tâches actives
        active_tasks[scan_id] = {
            "scan_id": scan_id,
            "target": scan_request.target,
            "status": "pending",
            "progress": 0,
            "started_at": datetime.utcnow().isoformat(),
            "user_id": current_user.get("user_id")
        }

        # Lancer le scan en arrière-plan
        background_tasks.add_task(
            run_scan_task,
            scan_id,
            scan_request,
            supervisor
        )

        logger.info(f"Scan démarré: {scan_id} pour {scan_request.target}")

        return ScanResponse(
            scan_id=scan_id,
            target=scan_request.target,
            status=ScanStatus.PENDING,
            message="Scan démarré avec succès",
            started_at=datetime.utcnow().isoformat()
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors du démarrage du scan: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "code": APIErrorCodes.SCAN_FAILED,
                "message": f"Erreur lors du démarrage: {str(e)}"
            }
        )


@router.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """
    Récupère les résultats d'un scan

    Args:
        scan_id: ID du scan

    Returns:
        Résultats du scan
    """
    try:
        # 1. Vérifier dans active_tasks
        if scan_id in active_tasks:
            task_data = active_tasks[scan_id]

            if task_data["status"] == "running":
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "status": "running",
                    "progress": task_data.get("progress", 0),
                    "message": "Scan en cours..."
                }

            elif task_data["status"] == "completed":
                # Récupérer les résultats depuis les fichiers workflow
                workflow_id = task_data.get("workflow_id")
                if workflow_id:
                    results_dir = Path("data/workflow_results")
                    result_file = results_dir / f"{workflow_id}.json"

                    if result_file.exists():
                        with open(result_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)

                        return {
                            "success": True,
                            "scan_id": scan_id,
                            "status": "completed",
                            "results": workflow_data
                        }

                # Fallback: retourner les résultats depuis active_tasks
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "status": "completed",
                    "results": task_data.get("results", {})
                }

            elif task_data["status"] == "failed":
                raise HTTPException(
                    status_code=500,
                    detail=f"Scan échoué: {task_data.get('error', 'Erreur inconnue')}"
                )

        # 2. Vérifier dans les fichiers workflow
        results_dir = Path("data/workflow_results")
        if results_dir.exists():
            # Chercher un fichier contenant le scan_id
            for result_file in results_dir.glob("*.json"):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)

                    # Vérifier si c'est le bon scan
                    if workflow_data.get("scan_result", {}).get("scan_id") == scan_id:
                        return {
                            "success": True,
                            "scan_id": scan_id,
                            "status": "completed",
                            "results": workflow_data
                        }
                except Exception as e:
                    logger.warning(f"Erreur lecture {result_file}: {e}")
                    continue

        # 3. Scan non trouvé
        raise HTTPException(
            status_code=404,
            detail="Scan non trouvé ou résultats non disponibles"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur récupération résultats: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur interne: {str(e)}"
        )

@router.get("/scan/{scan_id}/results", response_model=Dict[str, Any], tags=["scans"])
async def get_scan_results(
        scan_id: str,
        current_user: Dict[str, Any] = Depends(get_current_user),
        db: Database = Depends(get_database)
):
    """
    Récupérer les résultats d'un scan terminé

    Args:
        scan_id: ID du scan
        current_user: Utilisateur authentifié
        db: Instance de base de données

    Returns:
        Dict: Résultats détaillés du scan
    """
    if scan_id not in active_tasks:
        raise HTTPException(
            status_code=404,
            detail={
                "code": APIErrorCodes.SCAN_NOT_FOUND,
                "message": ERROR_MESSAGES[APIErrorCodes.SCAN_NOT_FOUND]
            }
        )

    task = active_tasks[scan_id]

    if task.get("status") != "completed":
        raise HTTPException(
            status_code=409,
            detail="Scan non terminé"
        )

    # Récupérer les résultats
    results = task.get("results")

    # Vérifier que les résultats existent
    if results is None:
        raise HTTPException(
            status_code=404,
            detail="Scan terminé mais résultats non disponibles"
        )

    return {
        "scan_id": scan_id,
        "target": task.get("target"),
        "completed_at": task.get("completed_at"),
        "summary": results.get("summary", {}),
        "vulnerabilities": results.get("vulnerabilities", []),
        "services": results.get("services", []),
        "open_ports": results.get("open_ports", []),
    }

@router.get("/scans", response_model=List[Dict[str, Any]], tags=["scans"])
async def list_scans(
        limit: int = Query(10, description="Nombre de scans à retourner"),
        offset: int = Query(0, description="Décalage pour la pagination"),
        status: Optional[str] = Query(None, description="Filtrer par statut"),
        current_user: Dict[str, Any] = Depends(get_current_user),
        db: Database = Depends(get_database)
):
    """
    Lister les scans de l'utilisateur

    Args:
        limit: Nombre de résultats
        offset: Décalage pour pagination
        status: Filtrer par statut
        current_user: Utilisateur authentifié
        db: Instance de base de données

    Returns:
        List: Liste des scans avec métadonnées
    """
    # TODO: Récupérer depuis la base de données avec pagination
    user_scans = []

    for task_id, task in active_tasks.items():
        if task.get("user_id") == current_user.get("user_id"):
            if status is None or task.get("status") == status:
                user_scans.append({
                    "scan_id": task_id,
                    "target": task.get("target"),
                    "status": task.get("status"),
                    "started_at": task.get("started_at"),
                    "completed_at": task.get("completed_at"),
                    "vulnerability_count": len(task.get("results", {}).get("vulnerabilities", []))
                })

    # Pagination basique
    return user_scans[offset:offset + limit]


@router.delete("/scan/{scan_id}", tags=["scans"])
async def cancel_scan(
        scan_id: str,
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Annuler un scan en cours

    Args:
        scan_id: ID du scan
        current_user: Utilisateur authentifié

    Returns:
        Dict: Confirmation d'annulation
    """
    if scan_id not in active_tasks:
        raise HTTPException(
            status_code=404,
            detail={
                "code": APIErrorCodes.SCAN_NOT_FOUND,
                "message": ERROR_MESSAGES[APIErrorCodes.SCAN_NOT_FOUND]
            }
        )

    task = active_tasks[scan_id]

    # Vérifier que l'utilisateur peut annuler ce scan
    if task.get("user_id") != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Permission refusée")

    if task.get("status") in ["completed", "failed", "cancelled"]:
        raise HTTPException(status_code=409, detail="Scan déjà terminé")

    # Marquer comme annulé
    active_tasks[scan_id]["status"] = "cancelled"
    active_tasks[scan_id]["completed_at"] = datetime.utcnow().isoformat()

    logger.info(f"Scan annulé: {scan_id}")

    return {
        "message": "Scan annulé avec succès",
        "scan_id": scan_id
    }


# === ROUTES D'ANALYSE ===

@router.post("/analyze", response_model=AnalysisResponse, tags=["analysis"])
async def analyze_vulnerabilities(
        analysis_request: AnalysisRequest,
        supervisor: Supervisor = Depends(get_supervisor),
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Analyser des vulnérabilités avec l'IA

    Args:
        analysis_request: Données à analyser
        supervisor: Instance du superviseur
        current_user: Utilisateur authentifié

    Returns:
        AnalysisResponse: Résultats d'analyse IA
    """
    try:
        # Exécuter l'analyse IA
        analysis_result = await supervisor.analyze_vulnerabilities(
            analysis_request.vulnerabilities_data
        )

        logger.info(f"Analyse terminée pour {len(analysis_request.vulnerabilities_data)} vulnérabilités")

        return AnalysisResponse(
            analysis_id=str(uuid.uuid4()),
            summary=analysis_result.get("analysis_summary", {}),
            vulnerabilities=analysis_result.get("vulnerabilities", []),
            remediation_plan=analysis_result.get("remediation_plan", {}),
            analyzed_at=datetime.utcnow().isoformat()
        )

    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "code": APIErrorCodes.ANALYSIS_FAILED,
                "message": f"Erreur d'analyse: {str(e)}"
            }
        )


@router.get("/vulnerability/{vuln_id}", response_model=VulnerabilityResponse, tags=["analysis"])
async def get_vulnerability_details(
        vuln_id: str,
        current_user: Dict[str, Any] = Depends(get_current_user),
        db: Database = Depends(get_database)
):
    """
    Récupérer les détails d'une vulnérabilité

    Args:
        vuln_id: ID de la vulnérabilité
        current_user: Utilisateur authentifié
        db: Instance de base de données

    Returns:
        VulnerabilityResponse: Détails de la vulnérabilité
    """
    # TODO: Récupérer depuis la base de données
    vulnerability_data = {
        "id": vuln_id,
        "name": "Example Vulnerability",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "Description de la vulnérabilité",
        "affected_service": "Apache HTTP Server",
        "remediation": "Mettre à jour vers la version 2.4.59"
    }

    return VulnerabilityResponse(**vulnerability_data)


# === ROUTES DE GÉNÉRATION DE SCRIPTS ===

@router.post("/script/generate", response_model=ScriptResponse, tags=["scripts"])
async def generate_fix_script(
        script_request: ScriptGenerationRequest,
        supervisor: Supervisor = Depends(get_supervisor),
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Générer un script de correction pour une vulnérabilité

    Args:
        script_request: Paramètres de génération
        supervisor: Instance du superviseur
        current_user: Utilisateur authentifié

    Returns:
        ScriptResponse: Script généré avec métadonnées
    """
    try:
        # Générer le script via le superviseur
        script_result = await supervisor.generate_fix_script(
            vulnerability_id=script_request.vulnerability_id,
            target_system=script_request.target_system
        )

        script_id = str(uuid.uuid4())

        logger.info(f"Script généré: {script_id} pour vulnérabilité {script_request.vulnerability_id}")

        return ScriptResponse(
            script_id=script_id,
            vulnerability_id=script_request.vulnerability_id,
            script_content=script_result.get("main_script", ""),
            rollback_script=script_result.get("rollback_script", ""),
            validation_status="pending",
            risk_level=script_result.get("script_info", {}).get("risk_level", "MEDIUM"),
            generated_at=datetime.utcnow().isoformat()
        )

    except Exception as e:
        logger.error(f"Erreur lors de la génération du script: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "code": APIErrorCodes.SCRIPT_GENERATION_FAILED,
                "message": f"Erreur de génération: {str(e)}"
            }
        )


@router.post("/script/validate", tags=["scripts"])
async def validate_script(
        script_content: str,
        supervisor: Supervisor = Depends(get_supervisor),
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Valider un script avant exécution

    Args:
        script_content: Contenu du script à valider
        supervisor: Instance du superviseur
        current_user: Utilisateur authentifié

    Returns:
        Dict: Résultat de validation
    """
    try:
        # Valider le script via le superviseur
        validation_result = await supervisor.validate_script(script_content)

        return {
            "validation_id": str(uuid.uuid4()),
            "is_safe": validation_result.get("security_assessment", {}).get("execution_recommendation") == "APPROVE",
            "risk_level": validation_result.get("security_assessment", {}).get("overall_risk", "UNKNOWN"),
            "identified_risks": validation_result.get("identified_risks", []),
            "improvements": validation_result.get("improvements", []),
            "validated_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Erreur lors de la validation du script: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "code": APIErrorCodes.SCRIPT_VALIDATION_FAILED,
                "message": f"Erreur de validation: {str(e)}"
            }
        )


# === ROUTES DE RAPPORTS ===

@router.post("/report/generate", response_model=ReportResponse, tags=["reports"])
async def generate_report(
        report_request: ReportRequest,
        background_tasks: BackgroundTasks,
        supervisor: Supervisor = Depends(get_supervisor),
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Générer un rapport d'analyse

    Args:
        report_request: Paramètres du rapport
        background_tasks: Tâches en arrière-plan
        supervisor: Instance du superviseur
        current_user: Utilisateur authentifié

    Returns:
        ReportResponse: Informations sur le rapport généré
    """
    try:
        report_id = str(uuid.uuid4())

        # Lancer la génération en arrière-plan
        background_tasks.add_task(
            generate_report_task,
            report_id,
            report_request,
            supervisor
        )

        return ReportResponse(
            report_id=report_id,
            report_type=report_request.report_type,
            status="generating",
            generated_at=datetime.utcnow().isoformat()
        )

    except Exception as e:
        logger.error(f"Erreur lors de la génération du rapport: {e}")
        raise HTTPException(
            status_code=500,
            detail={
                "code": APIErrorCodes.REPORT_GENERATION_FAILED,
                "message": f"Erreur de génération: {str(e)}"
            }
        )


@router.get("/report/{report_id}/download", tags=["reports"])
async def download_report(
        report_id: str,
        current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Télécharger un rapport généré

    Args:
        report_id: ID du rapport
        current_user: Utilisateur authentifié

    Returns:
        FileResponse: Fichier de rapport
    """
    # TODO: Vérifier que le rapport existe et appartient à l'utilisateur
    report_path = f"data/reports/report_{report_id}.pdf"

    # TODO: Vérifier que le fichier existe
    return FileResponse(
        path=report_path,
        filename=f"security_report_{report_id}.pdf",
        media_type="application/pdf"
    )


# === TÂCHES EN ARRIÈRE-PLAN ===

async def run_scan_task(
        scan_id: str,
        scan_request: ScanRequest,
        supervisor: Supervisor
):
    """Exécuter un scan en arrière-plan"""
    try:
        active_tasks[scan_id]["status"] = "running"
        active_tasks[scan_id]["progress"] = 10

        logger.info(f"Démarrage du scan {scan_id}")

        # Lancer le workflow via le superviseur
        workflow_id = await supervisor.start_workflow(
            WorkflowType.SCAN_ONLY,
            target=scan_request.target,
            parameters={"scan_type": scan_request.scan_type}
        )

        # ✅ IMPORTANT: Stocker le workflow_id
        active_tasks[scan_id]["workflow_id"] = workflow_id

        # Attendre la fin avec timeout de 1h (3600 secondes)
        scan_results = await supervisor.wait_for_workflow(workflow_id, timeout=3600)

        # Marquer comme terminé
        active_tasks[scan_id].update({
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.utcnow().isoformat(),
            "workflow_id": workflow_id,  # Garder le workflow_id
            "results": scan_results.to_dict() if hasattr(scan_results, 'to_dict') else scan_results
        })

        logger.info(f"Scan terminé: {scan_id}")

    except Exception as e:
        logger.error(f"Erreur dans le scan {scan_id}: {e}")
        active_tasks[scan_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow().isoformat(),
            "error": str(e)
        })

def update_scan_progress(scan_id: str, progress: int):
    """Mettre à jour la progression d'un scan"""
    if scan_id in active_tasks:
        active_tasks[scan_id]["progress"] = progress


async def generate_report_task(
        report_id: str,
        report_request: ReportRequest,
        supervisor: Supervisor
):
    """
    Générer un rapport en arrière-plan

    Args:
        report_id: ID du rapport
        report_request: Paramètres du rapport
        supervisor: Instance du superviseur
    """
    try:
        # Générer le rapport via le superviseur
        report_result = await supervisor.generate_report(
            report_type=report_request.report_type,
            scan_id=report_request.scan_id,
            format=report_request.format
        )

        logger.info(f"Rapport généré: {report_id}")

    except Exception as e:
        logger.error(f"Erreur génération rapport {report_id}: {e}")