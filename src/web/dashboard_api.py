"""
Dashboard API pour l'Agent IA de Cybersécurité
Backend FastAPI professionnel
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3
import sys
from pathlib import Path
import csv
import io
import uuid
from pydantic import BaseModel
import re
import time

# Ajouter le chemin racine pour les imports
root_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(root_path))

# Import de sync_workflows - fonction définie localement pour éviter les problèmes d'import
def sync_all_workflows(workflows_dir, db_path):
    """Synchronise les workflows vers la DB (fonction simplifiée)"""
    try:
        from src.web.sync_workflows import sync_all_workflows as _sync
        return _sync(workflows_dir, db_path)
    except:
        return 0

app = FastAPI(
    title="CyberSec AI Dashboard API",
    version="2.0.0",
    description="API professionnelle pour le dashboard de gestion des vulnérabilités"
)

# CORS pour le développement
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration des chemins
BASE_DIR = Path(__file__).parent  # src/web
STATIC_DIR = BASE_DIR / "static"
ROOT_DIR = BASE_DIR.parent.parent  # Racine du projet
DATA_DIR = ROOT_DIR / "data"
DB_PATH = DATA_DIR / "database" / "vulnerability_agent.db"
# Dossier principal prévu pour les workflows (racine du projet)
WORKFLOWS_DIR = DATA_DIR / "workflow_results"
# Ancien emplacement (là où le superviseur écrit actuellement quand on lance depuis src/web)
ALT_WORKFLOWS_DIR = BASE_DIR / "data" / "workflow_results"


def get_workflow_dirs():
    """Retourne la liste des répertoires où chercher les résultats de workflows."""
    dirs = []
    if WORKFLOWS_DIR.exists():
        dirs.append(WORKFLOWS_DIR)
    if ALT_WORKFLOWS_DIR.exists():
        dirs.append(ALT_WORKFLOWS_DIR)
    # Si rien n'existe encore, retourner au moins le dossier principal
    return dirs or [WORKFLOWS_DIR]


# ===== HELPER FUNCTIONS =====

def get_db_connection():
    """Connexion à la base de données"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def load_workflow_result(workflow_id: str):
    """Charge un résultat de workflow depuis le JSON"""
    # Chercher dans tous les emplacements possibles
    for wf_dir in get_workflow_dirs():
        result_file = wf_dir / f"{workflow_id}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                return json.load(f)
    return None


def get_supervisor_instance():
    """Crée et retourne une instance du Supervisor"""
    try:
        from config import get_config
        from src.core.supervisor import Supervisor
        config = get_config()
        return Supervisor(config)
    except Exception as e:
        print(f"⚠️ Erreur création Supervisor: {e}")
        raise HTTPException(status_code=500, detail=f"Impossible d'initialiser le Supervisor: {str(e)}")


# ===== ENDPOINTS API =====

@app.on_event("startup")
async def startup_event():
    """Synchronise les workflows au démarrage"""
    try:
        # Créer les répertoires si nécessaire
        for wf_dir in get_workflow_dirs():
            wf_dir.mkdir(parents=True, exist_ok=True)
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        
        total_synced = 0
        for wf_dir in get_workflow_dirs():
            synced = sync_all_workflows(wf_dir, DB_PATH)
            total_synced += synced
        print(f"✅ {total_synced} workflows synchronisés vers la base de données")
    except Exception as e:
        print(f"⚠️ Erreur synchronisation workflows: {e}")


@app.get("/")
async def root():
    """Page d'accueil - redirige vers le dashboard"""
    return FileResponse(STATIC_DIR / "dashboard.html")


@app.get("/api/health")
async def health_check():
    """Health check de l'API"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }


@app.get("/api/stats/overview")
async def get_overview_stats():
    """Statistiques d'ensemble du dashboard"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Charger depuis les workflows JSON (source principale)
        total_scans = 0
        recent_scans = 0
        all_vulns = set()
        critical_vulns = 0
        cvss_scores = []
        all_scripts = set()
        
        workflow_files = []
        for wf_dir in get_workflow_dirs():
            if wf_dir.exists():
                workflow_files.extend(list(wf_dir.glob("*.json")))

        if workflow_files:
            total_scans = len(workflow_files)
            thirty_days_ago = datetime.now().timestamp() - 30*24*3600
            recent_scans = len([f for f in workflow_files if f.stat().st_mtime > thirty_days_ago])
            
            for workflow_file in workflow_files:
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        
                        # Vulnérabilités
                        analysis_result = workflow_data.get("analysis_result")
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities") or []
                            if isinstance(vulns, list) and vulns:
                                for vuln in vulns:
                                    vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                    vuln_id = vuln_dict.get("vulnerability_id")
                                    if vuln_id:
                                        all_vulns.add(vuln_id)
                                        if vuln_dict.get("severity") == "CRITICAL":
                                            critical_vulns += 1
                                        cvss = vuln_dict.get("cvss_score")
                                        if cvss:
                                            cvss_scores.append(float(cvss))
                        
                        # Scripts
                        script_results = workflow_data.get("script_results") or []
                        if isinstance(script_results, list) and script_results:
                            for script in script_results:
                                script_dict = script if isinstance(script, dict) else script.to_dict() if hasattr(script, 'to_dict') else {}
                                script_id = script_dict.get("script_id")
                                if script_id:
                                    all_scripts.add(script_id)
                except Exception as e:
                    print(f"⚠️ Erreur lecture workflow {workflow_file}: {e}")
                    continue
        
        # Compléter avec la base de données si disponible
        try:
            db_scans = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_scans += db_scans
            db_vulns = cursor.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            total_vulns_db = db_vulns
            db_critical = cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'CRITICAL'").fetchone()[0]
            critical_vulns += db_critical
            db_scripts = cursor.execute("SELECT COUNT(*) FROM scripts").fetchone()[0]
            total_scripts_db = db_scripts
        except:
            total_vulns_db = 0
            total_scripts_db = 0
        
        total_vulns = len(all_vulns) + total_vulns_db
        total_scripts = len(all_scripts) + total_scripts_db
        
        # Calculer la moyenne CVSS
        avg_cvss = 0.0
        if cvss_scores:
            avg_cvss = sum(cvss_scores) / len(cvss_scores)
        else:
            try:
                db_avg = cursor.execute("SELECT AVG(cvss_score) FROM vulnerabilities").fetchone()[0]
                if db_avg:
                    avg_cvss = db_avg
            except:
                pass
        
        conn.close()

        return {
            "total_scans": total_scans,
            "recent_scans": recent_scans,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "total_scripts": total_scripts,
            "average_cvss": round(avg_cvss, 1),
            "last_updated": datetime.utcnow().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats/severity-distribution")
async def get_severity_distribution():
    """Distribution des vulnérabilités par sévérité"""

    try:
        # Essayer depuis la DB d'abord
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            severity_counts = cursor.execute("""
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
            """).fetchall()

            conn.close()

            # Transformer en format pour Chart.js
            distribution = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0
            }

            for row in severity_counts:
                severity = row['severity'].upper() if row['severity'] else 'UNKNOWN'
                count = row['count']
                if severity in distribution:
                    distribution[severity] = count

            return {
                "labels": list(distribution.keys()),
                "values": list(distribution.values()),
                "colors": ["#DC2626", "#F59E0B", "#FBBF24", "#10B981", "#6B7280"]
            }
        except Exception as db_error:
            # Fallback : calculer depuis les workflows JSON
            distribution = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0
            }
            
            for wf_dir in get_workflow_dirs():
                for workflow_file in wf_dir.glob("*.json"):
                    try:
                        with open(workflow_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                        
                        # Chercher dans analysis_result puis scan_result
                        vulns = []
                        analysis_result = workflow_data.get("analysis_result")
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities") or []
                        
                        if not vulns:
                            scan_result = workflow_data.get("scan_result")
                            if scan_result:
                                vulns = scan_result.get("vulnerabilities") or []
                        
                        if isinstance(vulns, list) and vulns:
                            for vuln in vulns:
                                if vuln:
                                    vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                    severity = (vuln_dict.get("severity", "UNKNOWN") or "UNKNOWN").upper()
                                    if severity in distribution:
                                        distribution[severity] += 1
                    except:
                        continue
            
            return {
                "labels": list(distribution.keys()),
                "values": list(distribution.values()),
                "colors": ["#DC2626", "#F59E0B", "#FBBF24", "#10B981", "#6B7280"]
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats/timeline")
async def get_vulnerability_timeline():
    """Timeline des vulnérabilités détectées (30 derniers jours)"""

    try:
        # Essayer depuis la DB d'abord
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Utiliser created_at au lieu de discovered_at
            timeline_data = cursor.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM vulnerabilities
                WHERE created_at >= date('now', '-30 days')
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            """).fetchall()

            conn.close()

            # Formater pour Chart.js
            dates = [row['date'] for row in timeline_data]
            counts = [row['count'] for row in timeline_data]

            return {
                "labels": dates,
                "datasets": [
                    {
                        "label": "Vulnérabilités détectées",
                        "data": counts,
                        "borderColor": "#3B82F6",
                        "backgroundColor": "rgba(59, 130, 246, 0.1)",
                        "tension": 0.4
                    }
                ]
            }
        except Exception as db_error:
            # Fallback : calculer depuis les workflows JSON
            from collections import defaultdict
            from datetime import datetime, timedelta
            
            timeline_dict = defaultdict(int)
            cutoff_date = datetime.now() - timedelta(days=30)
            
            for wf_dir in get_workflow_dirs():
                for workflow_file in wf_dir.glob("*.json"):
                    try:
                        with open(workflow_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                        
                        started_at = workflow_data.get("started_at")
                        if not started_at:
                            continue
                        
                        try:
                            scan_date = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
                            if scan_date < cutoff_date:
                                continue
                            
                            date_str = scan_date.strftime('%Y-%m-%d')
                            
                            # Compter les vulnérabilités
                            vulns = []
                            analysis_result = workflow_data.get("analysis_result")
                            if analysis_result:
                                vulns = analysis_result.get("vulnerabilities", []) or []
                            
                            if not vulns:
                                scan_result = workflow_data.get("scan_result")
                                if scan_result:
                                    vulns = scan_result.get("vulnerabilities", []) or []
                            
                            timeline_dict[date_str] += len(vulns) if vulns else 0
                        except:
                            continue
                    except:
                        continue
            
            # Trier par date
            sorted_items = sorted(timeline_dict.items())
            dates = [item[0] for item in sorted_items]
            counts = [item[1] for item in sorted_items]
            
            return {
                "labels": dates,
                "datasets": [
                    {
                        "label": "Vulnérabilités détectées",
                        "data": counts,
                        "borderColor": "#3B82F6",
                        "backgroundColor": "rgba(59, 130, 246, 0.1)",
                        "tension": 0.4
                    }
                ]
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
async def get_scans(
        limit: int = 50,
        status: Optional[str] = None
):
    """Liste des scans avec filtres"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM scans"
        params = []

        if status:
            query += " WHERE status = ?"
            params.append(status)

        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        scans = cursor.execute(query, params).fetchall()

        conn.close()

        return {
            "scans": [dict(scan) for scan in scans],
            "count": len(scans)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    """Détails d'un scan spécifique"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        scan = cursor.execute(
            "SELECT * FROM scans WHERE scan_id = ?",
            (scan_id,)
        ).fetchone()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan non trouvé")

        # Récupérer les vulnérabilités associées
        vulnerabilities = cursor.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ?",
            (scan_id,)
        ).fetchall()

        conn.close()

        return {
            "scan": dict(scan),
            "vulnerabilities": [dict(vuln) for vuln in vulnerabilities]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def _enrich_with_nist_async_quick(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Enrichit une CVE avec NIST API de manière asynchrone avec timeout très court (2s).
    Utilisé pour récupérer rapidement les CVSS sans bloquer.
    """
    global nist_cache
    
    # Vérifier le cache
    if cve_id in nist_cache:
        return nist_cache[cve_id]
    
    try:
        import httpx
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{base_url}?cveId={cve_id}")
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    metrics = cve.get('metrics', {})
                    
                    # Extraire CVSS score
                    cvss_score = None
                    severity = "UNKNOWN"
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                    elif 'cvssMetricV2' in metrics:
                        cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore')
                        # CVSS v2 n'a pas de baseSeverity, on calcule
                        if cvss_score:
                            if cvss_score >= 7.0:
                                severity = "HIGH"
                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"
                            else:
                                severity = "LOW"
                    
                    if cvss_score:
                        result = {
                            "cvss_score": cvss_score,
                            "severity": severity
                        }
                        # Mettre en cache
                        nist_cache[cve_id] = result
                        return result
    except Exception as e:
        # Erreur silencieuse pour ne pas bloquer
        pass
    
    return None


async def _enrich_with_vulners_async(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Enrichit une CVE avec Vulners API de manière asynchrone (plus rapide que NIST).
    Retourne CVSS score et severity depuis Vulners.
    """
    global nist_cache
    from src.core.vulners_fetcher import VulnersFetcher
    from config import get_config
    
    # Vérifier le cache (on utilise le même cache pour Vulners et NIST)
    if cve_id in nist_cache:
        return nist_cache[cve_id]
    
    try:
        config = get_config()
        api_key = getattr(config, 'vulners_api_key', None) or None
        
        fetcher = VulnersFetcher(api_key=api_key)
        cvss_data = await fetcher.fetch_cvss_info(cve_id)
        
        if cvss_data:
            # Mettre en cache
            nist_cache[cve_id] = cvss_data
            return cvss_data
                    
    except Exception as e:
        print(f"⚠️ Erreur enrichissement Vulners pour {cve_id}: {e}")
    
    return None


async def _enrich_scan_vulnerabilities_with_vulners(
    vuln_dicts: List[Dict[str, Any]],
    *,
    concurrency: int = 6,
    per_item_timeout: float = 6.0,
    global_timeout: float = 90.0,
) -> List[Dict[str, Any]]:
    """
    Enrichit une liste de vulnérabilités (scan_only) avec Vulners (CVSS+severity).
    Objectifs:
    - Réactiver des notes fiables (CVSS) et le classement (severity)
    - Éviter le "chargement infini" via timeouts + concurrence limitée
    """
    import asyncio

    if not vuln_dicts:
        return vuln_dicts

    sem = asyncio.Semaphore(concurrency)

    async def _one(v: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            # Toujours faire le local fast en premier (nom, liens NIST, etc.)
            base = _enrich_scan_vulnerability_local_fast(v)
            try:
                return await asyncio.wait_for(
                    _enrich_scan_vulnerability_async(base),
                    timeout=per_item_timeout,
                )
            except (asyncio.TimeoutError, Exception):
                return base

    async def _run_all() -> List[Dict[str, Any]]:
        results = await asyncio.gather(*[_one(v) for v in vuln_dicts], return_exceptions=True)
        out: List[Dict[str, Any]] = []
        for i, r in enumerate(results):
            if isinstance(r, dict):
                out.append(r)
            else:
                # Garder au minimum l'enrichissement local rapide
                out.append(_enrich_scan_vulnerability_local_fast(vuln_dicts[i]))
        return out

    try:
        return await asyncio.wait_for(_run_all(), timeout=global_timeout)
    except (asyncio.TimeoutError, Exception):
        # En cas de timeout global, retourner au moins le local fast
        return [_enrich_scan_vulnerability_local_fast(v) for v in vuln_dicts]


def _enrich_with_nist_sync(cve_id: str, max_calls: int = 50) -> Optional[Dict[str, Any]]:
    """
    Enrichit une CVE avec NIST de manière synchrone (avec cache et limite d'appels).
    Augmenté la limite à 50 pour permettre plus d'enrichissements.
    """
    global nist_cache
    
    # Vérifier le cache
    if cve_id in nist_cache:
        return nist_cache[cve_id]
    
    # Limiter le nombre d'appels NIST pour éviter de ralentir
    if not hasattr(_enrich_with_nist_sync, 'call_count'):
        _enrich_with_nist_sync.call_count = 0
        _enrich_with_nist_sync.last_request_time = 0
    
    if _enrich_with_nist_sync.call_count >= max_calls:
        # On a déjà fait assez d'appels, on skip pour cette requête
        return None
    
    try:
        import requests
        
        # Rate limiting simple (6 secondes entre les appels)
        time_since_last = time.time() - _enrich_with_nist_sync.last_request_time
        if time_since_last < 6:
            time.sleep(6 - time_since_last)
        _enrich_with_nist_sync.last_request_time = time.time()
        _enrich_with_nist_sync.call_count += 1
        
        # Appeler l'API NIST
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response = requests.get(f"{base_url}?cveId={cve_id}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                metrics = cve.get('metrics', {})
                
                # Extraire CVSS score
                cvss_score = None
                severity = "UNKNOWN"
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    # CVSS v2 n'a pas de baseSeverity, on calcule
                    if cvss_score:
                        if cvss_score >= 7.0:
                            severity = "HIGH"
                        elif cvss_score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                
                result = {
                    "cvss_score": cvss_score,
                    "severity": severity
                }
                
                # Mettre en cache
                nist_cache[cve_id] = result
                return result
    except Exception as e:
        print(f"⚠️ Erreur enrichissement NIST pour {cve_id}: {e}")
    
    return None


async def _enrich_scan_vulnerability_async(vuln_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrichit une vulnérabilité depuis les données du scan (sans analyse IA) de manière asynchrone.
    Utilise Vulners en priorité (plus rapide), puis NIST en fallback.
    
    Retourne toujours la vulnérabilité (enrichie ou originale) pour éviter les blocages.
    """
    try:
        enriched = vuln_dict.copy()
        vulnerability_id = enriched.get("vulnerability_id", "")
        
        # 1. Essayer de récupérer le CVSS depuis la base de vulnérabilités locale
        if not enriched.get("cvss_score") or enriched.get("cvss_score") is None:
            try:
                from pathlib import Path
                vuln_db_path = Path(__file__).parent.parent.parent / "config" / "vulnerability_db.json"
                if vuln_db_path.exists():
                    with open(vuln_db_path, 'r', encoding='utf-8') as f:
                        vuln_db = json.load(f)
                        known_vulns = vuln_db.get('known_vulnerabilities', [])
                        for known_vuln in known_vulns:
                            if (known_vuln.get('id') == vulnerability_id or 
                                vulnerability_id in known_vuln.get('cve_ids', [])):
                                if known_vuln.get('cvss_score'):
                                    enriched["cvss_score"] = known_vuln.get('cvss_score')
                                    # Améliorer aussi le nom si générique
                                    if enriched.get("name", "").startswith("Vulnerability "):
                                        enriched["name"] = known_vuln.get('name', enriched.get("name", ""))
                                    break
            except Exception as e:
                # Erreur silencieuse, on continue
                pass
        
        # 2. Si toujours pas de CVSS et que c'est une CVE, essayer Vulners (plus rapide que NIST)
        if (not enriched.get("cvss_score") or enriched.get("cvss_score") is None) and vulnerability_id.startswith("CVE-"):
            try:
                # Essayer Vulners d'abord avec timeout
                import asyncio
                vulners_data = await asyncio.wait_for(
                    _enrich_with_vulners_async(vulnerability_id),
                    timeout=5.0
                )
                if vulners_data and vulners_data.get("cvss_score"):
                    enriched["cvss_score"] = vulners_data.get("cvss_score")
                    if vulners_data.get("severity") and vulners_data.get("severity") != "UNKNOWN":
                        enriched["severity"] = vulners_data.get("severity")
            except (asyncio.TimeoutError, Exception):
                # En cas d'erreur ou timeout, on continue avec la vulnérabilité originale
                pass
        
        # 3. Normaliser le CVSS puis calculer la sévérité depuis le CVSS si disponible
        cvss_score = enriched.get("cvss_score")
        if cvss_score is not None and not isinstance(cvss_score, (int, float)):
            try:
                cvss_score = float(cvss_score)
                enriched["cvss_score"] = cvss_score
            except (ValueError, TypeError):
                cvss_score = None

        if cvss_score is not None and isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            enriched["severity"] = severity
        elif not enriched.get("severity") or enriched.get("severity") == "UNKNOWN":
            enriched["severity"] = "MEDIUM"
        
        # 4. Ajouter les liens de solution de base
        references = enriched.get("references", [])
        solution_links = []
        if references and isinstance(references, list):
            solution_links = [ref for ref in references if isinstance(ref, str) and ref.startswith("http")]
        
        if vulnerability_id and vulnerability_id.startswith("CVE-"):
            nist_link = f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"
            if nist_link not in solution_links:
                solution_links.insert(0, nist_link)
            enriched["primary_solution_link"] = nist_link
        
        if solution_links:
            enriched["solution_links"] = solution_links
        
        return enriched
        
    except Exception as e:
        # En cas d'erreur globale, retourner la vulnérabilité originale
        print(f"⚠️ Erreur enrichissement async pour {vuln_dict.get('vulnerability_id', 'unknown')}: {e}")
        return vuln_dict


def _enrich_scan_vulnerability_local_fast(vuln_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrichit une vulnérabilité rapidement depuis les données locales uniquement (sans appels API).
    Utilisé pour éviter les blocages lors du chargement des vulnérabilités.
    
    Cette fonction :
    - Préserve les données déjà présentes (cvss_score, severity)
    - Calcule la sévérité depuis le CVSS si manquante
    - Lit depuis la base locale vulnerability_db.json si nécessaire
    - Ajoute les liens de solution de base (NIST)
    - Ne fait AUCUN appel API externe
    """
    enriched = vuln_dict.copy()
    vulnerability_id = enriched.get("vulnerability_id", "")
    
    # 1. Normaliser le CVSS score (s'assurer que c'est un nombre)
    cvss_score = enriched.get("cvss_score")
    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score)
            if 0.0 <= cvss_score <= 10.0:
                enriched["cvss_score"] = cvss_score
            else:
                cvss_score = None
        except (ValueError, TypeError):
            cvss_score = None
    
    # 2. Si on a un CVSS mais pas de sévérité, la calculer
    if cvss_score is not None and isinstance(cvss_score, (int, float)):
        if not enriched.get("severity") or enriched.get("severity") == "UNKNOWN":
            if cvss_score >= 9.0:
                enriched["severity"] = "CRITICAL"
            elif cvss_score >= 7.0:
                enriched["severity"] = "HIGH"
            elif cvss_score >= 4.0:
                enriched["severity"] = "MEDIUM"
            else:
                enriched["severity"] = "LOW"
    
    # 3. Si on n'a toujours pas de CVSS, essayer de le récupérer depuis la base locale
    if enriched.get("cvss_score") is None or enriched.get("cvss_score") == "":
        try:
            from pathlib import Path
            vuln_db_path = Path(__file__).parent.parent.parent / "config" / "vulnerability_db.json"
            if vuln_db_path.exists():
                with open(vuln_db_path, 'r', encoding='utf-8') as f:
                    vuln_db = json.load(f)
                    known_vulns = vuln_db.get('known_vulnerabilities', [])
                    for known_vuln in known_vulns:
                        if (known_vuln.get('id') == vulnerability_id or 
                            vulnerability_id in known_vuln.get('cve_ids', [])):
                            if known_vuln.get('cvss_score'):
                                enriched["cvss_score"] = float(known_vuln.get('cvss_score'))
                                # Améliorer aussi le nom si générique
                                if enriched.get("name", "").startswith("Vulnerability "):
                                    enriched["name"] = known_vuln.get('name', enriched.get("name", ""))
                                break
        except Exception:
            # Erreur silencieuse, on continue
            pass
    
    # 4. Recalculer la sévérité si on a maintenant un CVSS mais toujours pas de sévérité
    cvss_score = enriched.get("cvss_score")
    if cvss_score is not None and isinstance(cvss_score, (int, float)):
        if not enriched.get("severity") or enriched.get("severity") == "UNKNOWN":
            if cvss_score >= 9.0:
                enriched["severity"] = "CRITICAL"
            elif cvss_score >= 7.0:
                enriched["severity"] = "HIGH"
            elif cvss_score >= 4.0:
                enriched["severity"] = "MEDIUM"
            else:
                enriched["severity"] = "LOW"
    
    # 5. Dernier recours : sévérité par défaut si rien n'a été trouvé
    if not enriched.get("severity") or enriched.get("severity") == "UNKNOWN":
        enriched["severity"] = "MEDIUM"
    
    # 4. Ajouter les liens de solution de base
    references = enriched.get("references", [])
    solution_links = []
    if references and isinstance(references, list):
        solution_links = [ref for ref in references if isinstance(ref, str) and ref.startswith("http")]
    
    if vulnerability_id and vulnerability_id.startswith("CVE-"):
        nist_link = f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"
        if nist_link not in solution_links:
            solution_links.insert(0, nist_link)
        enriched["primary_solution_link"] = nist_link
    
    if solution_links:
        enriched["solution_links"] = solution_links
    
    return enriched


def _enrich_scan_vulnerability(vuln_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrichit une vulnérabilité depuis les données du scan (sans analyse IA) - version synchrone.
    À utiliser pour la compatibilité, mais préférer _enrich_scan_vulnerability_async() pour les performances.
    """
    enriched = vuln_dict.copy()
    vulnerability_id = enriched.get("vulnerability_id", "")
    
    # 1. Essayer de récupérer le CVSS depuis la base de vulnérabilités locale
    if not enriched.get("cvss_score") or enriched.get("cvss_score") is None:
        try:
            from pathlib import Path
            vuln_db_path = Path(__file__).parent.parent.parent / "config" / "vulnerability_db.json"
            if vuln_db_path.exists():
                with open(vuln_db_path, 'r', encoding='utf-8') as f:
                    vuln_db = json.load(f)
                    known_vulns = vuln_db.get('known_vulnerabilities', [])
                    for known_vuln in known_vulns:
                        if (known_vuln.get('id') == vulnerability_id or 
                            vulnerability_id in known_vuln.get('cve_ids', [])):
                            if known_vuln.get('cvss_score'):
                                enriched["cvss_score"] = known_vuln.get('cvss_score')
                                # Améliorer aussi le nom si générique
                                if enriched.get("name", "").startswith("Vulnerability "):
                                    enriched["name"] = known_vuln.get('name', enriched.get("name", ""))
                                break
        except Exception as e:
            print(f"⚠️ Erreur lecture base vulnérabilités: {e}")
    
    # 2. Si toujours pas de CVSS et que c'est une CVE, essayer NIST (limite augmentée à 50)
    if (not enriched.get("cvss_score") or enriched.get("cvss_score") is None) and vulnerability_id.startswith("CVE-"):
        nist_data = _enrich_with_nist_sync(vulnerability_id, max_calls=50)
        if nist_data and nist_data.get("cvss_score"):
            enriched["cvss_score"] = nist_data.get("cvss_score")
            # Utiliser la sévérité NIST si disponible
            if nist_data.get("severity") and nist_data.get("severity") != "UNKNOWN":
                enriched["severity"] = nist_data.get("severity")
    
    # 3. Dernier recours : essayer d'extraire le CVSS depuis la description
    # (seulement si on n'a toujours pas de CVSS et que la description contient la CVE)
    if (not enriched.get("cvss_score") or enriched.get("cvss_score") is None):
        description = enriched.get("description", "")
        if description and vulnerability_id:
            # Chercher un pattern comme "CVE-XXXX-XXXX\t9.8\t" ou "CVE-XXXX-XXXX 9.8"
            # On cherche spécifiquement la CVE dans la description
            if vulnerability_id in description:
                # Pattern: CVE-ID suivi d'un score (séparé par tab, espace, ou autre)
                cvss_pattern = re.search(
                    rf'{re.escape(vulnerability_id)}[^\d]*(\d+\.\d+)',
                    description
                )
                if cvss_pattern:
                    try:
                        cvss_score = float(cvss_pattern.group(1))
                        # Valider que c'est un score CVSS raisonnable (0.0 à 10.0)
                        if 0.0 <= cvss_score <= 10.0:
                            enriched["cvss_score"] = cvss_score
                    except (ValueError, AttributeError):
                        pass
    
    # 4. Calculer la sévérité depuis le CVSS si disponible
    cvss_score = enriched.get("cvss_score")
    if cvss_score is not None and isinstance(cvss_score, (int, float)):
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Toujours utiliser la sévérité calculée depuis le CVSS (plus fiable)
        enriched["severity"] = severity
    elif not enriched.get("severity") or enriched.get("severity") == "UNKNOWN":
        # Si on n'a pas de CVSS et pas de sévérité, utiliser MEDIUM par défaut
        enriched["severity"] = "MEDIUM"
    
    # 3. Utiliser les références comme liens de solution (spécifiques à cette CVE)
    references = enriched.get("references", [])
    solution_links = []
    primary_link = None
    
    if references and isinstance(references, list):
        # Filtrer les références valides (URLs)
        solution_links = [ref for ref in references if isinstance(ref, str) and ref.startswith("http")]
    
    # Toujours créer un lien NIST pour la CVE spécifique si c'est une CVE
    if vulnerability_id and vulnerability_id.startswith("CVE-"):
        nist_link = f"https://nvd.nist.gov/vuln/detail/{vulnerability_id}"
        if nist_link not in solution_links:
            solution_links.insert(0, nist_link)  # Mettre en premier
        primary_link = nist_link
    
    # Si on a des références, chercher un lien qui correspond exactement à cette CVE
    if references and isinstance(references, list) and vulnerability_id:
        for link in references:
            if isinstance(link, str) and vulnerability_id.lower() in link.lower():
                # Trouver le lien qui correspond exactement à cette CVE
                if "cve" in link.lower() and vulnerability_id.lower() in link.lower():
                    primary_link = link
                    break
    
    # Si pas de lien principal trouvé, utiliser le premier lien de solution
    if not primary_link and solution_links:
        primary_link = solution_links[0]
    
    if solution_links:
        enriched["solution_links"] = solution_links
    if primary_link:
        enriched["primary_solution_link"] = primary_link
    
    return enriched


def _compute_upgrade_plan_from_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Calcule un plan de mises à jour de manière ALGORITHMIQUE (sans IA).

    Idée :
    - Regrouper les vulnérabilités par composant (service / produit détecté)
    - Pour chaque composant, compter le nombre de vulnérabilités
    - Déduire une priorité à partir de la sévérité maximale du groupe
    - Retourner une liste d'étapes triées par nombre de vulnérabilités corrigées
    """
    if not vulnerabilities:
        return {
            "upgrade_plan": [],
            "summary": {
                "total_steps": 0,
                "total_vulnerabilities_fixed": 0,
                "estimated_total_time": "0 min",
                "requires_reboot": False,
            },
            "notes": "Aucune vulnérabilité fournie pour construire un plan de mises à jour.",
        }

    # Regrouper par composant (service/prod). Fallback : extraire un "produit" du nom ou de la CVE.
    groups: Dict[str, Dict[str, Any]] = {}

    def _guess_component(v: Dict[str, Any]) -> str:
        # Priorité au service détecté
        service = (v.get("affected_service") or "").strip()
        if service:
            return service

        name = (v.get("name") or "").lower()
        if "apache" in name:
            return "apache"
        if "httpd" in name:
            return "apache-httpd"
        if "nginx" in name:
            return "nginx"
        if "openssl" in name:
            return "openssl"
        if "php" in name:
            return "php"
        if "mysql" in name:
            return "mysql"
        if "postgres" in name or "postgresql" in name:
            return "postgresql"

        # Fallback : utiliser un bucket générique pour les CVE sans service clair
        vid = v.get("vulnerability_id") or ""
        if vid.startswith("CVE-"):
            return "system-packages"

        return "autre-composant"

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

    for vuln in vulnerabilities:
        component = _guess_component(vuln)
        group = groups.setdefault(
            component,
            {
                "component": component,
                "component_display_name": vuln.get("affected_service") or component.capitalize(),
                "vulnerabilities": [],
                "max_severity": "LOW",
                "max_cvss": 0.0,
            },
        )

        group["vulnerabilities"].append(vuln)

        sev = (vuln.get("severity") or "LOW").upper()
        if severity_order.get(sev, 0) > severity_order.get(group["max_severity"], 0):
            group["max_severity"] = sev

        cvss = vuln.get("cvss_score")
        try:
            if cvss is not None:
                cvss_f = float(cvss)
                if cvss_f > group["max_cvss"]:
                    group["max_cvss"] = cvss_f
        except (TypeError, ValueError):
            pass

    # Construire les étapes
    steps: List[Dict[str, Any]] = []
    total_fixed = 0
    requires_reboot = False  # On ne peut pas le savoir algorithmiquement => False

    for idx, (component, info) in enumerate(groups.items(), start=1):
        vulns = info["vulnerabilities"]
        vuln_ids = [v.get("vulnerability_id") or "" for v in vulns]
        vuln_count = len(vuln_ids)
        total_fixed += vuln_count

        max_sev = info["max_severity"]
        # Déterminer une pseudo version cible : on ne la connaît pas, donc on reste générique.
        target_version = "Mettre à jour à la dernière version stable recommandée par l'éditeur"

        reason = (
            f"Cette mise à jour regroupe {vuln_count} vulnérabilité(s) sur le composant "
            f"« {info['component_display_name']} » avec une sévérité maximale {max_sev}."
        )

        cmd_hint = None
        # Donne juste un hint très générique selon le composant
        comp_lower = component.lower()
        if comp_lower in ("apache", "apache-httpd", "nginx", "php"):
            cmd_hint = "sudo apt update && sudo apt upgrade -y  # Adapter au gestionnaire de paquets de votre OS"
        elif comp_lower in ("openssl", "mysql", "postgresql"):
            cmd_hint = "sudo apt update && sudo apt install -y <paquet>  # Adapter au paquet exact"

        step = {
            "step": idx,
            "component": component,
            "component_display_name": info["component_display_name"],
            "current_version": "Inconnue (déduire depuis l'inventaire ou les bannières)",
            "target_version": target_version,
            "vulnerabilities_fixed": vuln_ids,
            "vulnerability_count": vuln_count,
            "reason": reason,
            "priority": max_sev,
            "requires_reboot": requires_reboot,
            "estimated_duration": "15-60 minutes (selon l'environnement)",
            "command_hint": cmd_hint,
        }
        steps.append(step)

    # Trier les étapes : d'abord par nombre de vulnérabilités corrigées, puis par sévérité
    def _step_sort_key(s: Dict[str, Any]):
        return (
            -(s.get("vulnerability_count") or 0),
            -severity_order.get(s.get("priority", "LOW"), 0),
        )

    steps.sort(key=_step_sort_key)

    summary = {
        "total_steps": len(steps),
        "total_vulnerabilities_fixed": total_fixed,
        "estimated_total_time": f"{len(steps) * 30} minutes (approximation)",
        "requires_reboot": requires_reboot,
    }

    notes = (
        "Ce plan est généré de manière purement algorithmique en regroupant les vulnérabilités "
        "par composant/service. Pour chaque groupe, il est recommandé de consulter les liens de "
        "solution (NIST, vendor advisories, etc.) afin de choisir la version exacte à déployer."
    )

    return {
        "upgrade_plan": steps,
        "summary": summary,
        "notes": notes,
    }


async def _prepare_solutions_text_for_ai(
    vulnerabilities: List[Dict[str, Any]], 
    max_vulns: int = 100
) -> str:
    """
    Récupère toutes les solutions depuis l'API Vulners et retourne un texte
    avec une phrase par CVE pour identifier les patterns répétés.
    
    C'est cette fonction qui prépare le texte que Claude va analyser
    pour trouver les solutions communes qui règlent le maximum de vulnérabilités.
    
    Format retourné :
    ```
    CVE-2023-XXXX se règle en mettant à jour Apache vers 2.4.62
    CVE-2023-YYYY se règle en mettant à jour OpenSSL vers 1.1.1w
    ...
    ```
    
    Args:
        vulnerabilities: Liste des vulnérabilités du scan
        max_vulns: Nombre maximum de vulnérabilités à traiter (par défaut 100)
    
    Returns:
        Texte avec une phrase de solution par CVE, séparées par des sauts de ligne
    """
    from src.core.vulners_fetcher import VulnersFetcher
    from config import get_config
    
    config = get_config()
    api_key = getattr(config, 'vulners_api_key', None) or None
    
    fetcher = VulnersFetcher(api_key=api_key)
    solutions_text = await fetcher.fetch_all_solutions_as_text(vulnerabilities, max_vulns)
    
    return solutions_text


def _prepare_vulnerabilities_for_ai_upgrade_plan(
    vulnerabilities: List[Dict[str, Any]], max_vulns: int = 100
) -> str:
    """
    Prépare les données de vulnérabilités pour le prompt IA de plan de mises à jour (ancien format).
    On garde uniquement les infos utiles : id, nom, sévérité, service, description courte, liens.
    
    NOTE: Cette fonction est gardée pour compatibilité avec l'ancien système (fallback).
    """
    # Trier par CVSS décroissant (les plus critiques en premier)
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda x: x.get("cvss_score", 0) or 0,
        reverse=True,
    )

    limited_vulns = sorted_vulns[:max_vulns]

    payload: List[Dict[str, Any]] = []
    for v in limited_vulns:
        payload.append(
            {
                "id": v.get("vulnerability_id", ""),
                "name": v.get("name", "")[:200],
                "severity": v.get("severity", "MEDIUM"),
                "cvss_score": v.get("cvss_score"),
                "affected_service": v.get("affected_service", ""),
                "description": (v.get("description", "") or "")[:400],
                "solution_links": (v.get("solution_links") or [])[:5],
                "primary_solution_link": v.get("primary_solution_link"),
            }
        )

    return json.dumps(payload, indent=2, ensure_ascii=False)


async def _generate_upgrade_plan_with_ai_from_scan_vulns(
    vulnerabilities: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Utilise l'IA pour détecter les patterns répétés dans les solutions
    et proposer un plan optimisé qui règle le maximum de vulnérabilités.
    
    Processus :
    1. Récupère toutes les solutions depuis l'API OSV.dev et formate en phrases simples
    2. Envoie ces phrases à Claude avec un prompt focalisé sur la détection de patterns
    3. Claude identifie les patterns répétés (les mêmes solutions pour plusieurs CVE)
    4. Claude propose un plan optimisé basé sur ces patterns
    
    L'objectif est de trouver les solutions qui règlent le plus de vulnérabilités en même temps.
    """
    from config import get_config
    from config.prompts import format_upgrade_plan_pattern_prompt
    from src.core.analyzer import Analyzer

    if not vulnerabilities:
        return {
            "upgrade_plan": [],
            "summary": {
                "total_steps": 0,
                "total_vulnerabilities_fixed": 0,
                "estimated_total_time": "0 min",
                "requires_reboot": False,
            },
            "notes": "Aucune vulnérabilité fournie pour construire un plan de mises à jour.",
        }

    # 1. Récupérer toutes les solutions depuis Vulners API et formater en phrases simples
    print(f"🔍 Récupération des solutions depuis Vulners API pour {len(vulnerabilities)} vulnérabilités...")
    solutions_text = await _prepare_solutions_text_for_ai(vulnerabilities, max_vulns=100)
    
    if not solutions_text or not solutions_text.strip():
        print("⚠️ Aucune solution trouvée depuis Vulners API, fallback sur l'algorithme local")
        return None  # Signaler l'échec pour déclencher le fallback
    
    print(f"✅ Solutions récupérées depuis Vulners, analyse des patterns par l'IA...")
    
    # 2. Construire le prompt focalisé sur la détection de patterns
    config = get_config()
    analyzer = Analyzer(config)
    
    prompt = format_upgrade_plan_pattern_prompt(solutions_text=solutions_text)
    
    # 3. Appeler Claude pour analyser les patterns
    response_text = await analyzer._call_ai_api(prompt)

    # 4. Nettoyer les éventuels blocs ```json
    response_text = (response_text or "").strip()
    if "```json" in response_text:
        start = response_text.find("```json") + 7
        end = response_text.find("```", start)
        if end != -1:
            response_text = response_text[start:end].strip()
    elif "```" in response_text:
        start = response_text.find("```") + 3
        end = response_text.find("```", start)
        if end != -1:
            response_text = response_text[start:end].strip()

    try:
        plan_data = json.loads(response_text)
    except json.JSONDecodeError as e:
        print(f"⚠️ Erreur parsing JSON du plan IA: {e}")
        print(f"Réponse brute: {response_text[:400]}")
        raise HTTPException(
            status_code=500,
            detail="Réponse IA invalide pour le plan de mises à jour",
        )

    # 5. Validation minimale de structure
    if not isinstance(plan_data, dict) or "upgrade_plan" not in plan_data:
        raise HTTPException(
            status_code=500,
            detail="Format de plan IA invalide (champ 'upgrade_plan' manquant)",
        )

    if not isinstance(plan_data.get("upgrade_plan"), list):
        raise HTTPException(
            status_code=500,
            detail="Format de plan IA invalide (upgrade_plan doit être une liste)",
        )

    print(f"✅ Plan de mises à jour généré via pattern detection ({len(plan_data.get('upgrade_plan', []))} étapes)")
    return plan_data


@app.post("/api/scans/{scan_id}/upgrade-plan")
async def generate_upgrade_plan(scan_id: str):
    """
    Génère un plan de mises à jour optimisé pour un scan donné.
    Le plan identifie les mises à jour de composants qui corrigent le maximum de vulnérabilités.
    
    Args:
        scan_id: ID du scan
    
    Returns:
        Dict contenant le plan de mises à jour structuré
    """
    global upgrade_plan_cache
    
    # Vérifier le cache (plan déjà calculé pour ce scan)
    if scan_id in upgrade_plan_cache:
        print(f"✅ Plan de mises à jour récupéré depuis le cache pour scan_id: {scan_id}")
        return upgrade_plan_cache[scan_id]
    
    try:
        # Récupérer les vulnérabilités du scan
        vuln_response = await get_scan_vulnerabilities(scan_id, limit=500)
        vulnerabilities = vuln_response.get("vulnerabilities", [])
        
        if not vulnerabilities:
            raise HTTPException(
                status_code=404,
                detail=f"Aucune vulnérabilité trouvée pour le scan {scan_id}"
            )
        
        plan_data = None
        
        # 1) Essayer d'abord avec l'IA (Claude via Analyzer)
        try:
            print(f"🧠 Génération du plan de mises à jour via IA pour scan {scan_id} ({len(vulnerabilities)} vulnérabilités)")
            plan_data = await _generate_upgrade_plan_with_ai_from_scan_vulns(vulnerabilities)
        except Exception as ai_error:
            print(f"⚠️ Erreur plan IA, fallback sur algorithme local: {ai_error}")
            # On continue en fallback sur l'algorithme local
        
        # 2) Fallback : algorithme local si l'IA a échoué ou renvoyé quelque chose d'invalide
        if not plan_data:
            plan_data = _compute_upgrade_plan_from_vulnerabilities(vulnerabilities)
        
        # Mettre en cache
        upgrade_plan_cache[scan_id] = plan_data
        
        return plan_data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"⚠️ Erreur génération plan de mises à jour pour scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la génération du plan de mises à jour: {str(e)}"
        )


@app.get("/api/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(scan_id: str, limit: int = 500):
    """
    Retourne les vulnérabilités pour un scan précis à partir des fichiers
    de résultats de workflow (sans les mélanger avec les autres scans).
    """
    # Réinitialiser le compteur d'appels NIST pour cette requête
    if hasattr(_enrich_with_nist_sync, 'call_count'):
        _enrich_with_nist_sync.call_count = 0
    
    try:
        vulnerabilities_list = []
        scan_info = {}  # Pour retourner aussi les infos du scan (cible, date, etc.)

        # D'abord, vérifier si on a le workflow_id dans active_scans
        workflow_id_from_active = None
        if scan_id in active_scans:
            workflow_id_from_active = active_scans[scan_id].get("workflow_id")
            if workflow_id_from_active:
                print(f"🔍 scan_id {scan_id} correspond à workflow_id {workflow_id_from_active} (depuis active_scans)")

        # Chercher dans TOUS les dossiers de workflows (nouveau + ancien)
        workflow_dirs = get_workflow_dirs()
        
        print(f"🔍 Recherche vulnérabilités pour scan_id: {scan_id}")
        if workflow_id_from_active:
            print(f"🔗 workflow_id connu: {workflow_id_from_active}")
        print(f"📁 Dossiers à chercher: {[str(d) for d in workflow_dirs]}")
        
        # Si on connaît le workflow_id, chercher directement ce fichier d'abord
        if workflow_id_from_active:
            for workflows_dir in workflow_dirs:
                if not workflows_dir.exists():
                    continue
                workflow_file = workflows_dir / f"{workflow_id_from_active}.json"
                if workflow_file.exists():
                    try:
                        with open(workflow_file, "r", encoding="utf-8") as f:
                            workflow_data = json.load(f)
                        
                        # Vérifier que c'est bien le bon scan
                        if workflow_data.get("scan_id") == scan_id or scan_id == workflow_id_from_active:
                            print(f"✅ Fichier workflow trouvé directement: {workflow_file.name}")
                            # Traiter ce workflow (code réutilisé ci-dessous)
                            workflow_id = workflow_file.stem
                            scan_result = workflow_data.get("scan_result") or {}
                            analysis_result = workflow_data.get("analysis_result") or {}
                            
                            scan_info = {
                                "scan_id": scan_id,
                                "workflow_id": workflow_id,
                                "target": workflow_data.get("target", "N/A"),
                                "scan_type": workflow_data.get("workflow_type", "N/A"),
                                "started_at": workflow_data.get("started_at", "N/A"),
                                "completed_at": workflow_data.get("completed_at", "N/A"),
                                "total_vulnerabilities": workflow_data.get("total_vulnerabilities", 0)
                            }
                            
                            # Récupérer les vulnérabilités
                            vulns = []
                            if analysis_result:
                                analysis_vulns = analysis_result.get("vulnerabilities")
                                if isinstance(analysis_vulns, list):
                                    vulns = analysis_vulns
                                elif analysis_vulns is not None:
                                    vulns = [analysis_vulns] if isinstance(analysis_vulns, dict) else []
                            
                            if not vulns and scan_result:
                                scan_vulns = scan_result.get("vulnerabilities")
                                if isinstance(scan_vulns, list):
                                    vulns = scan_vulns
                                elif scan_vulns is not None:
                                    vulns = [scan_vulns] if isinstance(scan_vulns, dict) else []
                            
                            if not isinstance(vulns, list):
                                vulns = []
                            
                            # Préparer les vulnérabilités pour traitement rapide (sans enrichissement API bloquant)
                            vuln_dicts = []
                            for vuln in vulns:
                                vuln_dict = (
                                    vuln
                                    if isinstance(vuln, dict)
                                    else vuln.to_dict()
                                    if hasattr(vuln, "to_dict")
                                    else {}
                                )
                                vuln_dicts.append(vuln_dict)
                            
                            # Enrichissement Vulners (CVSS + severity) - plus lent mais fiable.
                            # On protège contre les blocages via timeouts + concurrence limitée.
                            # ⚠️ Même si analysis_result existe, on ré-enrichit si les scores sont manquants.
                            needs_enrich = (
                                not analysis_result
                                or not analysis_result.get("vulnerabilities")
                                or all(
                                    (v.get("cvss_score") is None)
                                    for v in vuln_dicts
                                )
                            )
                            if needs_enrich:
                                print(f"🔄 Enrichissement Vulners de {len(vuln_dicts)} vulnérabilités (peut prendre du temps)...")
                                vuln_dicts = await _enrich_scan_vulnerabilities_with_vulners(
                                    vuln_dicts,
                                    concurrency=6,
                                    per_item_timeout=6.0,
                                    global_timeout=120.0,
                                )
                                print(f"✅ Vulners: enrichissement terminé ({len(vuln_dicts)} vulnérabilités)")
                            
                            # Traiter les vulnérabilités enrichies
                            for vuln_dict in vuln_dicts:
                                
                                # Extraire les liens de solution / références (si disponibles)
                                solution_links = []
                                # Priorité aux liens de solution dédiés (analyse IA ou enrichissement)
                                if isinstance(vuln_dict.get("solution_links"), list):
                                    solution_links = vuln_dict.get("solution_links") or []
                                # Sinon, utiliser les références du scan (CVE, exploit, NIST, etc.)
                                elif isinstance(vuln_dict.get("references"), list):
                                    solution_links = vuln_dict.get("references") or []

                                primary_solution_link = vuln_dict.get("primary_solution_link")
                                if not primary_solution_link and isinstance(solution_links, list) and solution_links:
                                    primary_solution_link = solution_links[0]

                                # Statut dérivé des informations de faux positif si disponibles
                                is_fp = vuln_dict.get("is_false_positive", False)
                                status = "false_positive" if is_fp else "open"

                                normalized_vuln = {
                                    "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                                    "name": vuln_dict.get("name", ""),
                                    "severity": vuln_dict.get("severity", "MEDIUM"),
                                    "cvss_score": vuln_dict.get("cvss_score"),
                                    "description": vuln_dict.get("description", ""),
                                    "affected_service": vuln_dict.get("affected_service", ""),
                                    "affected_port": vuln_dict.get("affected_port"),
                                    "status": status,
                                    "is_false_positive": is_fp,
                                    "false_positive_confidence": vuln_dict.get("false_positive_confidence"),
                                    "false_positive_reasoning": vuln_dict.get("false_positive_reasoning"),
                                    "solution_links": solution_links,
                                    "primary_solution_link": primary_solution_link,
                                    # Garder aussi les références brutes pour la modal de détails
                                    "references": vuln_dict.get("references", []),
                                    # Localisation de détection (où la vulnérabilité a été trouvée)
                                    "detection_location": vuln_dict.get("detection_location"),
                                }
                                
                                vulnerabilities_list.append(normalized_vuln)
                            
                            # Récupérer le rapport de validation
                            validation_report = workflow_data.get("validation_report")
                            
                            # Créer un mapping vuln_id -> validation
                            validation_map = {}
                            if validation_report:
                                for val in validation_report.get("validated_vulnerabilities", []):
                                    validation_map[val["vulnerability_id"]] = {
                                        "is_valid": val["is_valid"],
                                        "confidence_score": val["confidence_score"],
                                        "risk_assessment": val["risk_assessment"],
                                        "evidence": {
                                            "source": val["evidence"]["source"],
                                            "extracted_cvss": val["evidence"]["extracted_cvss"],
                                            "extracted_severity": val["evidence"]["extracted_severity"],
                                            "cve_mentioned": val["evidence"]["cve_mentioned"],
                                            "references_found": val["evidence"]["references_found"],
                                            "confidence_level": val["evidence"]["confidence_level"],
                                            "validation_notes": val["evidence"]["validation_notes"],
                                            "detection_location": val["evidence"].get("detection_location")
                                        },
                                        "cross_references": val["cross_references"],
                                        "recommendations": val["recommendations"]
                                    }
                            
                            # Ajouter les validations aux vulnérabilités
                            for vuln in vulnerabilities_list:
                                vuln_id = vuln.get("vulnerability_id")
                                if vuln_id in validation_map:
                                    vuln["validation"] = validation_map[vuln_id]
                                else:
                                    # Validation par défaut si pas trouvée
                                    vuln["validation"] = {
                                        "is_valid": None,
                                        "confidence_score": 0.0,
                                        "risk_assessment": "UNKNOWN",
                                        "evidence": {
                                            "validation_notes": "Validation non disponible"
                                        }
                                    }
                            
                            # Trier et retourner
                            vulnerabilities_list.sort(
                                key=lambda x: x.get("cvss_score", 0) or 0, reverse=True
                            )
                            
                            return {
                                "vulnerabilities": vulnerabilities_list[:limit],
                                "count": len(vulnerabilities_list),
                                "scan_info": scan_info,
                                "validation_summary": validation_report.get("summary", {}) if validation_report else None
                            }
                    except Exception as e:
                        print(f"⚠️ Erreur lecture workflow direct {workflow_file}: {e}")
                        # Continuer avec la recherche normale
        
        # Recherche normale dans tous les fichiers
        for workflows_dir in workflow_dirs:
            if not workflows_dir.exists():
                print(f"⚠️ Dossier non trouvé: {workflows_dir}")
                continue
            
            print(f"✅ Recherche dans: {workflows_dir}")
            json_files = list(workflows_dir.glob("*.json"))
            print(f"📄 {len(json_files)} fichiers JSON trouvés")
                
            for workflow_file in workflows_dir.glob("*.json"):
                try:
                    with open(workflow_file, "r", encoding="utf-8") as f:
                        workflow_data = json.load(f)

                    # Identifier les différents IDs possibles pour ce workflow
                    workflow_id = workflow_file.stem  # ID principal (utilisé comme scan_id dans list_scans)
                    wf_scan_id = workflow_data.get("scan_id")  # éventuel scan_id racine
                    scan_result = workflow_data.get("scan_result") or {}  # Définir scan_result tôt
                    sr_scan_id = scan_result.get("scan_id") if scan_result else None  # scan_id interne du collecteur

                    # Correspondance améliorée :
                    # 1. Correspondance exacte avec scan_id
                    # 2. Correspondance avec workflow_id si on le connaît
                    # 3. Correspondance avec les IDs dans le fichier
                    is_match = False
                    if scan_id in (workflow_id, wf_scan_id, sr_scan_id):
                        is_match = True
                    elif workflow_id_from_active and workflow_id == workflow_id_from_active:
                        is_match = True
                    elif workflow_id_from_active and wf_scan_id == workflow_id_from_active:
                        is_match = True

                    if not is_match:
                        continue  # pas le bon scan/workflow
                    
                    print(f"✅ MATCH trouvé dans {workflow_file.name}!")
                    print(f"   workflow_id={workflow_id}, wf_scan_id={wf_scan_id}, sr_scan_id={sr_scan_id}")

                    # Stocker les infos du scan pour le retour
                    scan_info = {
                        "scan_id": scan_id,
                        "workflow_id": workflow_id,
                        "target": workflow_data.get("target", "N/A"),
                        "scan_type": workflow_data.get("workflow_type", "N/A"),
                        "started_at": workflow_data.get("started_at", "N/A"),
                        "completed_at": workflow_data.get("completed_at", "N/A"),
                        "total_vulnerabilities": workflow_data.get("total_vulnerabilities", 0)
                    }

                    # On privilégie les vulnérabilités déjà analysées
                    vulns = []
                    analysis_result = workflow_data.get("analysis_result") or {}
                    if analysis_result:
                        analysis_vulns = analysis_result.get("vulnerabilities")
                        if isinstance(analysis_vulns, list):
                            vulns = analysis_vulns
                        elif analysis_vulns is not None:
                            vulns = [analysis_vulns] if isinstance(analysis_vulns, dict) else []

                    # Si pas d'analyse, on retombe sur les vulnérabilités brutes du scan
                    if not vulns and scan_result:
                        scan_vulns = scan_result.get("vulnerabilities")
                        if isinstance(scan_vulns, list):
                            vulns = scan_vulns
                        elif scan_vulns is not None:
                            vulns = [scan_vulns] if isinstance(scan_vulns, dict) else []
                    
                    # S'assurer que vulns est toujours une liste
                    if not isinstance(vulns, list):
                        vulns = []
                    
                    print(f"📊 Vulnérabilités trouvées: {len(vulns)} (analysis: {len(analysis_result.get('vulnerabilities', [])) if analysis_result and isinstance(analysis_result.get('vulnerabilities'), list) else 0}, scan: {len(scan_result.get('vulnerabilities', [])) if scan_result and isinstance(scan_result.get('vulnerabilities'), list) else 0})")

                    for vuln in vulns:
                        vuln_dict = (
                            vuln
                            if isinstance(vuln, dict)
                            else vuln.to_dict()
                            if hasattr(vuln, "to_dict")
                            else {}
                        )

                        # Enrichir la vulnérabilité si nécessaire :
                        # - pas d'analysis_result
                        # - OU analysis_result sans vulnérabilités
                        # - OU CVSS manquant
                        needs_enrich = (
                            not analysis_result
                            or not analysis_result.get("vulnerabilities")
                            or vuln_dict.get("cvss_score") is None
                        )
                        if needs_enrich:
                            # Enrichissement Vulners (safe): on ne fait pas de asyncio.run ici (déjà dans un endpoint async)
                            try:
                                import asyncio
                                vuln_dict = await asyncio.wait_for(
                                    _enrich_scan_vulnerability_async(_enrich_scan_vulnerability_local_fast(vuln_dict)),
                                    timeout=6.0,
                                )
                            except (asyncio.TimeoutError, Exception):
                                vuln_dict = _enrich_scan_vulnerability_local_fast(vuln_dict)

                        normalized_vuln = {
                            "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                            "name": vuln_dict.get("name", ""),
                            "severity": vuln_dict.get("severity", "MEDIUM"),
                            "cvss_score": vuln_dict.get("cvss_score"),
                            "description": vuln_dict.get("description", ""),
                            "affected_service": vuln_dict.get("affected_service", ""),
                            "affected_port": vuln_dict.get("affected_port"),
                            "status": "open",
                            "is_false_positive": vuln_dict.get(
                                "is_false_positive", False
                            ),
                            "false_positive_confidence": vuln_dict.get(
                                "false_positive_confidence"
                            ),
                            "false_positive_reasoning": vuln_dict.get(
                                "false_positive_reasoning"
                            ),
                            # Ajouter les liens de solution depuis l'enrichissement
                            "solution_links": vuln_dict.get("solution_links", []),
                            "primary_solution_link": vuln_dict.get("primary_solution_link"),
                            "references": vuln_dict.get("references", []),
                            # Localisation de détection (où la vulnérabilité a été trouvée)
                            "detection_location": vuln_dict.get("detection_location"),
                        }

                        vulnerabilities_list.append(normalized_vuln)

                    # Récupérer le rapport de validation depuis workflow_data
                    validation_report = workflow_data.get("validation_report")
                    
                    # Créer un mapping vuln_id -> validation
                    validation_map = {}
                    if validation_report:
                        for val in validation_report.get("validated_vulnerabilities", []):
                            validation_map[val["vulnerability_id"]] = {
                                "is_valid": val["is_valid"],
                                "confidence_score": val["confidence_score"],
                                "risk_assessment": val["risk_assessment"],
                                "evidence": {
                                    "source": val["evidence"]["source"],
                                    "extracted_cvss": val["evidence"]["extracted_cvss"],
                                    "extracted_severity": val["evidence"]["extracted_severity"],
                                    "cve_mentioned": val["evidence"]["cve_mentioned"],
                                    "references_found": val["evidence"]["references_found"],
                                    "confidence_level": val["evidence"]["confidence_level"],
                                    "validation_notes": val["evidence"]["validation_notes"],
                                    "detection_location": val["evidence"].get("detection_location")
                                },
                                "cross_references": val["cross_references"],
                                "recommendations": val["recommendations"]
                            }
                    
                    # Ajouter les validations aux vulnérabilités
                    for vuln in vulnerabilities_list:
                        vuln_id = vuln.get("vulnerability_id")
                        if vuln_id in validation_map:
                            vuln["validation"] = validation_map[vuln_id]
                        else:
                            # Validation par défaut si pas trouvée
                            vuln["validation"] = {
                                "is_valid": None,
                                "confidence_score": 0.0,
                                "risk_assessment": "UNKNOWN",
                                "evidence": {
                                    "validation_notes": "Validation non disponible"
                                }
                            }
                    
                    # On a trouvé le workflow correspondant à ce scan, inutile de continuer
                    break

                except Exception as e:
                    print(f"⚠️ Erreur lecture workflow {workflow_file}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            
            # Si on a trouvé le scan, ne pas chercher dans les autres dossiers
            if vulnerabilities_list or scan_info:
                break

        vulnerabilities_list.sort(
            key=lambda x: x.get("cvss_score", 0) or 0, reverse=True
        )
        
        print(f"✅ Retour de {len(vulnerabilities_list)} vulnérabilités pour scan_id={scan_id}")
        
        # Fallback : si aucun workflow trouvé, tenter de récupérer depuis la base SQLite
        if not vulnerabilities_list and not scan_info:
            print(f"⚠️ Aucun workflow trouvé pour scan_id={scan_id} – tentative de fallback via la base de données")
            try:
                conn = get_db_connection()
                cursor = conn.cursor()

                # Récupérer les vulnérabilités liées à ce scan dans la table de liaison
                rows = cursor.execute("""
                    SELECT v.*
                    FROM scan_vulnerabilities sv
                    JOIN vulnerabilities v ON v.vulnerability_id = sv.vulnerability_id
                    WHERE sv.scan_id = ?
                """, (scan_id,)).fetchall()

                if rows:
                    print(f"✅ Fallback DB: {len(rows)} vulnérabilités retrouvées pour scan_id={scan_id}")
                    for row in rows:
                        vuln_dict = dict(row)
                        vulnerabilities_list.append({
                            "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                            "name": vuln_dict.get("name", ""),
                            "severity": vuln_dict.get("severity", "MEDIUM"),
                            "cvss_score": vuln_dict.get("cvss_score"),
                            "description": vuln_dict.get("description", ""),
                            "affected_service": vuln_dict.get("affected_service", ""),
                            "affected_port": vuln_dict.get("affected_port"),
                            "status": "open",
                            "is_false_positive": False,
                            "false_positive_confidence": None,
                            "false_positive_reasoning": None,
                            "solution_links": [],
                            "primary_solution_link": None,
                            "references": json.loads(vuln_dict.get("refs") or "[]"),
                            "detection_location": vuln_dict.get("detection_method"),
                            "validation": {
                                "is_valid": None,
                                "confidence_score": 0.0,
                                "risk_assessment": "UNKNOWN",
                                "evidence": {
                                    "validation_notes": "Données chargées depuis la base, sans rapport de validation"
                                }
                            }
                        })

                    # Infos minimales de scan depuis la dernière entrée de liaison
                    scan_info = {
                        "scan_id": scan_id,
                        "workflow_id": None,
                        "target": "Unknown",
                        "scan_type": "unknown",
                        "started_at": None,
                        "completed_at": None,
                        "total_vulnerabilities": len(vulnerabilities_list),
                    }

                conn.close()
            except Exception as db_fallback_error:
                print(f"⚠️ Erreur lors du fallback DB pour scan_id={scan_id}: {db_fallback_error}")

        # Pagination pour les vulnérabilités d'un scan (workflow ou DB)
        total = len(vulnerabilities_list)
        page = 1
        page_size = min(limit, 100)  # Max 100 par page
        
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_vulns = vulnerabilities_list[start_idx:end_idx]
        
        # Récupérer le validation_summary depuis le dernier workflow_data lu (si disponible)
        validation_summary = None
        # Note: validation_report serait déjà dans validation_map, mais on peut le récupérer depuis workflow_data si besoin
        
        return {
            "scan_id": scan_id,
            "scan_info": scan_info,
            "vulnerabilities": paginated_vulns,
            "count": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 1,
            "validation_summary": validation_summary
        }

    except Exception as e:
        import traceback
        print(f"❌ Erreur dans get_scan_vulnerabilities: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
):
    """Liste des vulnérabilités avec filtres - Charge depuis DB et workflows"""

    try:
        vulnerabilities_list = []
        
        # D'abord essayer la base de données
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM vulnerabilities WHERE 1=1"
            params = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            if status:
                query += " AND status = ?"
                params.append(status)

            if search:
                query += " AND (vulnerability_id LIKE ? OR name LIKE ?)"
                params.extend([f"%{search}%", f"%{search}%"])

            query += " ORDER BY cvss_score DESC LIMIT ?"
            params.append(limit)

            db_vulns = cursor.execute(query, params).fetchall()
            vulnerabilities_list.extend([dict(vuln) for vuln in db_vulns])
            conn.close()
        except Exception as e:
            print(f"⚠️ Erreur lecture DB: {e}")
        
        # Ensuite charger depuis les workflows JSON (tous les emplacements possibles)
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        analysis_result = workflow_data.get("analysis_result")
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities", []) or []
                            if vulns:  # Vérifier que vulns n'est pas None
                                for vuln in vulns:
                                    vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                
                                # Vérifier les filtres
                                if severity and vuln_dict.get("severity") != severity:
                                    continue
                                if search and search.lower() not in str(vuln_dict.get("vulnerability_id", "")).lower() and search.lower() not in str(vuln_dict.get("name", "")).lower():
                                    continue
                                
                                # Normaliser le format
                                normalized_vuln = {
                                    "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                                    "name": vuln_dict.get("name", ""),
                                    "severity": vuln_dict.get("severity", "MEDIUM"),
                                    "cvss_score": vuln_dict.get("cvss_score"),
                                    "description": vuln_dict.get("description", ""),
                                    "affected_service": vuln_dict.get("affected_service", ""),
                                    "affected_port": vuln_dict.get("affected_port"),
                                    "status": "open",
                                    "is_false_positive": vuln_dict.get("is_false_positive", False),
                                    "false_positive_confidence": vuln_dict.get("false_positive_confidence"),
                                    "false_positive_reasoning": vuln_dict.get("false_positive_reasoning")
                                }
                                
                                # Éviter les doublons
                                if not any(v.get("vulnerability_id") == normalized_vuln["vulnerability_id"] for v in vulnerabilities_list):
                                    vulnerabilities_list.append(normalized_vuln)

                        # 🔽 Ajout : prendre aussi les vulnérabilités brutes du scan (scan_result)
                        scan_result = workflow_data.get("scan_result")
                        if scan_result:
                            vulns = scan_result.get("vulnerabilities", []) or []
                            if vulns:  # Vérifier que vulns n'est pas None
                                for vuln in vulns:
                                    vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}

                                    # Vérifier les filtres
                                    if severity and vuln_dict.get("severity") != severity:
                                        continue
                                    if search and search.lower() not in str(vuln_dict.get("vulnerability_id", "")).lower() and search.lower() not in str(vuln_dict.get("name", "")).lower():
                                        continue

                                    normalized_vuln = {
                                        "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                                        "name": vuln_dict.get("name", ""),
                                        "severity": vuln_dict.get("severity", "MEDIUM"),
                                        "cvss_score": vuln_dict.get("cvss_score"),
                                        "description": vuln_dict.get("description", ""),
                                        "affected_service": vuln_dict.get("affected_service", ""),
                                        "affected_port": vuln_dict.get("affected_port"),
                                        "status": "open",
                                        "is_false_positive": vuln_dict.get("is_false_positive", False),
                                        "false_positive_confidence": vuln_dict.get("false_positive_confidence"),
                                        "false_positive_reasoning": vuln_dict.get("false_positive_reasoning")
                                    }

                                    # Éviter les doublons avec celles déjà ajoutées (DB ou analysis_result)
                                    if not any(v.get("vulnerability_id") == normalized_vuln["vulnerability_id"] for v in vulnerabilities_list):
                                        vulnerabilities_list.append(normalized_vuln)
                except Exception as e:
                    print(f"⚠️ Erreur lecture workflow {workflow_file}: {e}")
                    continue
        
        # Trier par CVSS score
        vulnerabilities_list.sort(key=lambda x: x.get("cvss_score", 0) or 0, reverse=True)
        
        # Pagination
        total = len(vulnerabilities_list)
        page = 1
        page_size = limit if limit <= 100 else 50
        
        # Calculer les indices de pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_vulns = vulnerabilities_list[start_idx:end_idx]
        
        return {
            "vulnerabilities": paginated_vulns,
            "count": total,
            "page": page,
            "page_size": page_size,
            "total_pages": (total + page_size - 1) // page_size if page_size > 0 else 1
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/vulnerabilities/export/csv")
async def export_vulnerabilities_csv(
        scan_id: Optional[str] = None,
        severity: Optional[str] = None
):
    """Exporte les vulnérabilités en CSV"""
    try:
        vulnerabilities = []
        
        # Récupérer les vulnérabilités selon le scan_id ou toutes
        if scan_id:
            # Vulnérabilités d'un scan spécifique
            workflow_dirs = get_workflow_dirs()
            for workflows_dir in workflow_dirs:
                if not workflows_dir.exists():
                    continue
                for workflow_file in workflows_dir.glob("*.json"):
                    try:
                        with open(workflow_file, "r", encoding="utf-8") as f:
                            workflow_data = json.load(f)
                        workflow_id = workflow_file.stem
                        wf_scan_id = workflow_data.get("scan_id")
                        scan_result = workflow_data.get("scan_result") or {}
                        sr_scan_id = scan_result.get("scan_id")
                        
                        if scan_id not in (workflow_id, wf_scan_id, sr_scan_id):
                            continue
                        
                        # Récupérer les vulnérabilités
                        vulns = []
                        analysis_result = workflow_data.get("analysis_result") or {}
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities", []) or []
                        if not vulns and scan_result:
                            vulns = scan_result.get("vulnerabilities", []) or []
                        
                        for vuln in vulns:
                            vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, "to_dict") else {}
                            normalized_vuln = {
                                "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                                "name": vuln_dict.get("name", ""),
                                "severity": vuln_dict.get("severity", "MEDIUM"),
                                "cvss_score": vuln_dict.get("cvss_score"),
                                "description": vuln_dict.get("description", ""),
                                "affected_service": vuln_dict.get("affected_service", ""),
                                "affected_port": vuln_dict.get("affected_port"),
                                "status": "open",
                                "is_false_positive": vuln_dict.get("is_false_positive", False),
                                "false_positive_confidence": vuln_dict.get("false_positive_confidence"),
                            }
                            vulnerabilities.append(normalized_vuln)
                        break
                    except:
                        continue
        else:
            # Toutes les vulnérabilités
            for wf_dir in get_workflow_dirs():
                if not wf_dir.exists():
                    continue
                for workflow_file in wf_dir.glob("*.json"):
                    try:
                        with open(workflow_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                        
                        vulns = []
                        analysis_result = workflow_data.get("analysis_result")
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities", []) or []
                        if not vulns:
                            scan_result = workflow_data.get("scan_result")
                            if scan_result:
                                vulns = scan_result.get("vulnerabilities", []) or []
                        
                        for vuln in vulns:
                            if vuln:
                                vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                
                                if severity and vuln_dict.get("severity") != severity:
                                    continue
                                
                                normalized_vuln = {
                                    "vulnerability_id": vuln_dict.get("vulnerability_id", ""),
                                    "name": vuln_dict.get("name", ""),
                                    "severity": vuln_dict.get("severity", "MEDIUM"),
                                    "cvss_score": vuln_dict.get("cvss_score"),
                                    "description": vuln_dict.get("description", ""),
                                    "affected_service": vuln_dict.get("affected_service", ""),
                                    "affected_port": vuln_dict.get("affected_port"),
                                    "status": "open",
                                    "is_false_positive": vuln_dict.get("is_false_positive", False),
                                    "false_positive_confidence": vuln_dict.get("false_positive_confidence"),
                                }
                                
                                if not any(v.get("vulnerability_id") == normalized_vuln["vulnerability_id"] for v in vulnerabilities):
                                    vulnerabilities.append(normalized_vuln)
                    except:
                        continue
        
        # Créer le CSV en mémoire
        output = io.StringIO()
        writer = csv.writer(output)
        
        # En-têtes
        writer.writerow([
            "CVE ID", "Nom", "Sévérité", "CVSS", "Service", "Port",
            "Description", "Faux Positif", "Confiance FP", "Statut"
        ])
        
        # Données
        for vuln in vulnerabilities:
            writer.writerow([
                vuln.get("vulnerability_id", ""),
                vuln.get("name", ""),
                vuln.get("severity", ""),
                vuln.get("cvss_score", ""),
                vuln.get("affected_service", ""),
                vuln.get("affected_port", ""),
                (vuln.get("description", "") or "").replace("\n", " ").replace("\r", "")[:200],
                "Oui" if vuln.get("is_false_positive") else "Non",
                f"{vuln.get('false_positive_confidence', 0) * 100:.1f}%" if vuln.get("false_positive_confidence") else "",
                vuln.get("status", "open")
            ])
        
        # Retourner le CSV
        csv_content = output.getvalue()
        output.close()
        
        filename = f"vulnerabilities_{scan_id or 'all'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erreur export CSV: {str(e)}")


@app.get("/api/vulnerabilities/{vuln_id}")
async def get_vulnerability_details(vuln_id: str):
    """Détails d'une vulnérabilité"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        vuln = cursor.execute(
            "SELECT * FROM vulnerabilities WHERE vulnerability_id = ?",
            (vuln_id,)
        ).fetchone()

        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnérabilité non trouvée")

        # Récupérer les scripts de remédiation associés
        scripts = cursor.execute(
            "SELECT * FROM remediation_scripts WHERE vulnerability_id = ?",
            (vuln_id,)
        ).fetchall()

        conn.close()

        return {
            "vulnerability": dict(vuln),
            "remediation_scripts": [dict(script) for script in scripts]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scripts")
async def get_scripts(
        limit: int = 50,
        status: Optional[str] = None
):
    """Liste des scripts de remédiation - Charge depuis DB et workflows"""

    try:
        scripts_list = []
        
        # D'abord essayer la base de données
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM scripts"
            params = []

            if status:
                query += " WHERE validation_status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            db_scripts = cursor.execute(query, params).fetchall()
            scripts_list.extend([dict(script) for script in db_scripts])
            conn.close()
        except Exception as e:
            print(f"⚠️ Erreur lecture DB scripts: {e}")
        
        # Ensuite charger depuis les workflows JSON (tous les emplacements possibles)
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        script_results = workflow_data.get("script_results") or []
                        if isinstance(script_results, list) and script_results:
                            for script in script_results:
                                script_dict = script if isinstance(script, dict) else script.to_dict() if hasattr(script, 'to_dict') else {}
                                
                                # Normaliser le format
                                normalized_script = {
                                    "script_id": script_dict.get("script_id", ""),
                                    "vulnerability_id": script_dict.get("vulnerability_id", ""),
                                    "target_system": script_dict.get("target_system", "ubuntu"),
                                    "script_type": script_dict.get("script_type", "bash"),
                                    "script_content": script_dict.get("script_content", ""),
                                    "rollback_script": script_dict.get("rollback_script", ""),
                                    "ai_model_used": script_dict.get("ai_model_used", ""),
                                    "validation_status": "pending",
                                    "risk_level": "medium",
                                    "generated_at": workflow_data.get("completed_at", workflow_data.get("started_at"))
                                }
                                
                                # Éviter les doublons
                                if not any(s.get("script_id") == normalized_script["script_id"] for s in scripts_list):
                                    scripts_list.append(normalized_script)
                except Exception as e:
                    print(f"⚠️ Erreur lecture workflow {workflow_file}: {e}")
                    continue
        
        return {
            "scripts": scripts_list[:limit],
            "count": len(scripts_list)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows")
async def get_workflows(limit: int = 20):
    """Liste des workflows complets"""

    try:
        workflows = []

        workflow_files = []
        for wf_dir in get_workflow_dirs():
            if wf_dir.exists():
                workflow_files.extend(list(wf_dir.glob("*.json")))

        if workflow_files:
            workflow_files = sorted(
                workflow_files,
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )[:limit]

            for workflow_file in workflow_files:
                with open(workflow_file, 'r', encoding='utf-8') as f:
                    workflow_data = json.load(f)

                    # Extraire seulement les infos principales
                    workflows.append({
                        "workflow_id": workflow_data.get("workflow_id"),
                        "workflow_type": workflow_data.get("workflow_type"),
                        "target": workflow_data.get("target"),
                        "status": workflow_data.get("status"),
                        "started_at": workflow_data.get("started_at"),
                        "completed_at": workflow_data.get("completed_at"),
                        "duration": workflow_data.get("duration"),
                        "total_vulnerabilities": workflow_data.get("total_vulnerabilities", 0),
                        "critical_vulnerabilities": workflow_data.get("critical_vulnerabilities", 0),
                        "scripts_generated": workflow_data.get("scripts_generated", 0)
                    })

        return {
            "workflows": workflows,
            "count": len(workflows)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows/{workflow_id}")
async def get_workflow_details(workflow_id: str):
    """Détails complets d'un workflow"""

    workflow_data = load_workflow_result(workflow_id)

    if not workflow_data:
        raise HTTPException(status_code=404, detail="Workflow non trouvé")

    return workflow_data


@app.get("/api/stats/top-vulnerabilities")
async def get_top_vulnerabilities(limit: int = 10):
    """Top vulnérabilités les plus critiques"""

    try:
        # Essayer depuis la DB d'abord
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            top_vulns = cursor.execute("""
                SELECT 
                    vulnerability_id,
                    name,
                    severity,
                    cvss_score,
                    affected_service
                FROM vulnerabilities
                ORDER BY 
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END,
                    cvss_score DESC NULLS LAST
                LIMIT ?
            """, (limit,)).fetchall()

            conn.close()

            return {
                "vulnerabilities": [dict(vuln) for vuln in top_vulns]
            }
        except Exception as db_error:
            # Fallback : calculer depuis les workflows JSON
            all_vulns = []
            
            for wf_dir in get_workflow_dirs():
                for workflow_file in wf_dir.glob("*.json"):
                    try:
                        with open(workflow_file, 'r', encoding='utf-8') as f:
                            workflow_data = json.load(f)
                        
                        # Chercher dans analysis_result puis scan_result
                        vulns = []
                        analysis_result = workflow_data.get("analysis_result")
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities", []) or []
                        
                        if not vulns:
                            scan_result = workflow_data.get("scan_result")
                            if scan_result:
                                vulns = scan_result.get("vulnerabilities", []) or []
                        
                        for vuln in vulns:
                            if vuln:
                                vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                vuln_id = vuln_dict.get("vulnerability_id")
                                if vuln_id and not any(v.get("vulnerability_id") == vuln_id for v in all_vulns):
                                    all_vulns.append({
                                        "vulnerability_id": vuln_id,
                                        "name": vuln_dict.get("name", ""),
                                        "severity": vuln_dict.get("severity", "MEDIUM"),
                                        "cvss_score": vuln_dict.get("cvss_score"),
                                        "affected_service": vuln_dict.get("affected_service", "")
                                    })
                    except:
                        continue
            
            # Trier par sévérité puis CVSS
            severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
            all_vulns.sort(key=lambda v: (
                severity_order.get(v.get("severity", "UNKNOWN").upper(), 5),
                -(v.get("cvss_score") or 0)
            ))
            
            return {
                "vulnerabilities": all_vulns[:limit]
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===== DÉMARRAGE =====

# === MODÈLES PYDANTIC POUR LES GROUPES ===

class VulnerabilityGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    vulnerability_ids: List[str]


class VulnerabilityGroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    vulnerability_ids: Optional[List[str]] = None


# === ENDPOINTS GROUPES DE VULNÉRABILITÉS ===

@app.post("/api/vulnerability-groups")
async def create_vulnerability_group(group: VulnerabilityGroupCreate):
    """Crée un nouveau groupe de vulnérabilités personnalisé"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        group_id = f"group_{uuid.uuid4().hex[:12]}"
        
        cursor.execute("""
            INSERT INTO vulnerability_groups (group_id, name, description, vulnerability_ids)
            VALUES (?, ?, ?, ?)
        """, (
            group_id,
            group.name,
            group.description or "",
            json.dumps(group.vulnerability_ids)
        ))
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "group_id": group_id,
            "message": "Groupe créé avec succès"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/vulnerability-groups")
async def list_vulnerability_groups():
    """Liste tous les groupes de vulnérabilités"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        groups = cursor.execute("""
            SELECT * FROM vulnerability_groups
            ORDER BY created_at DESC
        """).fetchall()
        
        conn.close()
        
        result = []
        for group in groups:
            result.append({
                "group_id": group['group_id'],
                "name": group['name'],
                "description": group['description'],
                "vulnerability_ids": json.loads(group['vulnerability_ids']),
                "vulnerability_count": len(json.loads(group['vulnerability_ids'])),
                "created_at": group['created_at'],
                "updated_at": group['updated_at']
            })
        
        return {
            "groups": result,
            "count": len(result)
        }
    except Exception as e:
        return {"groups": [], "count": 0}


@app.get("/api/vulnerability-groups/{group_id}")
async def get_vulnerability_group(group_id: str):
    """Récupère un groupe de vulnérabilités"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        group = cursor.execute("""
            SELECT * FROM vulnerability_groups WHERE group_id = ?
        """, (group_id,)).fetchone()
        
        conn.close()
        
        if not group:
            raise HTTPException(status_code=404, detail="Groupe non trouvé")
        
        return {
            "group_id": group['group_id'],
            "name": group['name'],
            "description": group['description'],
            "vulnerability_ids": json.loads(group['vulnerability_ids']),
            "created_at": group['created_at'],
            "updated_at": group['updated_at']
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/vulnerability-groups/{group_id}")
async def update_vulnerability_group(group_id: str, group_update: VulnerabilityGroupUpdate):
    """Met à jour un groupe de vulnérabilités"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        existing = cursor.execute("""
            SELECT * FROM vulnerability_groups WHERE group_id = ?
        """, (group_id,)).fetchone()
        
        if not existing:
            raise HTTPException(status_code=404, detail="Groupe non trouvé")
        
        updates = []
        params = []
        
        if group_update.name is not None:
            updates.append("name = ?")
            params.append(group_update.name)
        
        if group_update.description is not None:
            updates.append("description = ?")
            params.append(group_update.description)
        
        if group_update.vulnerability_ids is not None:
            updates.append("vulnerability_ids = ?")
            params.append(json.dumps(group_update.vulnerability_ids))
        
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(group_id)
            
            cursor.execute(f"""
                UPDATE vulnerability_groups
                SET {', '.join(updates)}
                WHERE group_id = ?
            """, params)
            
            conn.commit()
        
        conn.close()
        
        return {"success": True, "message": "Groupe mis à jour avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/vulnerability-groups/{group_id}")
async def delete_vulnerability_group(group_id: str):
    """Supprime un groupe de vulnérabilités"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM vulnerability_groups WHERE group_id = ?
        """, (group_id,))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Groupe non trouvé")
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "Groupe supprimé avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === ENDPOINTS HISTORIQUE DES ANALYSES IA ===

@app.get("/api/analysis-history")
async def get_analysis_history(limit: int = 20):
    """Récupère l'historique des analyses IA"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        analyses = cursor.execute("""
            SELECT * FROM analysis_history
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        conn.close()
        
        result = []
        for analysis in analyses:
            result.append({
                "analysis_id": analysis['analysis_id'],
                "workflow_id": analysis['workflow_id'],
                "target_system": analysis['target_system'],
                "vulnerability_ids": json.loads(analysis['vulnerability_ids']),
                "vulnerability_count": len(json.loads(analysis['vulnerability_ids'])),
                "ai_model_used": analysis['ai_model_used'],
                "analysis_summary": json.loads(analysis['analysis_summary']) if analysis['analysis_summary'] else {},
                "remediation_plan": json.loads(analysis['remediation_plan']) if analysis['remediation_plan'] else {},
                "confidence_score": analysis['confidence_score'],
                "processing_time": analysis['processing_time'],
                "analyzed_at": analysis['analyzed_at']
            })
        
        return {"analyses": result, "count": len(result)}
    except Exception as e:
        # Fallback : chercher dans les workflows JSON
        analyses = []
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in sorted(wf_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                    
                    analysis_result = workflow_data.get("analysis_result")
                    if analysis_result:
                        vulns = analysis_result.get("vulnerabilities", []) or []
                        analyses.append({
                            "analysis_id": analysis_result.get("analysis_id", workflow_data.get("workflow_id", "")),
                            "workflow_id": workflow_data.get("workflow_id"),
                            "target_system": workflow_data.get("target", "Unknown"),
                            "vulnerability_ids": [v.get("vulnerability_id", "") for v in vulns if isinstance(v, dict) and v.get("vulnerability_id")],
                            "vulnerability_count": len(vulns),
                            "ai_model_used": analysis_result.get("ai_model_used", "unknown"),
                            "analysis_summary": analysis_result.get("analysis_summary", {}),
                            "remediation_plan": analysis_result.get("remediation_plan", {}),
                            "confidence_score": analysis_result.get("confidence_score", 0.0),
                            "processing_time": analysis_result.get("processing_time", 0.0),
                            "analyzed_at": workflow_data.get("completed_at", workflow_data.get("started_at", ""))
                        })
                except:
                    continue
        
        return {"analyses": analyses[:limit], "count": len(analyses)}


@app.get("/api/analysis-history/{analysis_id}")
async def get_analysis_details(analysis_id: str):
    """Récupère les détails d'une analyse IA spécifique"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        analysis = cursor.execute("""
            SELECT * FROM analysis_history WHERE analysis_id = ?
        """, (analysis_id,)).fetchone()
        
        conn.close()
        
        if analysis:
            return {
                "analysis_id": analysis['analysis_id'],
                "workflow_id": analysis['workflow_id'],
                "target_system": analysis['target_system'],
                "vulnerability_ids": json.loads(analysis['vulnerability_ids']),
                "ai_model_used": analysis['ai_model_used'],
                "analysis_summary": json.loads(analysis['analysis_summary']) if analysis['analysis_summary'] else {},
                "remediation_plan": json.loads(analysis['remediation_plan']) if analysis['remediation_plan'] else {},
                "confidence_score": analysis['confidence_score'],
                "processing_time": analysis['processing_time'],
                "analyzed_at": analysis['analyzed_at']
            }
        
        # Fallback : chercher dans les workflows JSON
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                    
                    analysis_result = workflow_data.get("analysis_result")
                    if analysis_result and analysis_result.get("analysis_id") == analysis_id:
                        vulns = analysis_result.get("vulnerabilities", []) or []
                        return {
                            "analysis_id": analysis_id,
                            "workflow_id": workflow_data.get("workflow_id"),
                            "target_system": workflow_data.get("target", "Unknown"),
                            "vulnerability_ids": [v.get("vulnerability_id", "") for v in vulns if isinstance(v, dict) and v.get("vulnerability_id")],
                            "ai_model_used": analysis_result.get("ai_model_used", "unknown"),
                            "analysis_summary": analysis_result.get("analysis_summary", {}),
                            "remediation_plan": analysis_result.get("remediation_plan", {}),
                            "confidence_score": analysis_result.get("confidence_score", 0.0),
                            "processing_time": analysis_result.get("processing_time", 0.0),
                            "analyzed_at": workflow_data.get("completed_at", workflow_data.get("started_at", ""))
                        }
                except:
                    continue
        
        raise HTTPException(status_code=404, detail="Analyse non trouvée")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === INSTANCE GLOBALE DU SUPERVISEUR ===

supervisor_instance: Optional[Any] = None
active_scans: Dict[str, Dict[str, Any]] = {}  # Stockage des scans actifs

# Cache global pour les enrichissements NIST (évite les appels répétés)
nist_cache: Dict[str, Dict[str, Any]] = {}

# Cache global pour les plans de mises à jour (évite de recalculer l'algo)
upgrade_plan_cache: Dict[str, Dict[str, Any]] = {}

def get_or_create_supervisor():
    """Récupère ou crée l'instance globale du Supervisor"""
    global supervisor_instance
    if supervisor_instance is None:
        try:
            from config import get_config
            from src.core.supervisor import Supervisor, WorkflowType
            config = get_config()
            supervisor_instance = Supervisor(config)
            print("✅ Superviseur initialisé")
        except Exception as e:
            print(f"⚠️ Erreur initialisation Supervisor: {e}")
            raise HTTPException(status_code=500, detail=f"Impossible d'initialiser le Supervisor: {str(e)}")
    return supervisor_instance


# === MODÈLES PYDANTIC POUR L'ANALYSE ET LA CORRECTION ===

class AnalyzeSelectedRequest(BaseModel):
    """Requête pour analyser des CVEs sélectionnées"""
    vulnerability_ids: List[str]
    target_system: Optional[str] = "Unknown System"
    business_context: Optional[str] = None


class CorrectSelectedRequest(BaseModel):
    """Requête pour corriger des CVEs sélectionnées"""
    vulnerability_ids: List[str]
    target_system: Optional[str] = "ubuntu"


class ScanLaunchRequest(BaseModel):
    """Requête de lancement de scan"""
    target: str
    scan_type: str = "full"
    workflow_type: str = "full"
    script_type: str = "bash"


# === ENDPOINTS ANALYSE ===

@app.post("/api/analyze/group/{group_id}")
async def analyze_group(group_id: str, target_system: Optional[str] = None):
    """Analyse un groupe de vulnérabilités avec l'IA"""
    try:
        # Récupérer le groupe depuis la DB
        conn = get_db_connection()
        cursor = conn.cursor()
        
        group = cursor.execute("""
            SELECT * FROM vulnerability_groups WHERE group_id = ?
        """, (group_id,)).fetchone()
        
        if not group:
            conn.close()
            raise HTTPException(status_code=404, detail="Groupe non trouvé")
        
        vulnerability_ids = json.loads(group['vulnerability_ids'])
        conn.close()
        
        if not vulnerability_ids:
            raise HTTPException(status_code=400, detail="Le groupe ne contient aucune vulnérabilité")
        
        # Récupérer les détails des vulnérabilités depuis les workflows ou la DB
        vulnerabilities_data = []
        
        # Chercher dans les workflows JSON d'abord
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                    
                    # Chercher dans analysis_result puis scan_result
                    vulns = []
                    analysis_result = workflow_data.get("analysis_result")
                    if analysis_result:
                        vulns = analysis_result.get("vulnerabilities", []) or []
                    
                    if not vulns:
                        scan_result = workflow_data.get("scan_result")
                        if scan_result:
                            vulns = scan_result.get("vulnerabilities", []) or []
                    
                    for vuln in vulns:
                        vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                        vuln_id = vuln_dict.get("vulnerability_id")
                        if vuln_id and vuln_id in vulnerability_ids:
                            vulnerabilities_data.append(vuln_dict)
                            if len(vulnerabilities_data) >= len(vulnerability_ids):
                                break
                    
                    if len(vulnerabilities_data) >= len(vulnerability_ids):
                        break
                except:
                    continue
            
            if len(vulnerabilities_data) >= len(vulnerability_ids):
                break
        
        # Si pas assez trouvé, chercher dans la DB
        if len(vulnerabilities_data) < len(vulnerability_ids):
            conn = get_db_connection()
            cursor = conn.cursor()
            for vuln_id in vulnerability_ids:
                if not any(v.get("vulnerability_id") == vuln_id for v in vulnerabilities_data):
                    vuln = cursor.execute("""
                        SELECT * FROM vulnerabilities WHERE vulnerability_id = ?
                    """, (vuln_id,)).fetchone()
                    if vuln:
                        vulnerabilities_data.append(dict(vuln))
            conn.close()
        
        if not vulnerabilities_data:
            raise HTTPException(status_code=404, detail="Aucune vulnérabilité trouvée pour ce groupe")
        
        # Initialiser le Supervisor et lancer l'analyse
        supervisor = get_supervisor_instance()
        try:
            analysis_result = await supervisor.analyze_vulnerabilities(
                vulnerabilities_data=vulnerabilities_data,
                target_system=target_system or group.get('name', 'Unknown System')
            )
            
            # Sauvegarder dans analysis_history
            analysis_id = analysis_result.analysis_id
            vulnerability_ids_analyzed = [v.vulnerability_id for v in analysis_result.vulnerabilities]
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Vérifier si la table existe, sinon la créer
            try:
                cursor.execute("""
                    INSERT INTO analysis_history (
                        analysis_id, workflow_id, target_system, vulnerability_ids,
                        ai_model_used, analysis_summary, remediation_plan,
                        confidence_score, processing_time, analyzed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    f"group_{group_id}",
                    target_system or group.get('name', 'Unknown System'),
                    json.dumps(vulnerability_ids_analyzed),
                    analysis_result.ai_model_used,
                    json.dumps(analysis_result.analysis_summary),
                    json.dumps(analysis_result.remediation_plan),
                    analysis_result.confidence_score,
                    analysis_result.processing_time,
                    datetime.utcnow().isoformat()
                ))
                conn.commit()
            except sqlite3.OperationalError as e:
                # Table n'existe peut-être pas encore
                print(f"⚠️ Table analysis_history non disponible: {e}")
            
            conn.close()
            
            return {
                "success": True,
                "analysis_id": analysis_id,
                "vulnerability_count": len(vulnerability_ids_analyzed),
                "message": f"Analyse terminée pour {len(vulnerability_ids_analyzed)} vulnérabilités"
            }
        finally:
            await supervisor.shutdown()
            
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'analyse: {str(e)}")


@app.post("/api/analyze/selected")
async def analyze_selected(request: AnalyzeSelectedRequest):
    """Analyse des CVEs sélectionnées avec l'IA"""
    try:
        if not request.vulnerability_ids:
            raise HTTPException(status_code=400, detail="Aucune vulnérabilité sélectionnée")
        
        # Récupérer les détails des vulnérabilités
        vulnerabilities_data = []
        
        # Chercher dans les workflows JSON d'abord
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                    
                    # Chercher dans analysis_result puis scan_result
                    vulns = []
                    analysis_result = workflow_data.get("analysis_result")
                    if analysis_result:
                        vulns = analysis_result.get("vulnerabilities", []) or []
                    
                    if not vulns:
                        scan_result = workflow_data.get("scan_result")
                        if scan_result:
                            vulns = scan_result.get("vulnerabilities", []) or []
                    
                    for vuln in vulns:
                        vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                        vuln_id = vuln_dict.get("vulnerability_id")
                        if vuln_id and vuln_id in request.vulnerability_ids:
                            vulnerabilities_data.append(vuln_dict)
                            if len(vulnerabilities_data) >= len(request.vulnerability_ids):
                                break
                    
                    if len(vulnerabilities_data) >= len(request.vulnerability_ids):
                        break
                except:
                    continue
            
            if len(vulnerabilities_data) >= len(request.vulnerability_ids):
                break
        
        # Si pas assez trouvé, chercher dans la DB
        if len(vulnerabilities_data) < len(request.vulnerability_ids):
            conn = get_db_connection()
            cursor = conn.cursor()
            for vuln_id in request.vulnerability_ids:
                if not any(v.get("vulnerability_id") == vuln_id for v in vulnerabilities_data):
                    vuln = cursor.execute("""
                        SELECT * FROM vulnerabilities WHERE vulnerability_id = ?
                    """, (vuln_id,)).fetchone()
                    if vuln:
                        vulnerabilities_data.append(dict(vuln))
            conn.close()
        
        if not vulnerabilities_data:
            raise HTTPException(status_code=404, detail="Aucune vulnérabilité trouvée")
        
        # Initialiser le Supervisor et lancer l'analyse
        supervisor = get_supervisor_instance()
        try:
            analysis_result = await supervisor.analyze_vulnerabilities(
                vulnerabilities_data=vulnerabilities_data,
                target_system=request.target_system
            )
            
            # Sauvegarder dans analysis_history
            analysis_id = analysis_result.analysis_id
            vulnerability_ids_analyzed = [v.vulnerability_id for v in analysis_result.vulnerabilities]
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                    INSERT INTO analysis_history (
                        analysis_id, workflow_id, target_system, vulnerability_ids,
                        ai_model_used, analysis_summary, remediation_plan,
                        confidence_score, processing_time, analyzed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    analysis_id,
                    f"selected_{uuid.uuid4().hex[:12]}",
                    request.target_system,
                    json.dumps(vulnerability_ids_analyzed),
                    analysis_result.ai_model_used,
                    json.dumps(analysis_result.analysis_summary),
                    json.dumps(analysis_result.remediation_plan),
                    analysis_result.confidence_score,
                    analysis_result.processing_time,
                    datetime.utcnow().isoformat()
                ))
                conn.commit()
            except sqlite3.OperationalError as e:
                print(f"⚠️ Table analysis_history non disponible: {e}")
            
            conn.close()
            
            return {
                "success": True,
                "analysis_id": analysis_id,
                "vulnerability_count": len(vulnerability_ids_analyzed),
                "message": f"Analyse terminée pour {len(vulnerability_ids_analyzed)} vulnérabilités"
            }
        finally:
            await supervisor.shutdown()
            
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'analyse: {str(e)}")


@app.get("/api/analysis/{analysis_id}/vulnerabilities")
async def get_analysis_vulnerabilities(analysis_id: str):
    """Récupère la liste des CVEs analysées pour une analyse spécifique"""
    try:
        # Chercher dans la DB d'abord
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            analysis = cursor.execute("""
                SELECT * FROM analysis_history WHERE analysis_id = ?
            """, (analysis_id,)).fetchone()
            
            if analysis:
                vulnerability_ids = json.loads(analysis['vulnerability_ids'])
                conn.close()
                
                # Récupérer les détails de chaque vulnérabilité
                vulnerabilities = []
                for wf_dir in get_workflow_dirs():
                    if not wf_dir.exists():
                        continue
                    for workflow_file in wf_dir.glob("*.json"):
                        try:
                            with open(workflow_file, 'r', encoding='utf-8') as f:
                                workflow_data = json.load(f)
                            
                            analysis_result = workflow_data.get("analysis_result")
                            if analysis_result and analysis_result.get("analysis_id") == analysis_id:
                                vulns = analysis_result.get("vulnerabilities", []) or []
                                for vuln in vulns:
                                    vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                                    if vuln_dict.get("vulnerability_id") in vulnerability_ids:
                                        vulnerabilities.append(vuln_dict)
                                
                                if len(vulnerabilities) >= len(vulnerability_ids):
                                    break
                        except:
                            continue
                    
                    if len(vulnerabilities) >= len(vulnerability_ids):
                        break
                
                return {
                    "analysis_id": analysis_id,
                    "vulnerabilities": vulnerabilities,
                    "count": len(vulnerabilities)
                }
        except sqlite3.OperationalError:
            pass
        
        conn.close()
        
        # Fallback : chercher dans les workflows JSON
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in wf_dir.glob("*.json"):
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                    
                    analysis_result = workflow_data.get("analysis_result")
                    if analysis_result and analysis_result.get("analysis_id") == analysis_id:
                        vulns = analysis_result.get("vulnerabilities", []) or []
                        vulnerabilities = []
                        for vuln in vulns:
                            vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                            vulnerabilities.append(vuln_dict)
                        
                        return {
                            "analysis_id": analysis_id,
                            "vulnerabilities": vulnerabilities,
                            "count": len(vulnerabilities)
                        }
                except:
                    continue
        
        raise HTTPException(status_code=404, detail="Analyse non trouvée")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === ENDPOINTS CORRECTION ===

@app.post("/api/correct/selected")
async def correct_selected(request: CorrectSelectedRequest):
    """Génère des scripts de correction pour des CVEs sélectionnées"""
    try:
        if not request.vulnerability_ids:
            raise HTTPException(status_code=400, detail="Aucune vulnérabilité sélectionnée")
        
        # Initialiser le Supervisor
        supervisor = get_supervisor_instance()
        scripts_generated = []
        
        try:
            for vuln_id in request.vulnerability_ids:
                try:
                    script_result = await supervisor.generate_fix_script(
                        vulnerability_id=vuln_id,
                        target_system=request.target_system
                    )
                    
                    if script_result:
                        scripts_generated.append({
                            "vulnerability_id": vuln_id,
                            "script_id": script_result.script_id,
                            "script_content": script_result.fix_script,
                            "rollback_script": script_result.rollback_script or "",
                            "validation_status": script_result.validation_status,
                            "risk_level": script_result.risk_level,
                            "target_system": script_result.target_system,
                            "script_type": script_result.script_type,
                            "generated_at": script_result.generated_at.isoformat() if hasattr(script_result.generated_at, 'isoformat') else str(script_result.generated_at)
                        })
                except Exception as e:
                    print(f"⚠️ Erreur génération script pour {vuln_id}: {e}")
                    scripts_generated.append({
                        "vulnerability_id": vuln_id,
                        "error": str(e)
                    })
            
            return {
                "success": True,
                "scripts_generated": scripts_generated,
                "count": len([s for s in scripts_generated if "error" not in s]),
                "message": f"Scripts générés pour {len([s for s in scripts_generated if 'error' not in s])}/{len(request.vulnerability_ids)} vulnérabilités"
            }
        finally:
            await supervisor.shutdown()
            
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération des scripts: {str(e)}")


# === ENDPOINTS SCAN ===

@app.post("/api/v2/scans/launch")
async def launch_scan(request: ScanLaunchRequest, background_tasks: BackgroundTasks):
    """Lance un nouveau scan de vulnérabilités"""
    try:
        # Valider la cible
        if not request.target:
            raise HTTPException(status_code=400, detail="La cible est requise")
        
        # Générer un ID unique pour le scan
        scan_id = str(uuid.uuid4())
        
        # Mapper le workflow_type
        from src.core.supervisor import WorkflowType
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
        
        # Récupérer ou créer le superviseur
        supervisor = get_or_create_supervisor()
        
        # Lancer le workflow en arrière-plan
        background_tasks.add_task(
            run_scan_workflow_task,
            scan_id,
            request.target,
            request.scan_type,
            workflow_type,
            request.script_type
        )
        
        print(f"✅ Scan lancé: {scan_id} pour {request.target}")
        
        return {
            "success": True,
            "scan_id": scan_id,
            "message": "Scan lancé avec succès",
            "workflow_id": None
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"❌ Erreur lancement scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def run_scan_workflow_task(
    scan_id: str,
    target: str,
    scan_type: str,
    workflow_type: Any,
    script_type: str = "bash"
):
    """Exécute un workflow de scan en arrière-plan"""
    try:
        from src.core.supervisor import WorkflowType
        supervisor = get_or_create_supervisor()
        
        # Mettre à jour le statut
        if scan_id in active_scans:
            active_scans[scan_id].update({
                "status": "running",
                "progress": 5,
                "current_step": "Initialisation",
                "message": "Démarrage du scan..."
            })
        
        # Lancer le workflow via le superviseur
        workflow_id = await supervisor.start_workflow(
            workflow_type=workflow_type,
            target=target,
            parameters={
                "scan_type": scan_type,
                "script_type": script_type
            },
            created_by="dashboard"
        )
        
        if scan_id in active_scans:
            active_scans[scan_id]["workflow_id"] = workflow_id
        
        print(f"✅ Workflow créé: {workflow_id} pour scan {scan_id}")
        
        # Sauvegarder le scan_id dans le fichier workflow dès qu'il est créé
        # (même si le workflow n'est pas encore terminé)
        try:
            from pathlib import Path
            workflow_dirs = get_workflow_dirs()
            for wf_dir in workflow_dirs:
                if not wf_dir.exists():
                    continue
                workflow_file = wf_dir / f"{workflow_id}.json"
                if workflow_file.exists():
                    # Lire, modifier et sauvegarder
                    with open(workflow_file, 'r+', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        workflow_data["scan_id"] = scan_id  # Sauvegarder le scan_id
                        f.seek(0)
                        json.dump(workflow_data, f, indent=2, ensure_ascii=False)
                        f.truncate()
                    print(f"✅ scan_id sauvegardé dans workflow {workflow_id}")
                    break
        except Exception as e:
            print(f"⚠️ Impossible de sauvegarder scan_id dans workflow: {e}")
        
        # Mettre à jour la progression pendant l'exécution
        if scan_id in active_scans:
            active_scans[scan_id].update({
                "progress": 20,
                "current_step": "Scan Nmap",
                "message": "Scan en cours..."
            })
        
        # Attendre la fin du workflow
        result = await supervisor.wait_for_workflow(workflow_id, timeout=3600)
        
        # S'assurer que le scan_id est bien dans le fichier workflow final
        try:
            from pathlib import Path
            workflow_dirs = get_workflow_dirs()
            for wf_dir in workflow_dirs:
                if not wf_dir.exists():
                    continue
                workflow_file = wf_dir / f"{workflow_id}.json"
                if workflow_file.exists():
                    with open(workflow_file, 'r+', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        workflow_data["scan_id"] = scan_id  # S'assurer que scan_id est présent
                        f.seek(0)
                        json.dump(workflow_data, f, indent=2, ensure_ascii=False)
                        f.truncate()
                    print(f"✅ scan_id final sauvegardé dans workflow {workflow_id}")
                    break
        except Exception as e:
            print(f"⚠️ Impossible de sauvegarder scan_id final: {e}")
        
        # Mettre à jour le statut final
        if scan_id in active_scans:
            active_scans[scan_id].update({
                "status": "completed",
                "progress": 100,
                "current_step": "Terminé",
                "message": "Scan terminé avec succès",
                "estimated_time_remaining": 0,
                "vulnerabilities_found": result.total_vulnerabilities if result else 0
            })
        
        print(f"✅ Scan terminé: {scan_id}, workflow: {workflow_id}")
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        if scan_id in active_scans:
            active_scans[scan_id].update({
                "status": "failed",
                "progress": 0,
                "current_step": "Erreur",
                "message": f"Erreur: {str(e)}",
                "estimated_time_remaining": 0
            })
        print(f"❌ Erreur scan {scan_id}: {e}")


@app.get("/api/v2/scans")
async def list_scans_v2(limit: int = 50):
    """Liste tous les scans (compatible avec scan_api)"""
    try:
        scans_list = []
        
        # Charger depuis les fichiers workflow
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            for workflow_file in sorted(wf_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                try:
                    with open(workflow_file, 'r', encoding='utf-8') as f:
                        workflow_data = json.load(f)
                        workflow_id = workflow_file.stem
                        
                        scan_result = workflow_data.get("scan_result", {})
                        analysis_result = workflow_data.get("analysis_result", {})
                        
                        # Compter les vulnérabilités
                        vulnerabilities_count = 0
                        if analysis_result:
                            vulns = analysis_result.get("vulnerabilities") or []
                            if isinstance(vulns, list):
                                vulnerabilities_count = len(vulns)
                        elif scan_result:
                            vulns = scan_result.get("vulnerabilities") or []
                            if isinstance(vulns, list):
                                vulnerabilities_count = len(vulns)
                        
                        scans_list.append({
                            "scan_id": workflow_id,
                            "target": workflow_data.get("target", "N/A"),
                            "scan_type": workflow_data.get("workflow_type", "unknown"),
                            "status": "completed",
                            "progress": 100,
                            "current_step": "Terminé",
                            "started_at": workflow_data.get("started_at", workflow_data.get("created_at")),
                            "completed_at": workflow_data.get("completed_at"),
                            "vulnerabilities_found": vulnerabilities_count,
                            "workflow_id": workflow_id
                        })
                except Exception as e:
                    print(f"⚠️ Erreur lecture workflow {workflow_file}: {e}")
                    continue
        
        # Trier par date (plus récent en premier)
        scans_list.sort(key=lambda x: x.get("started_at", ""), reverse=True)
        
        return {
            "scans": scans_list[:limit],
            "count": len(scans_list),
            "active_count": 0
        }
    except Exception as e:
        print(f"❌ Erreur liste scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/scans/{scan_id}/status")
async def get_scan_status_v2(scan_id: str):
    """Récupère le statut d'un scan"""
    try:
        # D'abord vérifier dans les scans actifs
        if scan_id in active_scans:
            return active_scans[scan_id]
        
        # Chercher dans les fichiers workflow (scans terminés)
        for wf_dir in get_workflow_dirs():
            if not wf_dir.exists():
                continue
            workflow_file = wf_dir / f"{scan_id}.json"
            if workflow_file.exists():
                with open(workflow_file, 'r', encoding='utf-8') as f:
                    workflow_data = json.load(f)
                    return {
                        "scan_id": scan_id,
                        "status": "completed",
                        "progress": 100,
                        "current_step": "Terminé",
                        "message": "Scan terminé",
                        "estimated_time_remaining": 0
                    }
        
        # Si pas trouvé, considérer comme en cours (peut-être que le scan vient d'être lancé)
        return {
            "scan_id": scan_id,
            "status": "running",
            "progress": 10,
            "current_step": "Initialisation",
            "message": "Scan en cours...",
            "estimated_time_remaining": 600
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    print("🚀 Démarrage du Dashboard API...")
    print("📊 Dashboard: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    try:
        from config import get_config
        cfg = get_config()
        if not getattr(cfg, "vulners_api_key", None):
            print("⚠️  AVERTISSEMENT: VULNERS_API_KEY n'est pas définie. Vulners peut renvoyer 0 résultat sans clé.")
    except Exception:
        pass

    uvicorn.run(
        "dashboard_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )