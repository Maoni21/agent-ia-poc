"""
Dashboard API pour l'Agent IA de Cybersécurité
Backend FastAPI professionnel
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3

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
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "database" / "vulnerability_agent.db"
WORKFLOWS_DIR = DATA_DIR / "workflow_results"


# ===== HELPER FUNCTIONS =====

def get_db_connection():
    """Connexion à la base de données"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def load_workflow_result(workflow_id: str):
    """Charge un résultat de workflow depuis le JSON"""
    result_file = WORKFLOWS_DIR / f"{workflow_id}.json"
    if result_file.exists():
        with open(result_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


# ===== ENDPOINTS API =====

@app.get("/")
async def root():
    """Page d'accueil - redirige vers le dashboard"""
    return FileResponse(BASE_DIR / "static" / "dashboard.html")


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

        # Total des scans
        total_scans = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

        # Scans récents (30 derniers jours)
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        recent_scans = cursor.execute(
            "SELECT COUNT(*) FROM scans WHERE started_at > ?",
            (thirty_days_ago,)
        ).fetchone()[0]

        # Total vulnérabilités
        total_vulns = cursor.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]

        # Vulnérabilités critiques non résolues
        critical_vulns = cursor.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('CRITICAL', 'HIGH') AND status != 'resolved'"
        ).fetchone()[0]

        # Scripts générés
        total_scripts = cursor.execute("SELECT COUNT(*) FROM remediation_scripts").fetchone()[0]

        # Moyenne CVSS
        avg_cvss = cursor.execute("SELECT AVG(cvss_score) FROM vulnerabilities").fetchone()[0] or 0.0

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
        conn = get_db_connection()
        cursor = conn.cursor()

        severity_counts = cursor.execute("""
            SELECT 
                severity,
                COUNT(*) as count
            FROM vulnerabilities
            WHERE status != 'resolved'
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
            severity = row['severity']
            count = row['count']
            distribution[severity] = count

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
        conn = get_db_connection()
        cursor = conn.cursor()

        # Derniers 30 jours
        timeline_data = cursor.execute("""
            SELECT 
                DATE(discovered_at) as date,
                COUNT(*) as count
            FROM vulnerabilities
            WHERE discovered_at >= date('now', '-30 days')
            GROUP BY DATE(discovered_at)
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


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
):
    """Liste des vulnérabilités avec filtres"""

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

        query += " ORDER BY cvss_score DESC, discovered_at DESC LIMIT ?"
        params.append(limit)

        vulnerabilities = cursor.execute(query, params).fetchall()

        conn.close()

        return {
            "vulnerabilities": [dict(vuln) for vuln in vulnerabilities],
            "count": len(vulnerabilities)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    """Liste des scripts de remédiation"""

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM remediation_scripts"
        params = []

        if status:
            query += " WHERE validation_status = ?"
            params.append(status)

        query += " ORDER BY generated_at DESC LIMIT ?"
        params.append(limit)

        scripts = cursor.execute(query, params).fetchall()

        conn.close()

        return {
            "scripts": [dict(script) for script in scripts],
            "count": len(scripts)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/workflows")
async def get_workflows(limit: int = 20):
    """Liste des workflows complets"""

    try:
        workflows = []

        if WORKFLOWS_DIR.exists():
            workflow_files = sorted(
                WORKFLOWS_DIR.glob("*.json"),
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
        conn = get_db_connection()
        cursor = conn.cursor()

        top_vulns = cursor.execute("""
            SELECT 
                vulnerability_id,
                name,
                severity,
                cvss_score,
                affected_service,
                status
            FROM vulnerabilities
            WHERE status != 'resolved'
            ORDER BY cvss_score DESC, severity DESC
            LIMIT ?
        """, (limit,)).fetchall()

        conn.close()

        return {
            "vulnerabilities": [dict(vuln) for vuln in top_vulns]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ===== DÉMARRAGE =====

if __name__ == "__main__":
    import uvicorn

    print("🚀 Démarrage du Dashboard API...")
    print("📊 Dashboard: http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")

    uvicorn.run(
        "dashboard_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )