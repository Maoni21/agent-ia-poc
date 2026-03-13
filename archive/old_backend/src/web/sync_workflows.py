"""
Module pour synchroniser les données des workflows vers la base de données
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging
import time

logger = logging.getLogger(__name__)


def sync_workflow_to_db(workflow_data: Dict[str, Any], db_path: Path) -> bool:
    """Synchronise un workflow vers la base de données"""
    # Toujours initialiser workflow_id AVANT le try pour éviter
    # "cannot access local variable 'workflow_id' where it is not associated with a value"
    workflow_id = workflow_data.get("workflow_id") or "unknown"

    try:
        # Créer la base de données si elle n'existe pas
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Connexion avec timeout pour éviter les verrous
        # Retry avec backoff en cas de verrou
        max_retries = 5
        retry_delay = 0.1
        conn = None
        
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(str(db_path), timeout=10.0)
                conn.row_factory = sqlite3.Row
                # Activer WAL mode pour meilleure concurrence
                conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError as e:
                if "locked" in str(e).lower() and attempt < max_retries - 1:
                    time.sleep(retry_delay * (2 ** attempt))
                    continue
                raise
        
        if conn is None:
            raise sqlite3.OperationalError("Impossible de se connecter à la base de données")
        
        cursor = conn.cursor()
        
        # Créer les tables si elles n'existent pas (schéma simplifié)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT PRIMARY KEY,
                workflow_type TEXT,
                target TEXT,
                status TEXT,
                started_at TEXT,
                completed_at TEXT,
                actual_duration REAL,
                vulnerabilities_found INTEGER DEFAULT 0,
                scripts_generated INTEGER DEFAULT 0,
                critical_issues INTEGER DEFAULT 0,
                progress_percentage INTEGER DEFAULT 0,
                current_step TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vulnerability_id TEXT PRIMARY KEY,
                name TEXT,
                severity TEXT,
                cvss_score REAL,
                description TEXT,
                affected_service TEXT,
                affected_port INTEGER,
                cve_ids TEXT,
                refs TEXT,
                detection_method TEXT,
                confidence TEXT,
                is_false_positive INTEGER DEFAULT 0,
                false_positive_confidence REAL,
                false_positive_reasoning TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migration: renommer la colonne 'references' en 'refs' si elle existe
        try:
            cursor.execute("PRAGMA table_info(vulnerabilities)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'references' in columns and 'refs' not in columns:
                # SQLite ne supporte pas ALTER TABLE RENAME COLUMN directement
                # On doit recréer la table
                cursor.execute("""
                    CREATE TABLE vulnerabilities_new (
                        vulnerability_id TEXT PRIMARY KEY,
                        name TEXT,
                        severity TEXT,
                        cvss_score REAL,
                        description TEXT,
                        affected_service TEXT,
                        affected_port INTEGER,
                        cve_ids TEXT,
                        refs TEXT,
                        detection_method TEXT,
                        confidence TEXT,
                        is_false_positive INTEGER DEFAULT 0,
                        false_positive_confidence REAL,
                        false_positive_reasoning TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                cursor.execute("""
                    INSERT INTO vulnerabilities_new 
                    SELECT vulnerability_id, name, severity, cvss_score, description,
                           affected_service, affected_port, cve_ids, references as refs,
                           detection_method, confidence, is_false_positive,
                           false_positive_confidence, false_positive_reasoning, created_at
                    FROM vulnerabilities
                """)
                cursor.execute("DROP TABLE vulnerabilities")
                cursor.execute("ALTER TABLE vulnerabilities_new RENAME TO vulnerabilities")
                conn.commit()
                logger.info("✅ Migration: colonne 'references' renommée en 'refs'")
        except Exception as e:
            logger.warning(f"⚠️ Erreur migration colonne 'references': {e}")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
                scan_id TEXT,
                vulnerability_id TEXT,
                detected_at TEXT,
                confidence TEXT,
                false_positive INTEGER DEFAULT 0,
                PRIMARY KEY (scan_id, vulnerability_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scripts (
                script_id TEXT PRIMARY KEY,
                vulnerability_id TEXT,
                target_system TEXT,
                script_type TEXT,
                script_content TEXT,
                rollback_script TEXT,
                ai_model_used TEXT,
                validation_status TEXT,
                risk_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Si aucun workflow_id exploitable, on ignore ce fichier
        if not workflow_data.get("workflow_id"):
            return False
        
        # Insérer ou mettre à jour le workflow
        workflow_values = {
            "workflow_id": workflow_id,
            "workflow_type": workflow_data.get("workflow_type", "full_workflow"),
            "target": workflow_data.get("target", ""),
            "status": workflow_data.get("status", "completed"),
            "started_at": workflow_data.get("started_at"),
            "completed_at": workflow_data.get("completed_at"),
            "actual_duration": workflow_data.get("duration"),
            "vulnerabilities_found": workflow_data.get("total_vulnerabilities", 0),
            "scripts_generated": workflow_data.get("scripts_generated", 0),
            "critical_issues": workflow_data.get("critical_vulnerabilities", 0),
            "progress_percentage": 100 if workflow_data.get("status") == "completed" else 0,
            "current_step": "Terminé" if workflow_data.get("status") == "completed" else "En cours"
        }
        
        cursor.execute("""
            INSERT OR REPLACE INTO workflows (
                workflow_id, workflow_type, target, status, started_at, completed_at,
                actual_duration, vulnerabilities_found, scripts_generated, critical_issues,
                progress_percentage, current_step
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            workflow_values["workflow_id"],
            workflow_values["workflow_type"],
            workflow_values["target"],
            workflow_values["status"],
            workflow_values["started_at"],
            workflow_values["completed_at"],
            workflow_values["actual_duration"],
            workflow_values["vulnerabilities_found"],
            workflow_values["scripts_generated"],
            workflow_values["critical_issues"],
            workflow_values["progress_percentage"],
            workflow_values["current_step"]
        ))
        
        # Synchroniser les vulnérabilités depuis analysis_result puis scan_result
        vulnerabilities_to_sync = []
        
        # D'abord depuis analysis_result (priorité)
        analysis_result = workflow_data.get("analysis_result")
        if analysis_result and isinstance(analysis_result, dict):
            vulns = analysis_result.get("vulnerabilities")
            # S'assurer que vulns est une liste, pas None
            if vulns is None:
                vulns = []
            elif not isinstance(vulns, list):
                vulns = [vulns] if vulns else []
            vulnerabilities_to_sync.extend(vulns)
        
        # Ensuite depuis scan_result si pas d'analyse
        if not vulnerabilities_to_sync:
            scan_result = workflow_data.get("scan_result")
            if scan_result and isinstance(scan_result, dict):
                vulns = scan_result.get("vulnerabilities")
                # S'assurer que vulns est une liste, pas None
                if vulns is None:
                    vulns = []
                elif not isinstance(vulns, list):
                    vulns = [vulns] if vulns else []
                vulnerabilities_to_sync.extend(vulns)
        
        # Filtrer les None avant d'itérer
        vulnerabilities_to_sync = [v for v in vulnerabilities_to_sync if v is not None]
        
        for vuln in vulnerabilities_to_sync:
                vuln_dict = vuln if isinstance(vuln, dict) else vuln.to_dict() if hasattr(vuln, 'to_dict') else {}
                
                # Insérer ou mettre à jour la vulnérabilité
                cursor.execute("""
                    INSERT OR REPLACE INTO vulnerabilities (
                        vulnerability_id, name, severity, cvss_score, description,
                        affected_service, affected_port, cve_ids, refs,
                        detection_method, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vuln_dict.get("vulnerability_id", ""),
                    vuln_dict.get("name", ""),
                    vuln_dict.get("severity", "MEDIUM"),
                    vuln_dict.get("cvss_score"),
                    vuln_dict.get("description", ""),
                    vuln_dict.get("affected_service", ""),
                    vuln_dict.get("affected_port"),
                    json.dumps(vuln_dict.get("cve_ids", [])),
                    json.dumps(vuln_dict.get("references", [])),
                    vuln_dict.get("detection_method", "nmap"),
                    vuln_dict.get("confidence", "medium")
                ))
                
                # Créer la liaison workflow-vulnérabilité
                # Utiliser workflow_id comme scan_id pour les scans terminés
                scan_id = workflow_data.get("scan_id") or workflow_id
                cursor.execute("""
                    INSERT OR IGNORE INTO scan_vulnerabilities (
                        scan_id, vulnerability_id, detected_at, confidence, false_positive
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    vuln_dict.get("vulnerability_id", ""),
                    workflow_data.get("started_at") or datetime.utcnow().isoformat(),
                    vuln_dict.get("confidence", "medium"),
                    1 if vuln_dict.get("is_false_positive") else 0
                ))
        
        # Synchroniser les scripts depuis script_results
        script_results = workflow_data.get("script_results")
        # S'assurer que script_results est une liste, pas None
        if script_results is None:
            script_results = []
        elif not isinstance(script_results, list):
            script_results = [script_results] if script_results else []
        
        # Filtrer les None avant d'itérer
        script_results = [s for s in script_results if s is not None]
        
        for script in script_results:
            script_dict = script if isinstance(script, dict) else script.to_dict() if hasattr(script, 'to_dict') else {}
            
            vulnerability_id = script_dict.get("vulnerability_id", "")
            if not vulnerability_id:
                continue
            
            cursor.execute("""
                INSERT OR REPLACE INTO scripts (
                    script_id, vulnerability_id, target_system, script_type,
                    script_content, rollback_script, ai_model_used,
                    validation_status, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                script_dict.get("script_id", ""),
                vulnerability_id,
                script_dict.get("target_system", "ubuntu"),
                script_dict.get("script_type", "bash"),
                script_dict.get("script_content", ""),
                script_dict.get("rollback_script", ""),
                script_dict.get("ai_model_used", ""),
                "pending",
                "medium"
            ))
        
        conn.commit()
        return True
        
    except sqlite3.OperationalError as e:
        if "locked" in str(e).lower():
            logger.warning(f"⚠️ Base de données verrouillée pour workflow {workflow_id}, réessai plus tard")
        else:
            logger.error(f"Erreur SQL synchronisation workflow {workflow_id}: {e}")
        return False
    except Exception as e:
        logger.error(f"Erreur synchronisation workflow {workflow_id}: {e}")
        import traceback
        logger.debug(traceback.format_exc())
        return False
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass


def sync_all_workflows(workflows_dir: Path, db_path: Path) -> int:
    """Synchronise tous les workflows depuis les fichiers JSON"""
    synced_count = 0
    failed_count = 0
    
    if not workflows_dir.exists():
        return 0
    
    # Récupérer tous les fichiers JSON
    workflow_files = list(workflows_dir.glob("*.json"))
    total_files = len(workflow_files)
    
    logger.info(f"🔄 Synchronisation de {total_files} workflows...")
    
    # Traiter séquentiellement pour éviter les verrous
    for idx, workflow_file in enumerate(workflow_files, 1):
        try:
            with open(workflow_file, 'r', encoding='utf-8') as f:
                workflow_data = json.load(f)
                
            # Retry en cas d'échec (surtout pour les verrous)
            max_retries = 3
            success = False
            for retry in range(max_retries):
                if sync_workflow_to_db(workflow_data, db_path):
                    synced_count += 1
                    success = True
                    break
                elif retry < max_retries - 1:
                    # Attendre un peu avant de réessayer
                    time.sleep(0.2 * (retry + 1))
            
            if not success:
                failed_count += 1
                logger.warning(f"⚠️ Échec synchronisation {workflow_file.name} après {max_retries} tentatives")
            
            # Log de progression tous les 10 fichiers
            if idx % 10 == 0:
                logger.info(f"📊 Progression: {idx}/{total_files} workflows traités ({synced_count} réussis, {failed_count} échoués)")
                
        except json.JSONDecodeError as e:
            logger.error(f"❌ Erreur JSON dans {workflow_file.name}: {e}")
            failed_count += 1
        except Exception as e:
            logger.error(f"❌ Erreur lecture workflow {workflow_file.name}: {e}")
            failed_count += 1
            continue
    
    logger.info(f"✅ Synchronisation terminée: {synced_count} réussis, {failed_count} échoués sur {total_files} workflows")
    return synced_count

