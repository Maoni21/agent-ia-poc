"""
Script d'initialisation de la base de données pour le dashboard
Crée toutes les tables nécessaires avec le schéma complet
"""

import sqlite3
from pathlib import Path
import sys

def get_schema_sql():
    """Retourne le SQL complet du schéma de base de données"""
    return """
    -- Active les clés étrangères
    PRAGMA foreign_keys = ON;

    -- Table des scans
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        target TEXT NOT NULL,
        scan_type TEXT NOT NULL DEFAULT 'full',
        status TEXT NOT NULL DEFAULT 'pending',
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        duration REAL,
        host_status TEXT DEFAULT 'unknown',
        open_ports TEXT,
        services_count INTEGER DEFAULT 0,
        vulnerabilities_count INTEGER DEFAULT 0,
        nmap_version TEXT,
        scan_parameters TEXT,
        command_line TEXT,
        total_ports_scanned INTEGER DEFAULT 0,
        scan_progress INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Table des vulnérabilités
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'MEDIUM',
        cvss_score REAL,
        cvss_vector TEXT,
        cwe_id TEXT,
        cve_ids TEXT,
        description TEXT,
        impact TEXT,
        solution TEXT,
        affected_service TEXT,
        affected_port INTEGER,
        affected_protocol TEXT DEFAULT 'tcp',
        affected_versions TEXT,
        detection_method TEXT,
        confidence TEXT DEFAULT 'medium',
        false_positive_risk TEXT DEFAULT 'low',
        refs TEXT,
        exploit_available BOOLEAN DEFAULT FALSE,
        patch_available BOOLEAN DEFAULT FALSE,
        category TEXT,
        tags TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Table des analyses IA
    CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT UNIQUE NOT NULL,
        target_system TEXT NOT NULL,
        ai_model_used TEXT,
        analysis_type TEXT DEFAULT 'vulnerability_assessment',
        confidence_score REAL DEFAULT 0.0,
        processing_time REAL DEFAULT 0.0,
        total_vulnerabilities INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        overall_risk_score REAL DEFAULT 0.0,
        analysis_summary TEXT,
        vulnerability_analyses TEXT,
        remediation_plan TEXT,
        immediate_actions TEXT,
        short_term_actions TEXT,
        long_term_actions TEXT,
        business_impact TEXT,
        compliance_notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Table des scripts
    CREATE TABLE IF NOT EXISTS scripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        script_id TEXT UNIQUE NOT NULL,
        vulnerability_id TEXT NOT NULL,
        target_system TEXT NOT NULL DEFAULT 'ubuntu',
        script_type TEXT NOT NULL DEFAULT 'remediation',
        script_content TEXT NOT NULL,
        rollback_script TEXT,
        validation_script TEXT,
        generated_by TEXT DEFAULT 'ai',
        ai_model_used TEXT,
        generation_prompt TEXT,
        validation_status TEXT DEFAULT 'pending',
        risk_level TEXT DEFAULT 'medium',
        safety_checks TEXT,
        warnings TEXT,
        estimated_duration TEXT DEFAULT 'unknown',
        requires_reboot BOOLEAN DEFAULT FALSE,
        requires_sudo BOOLEAN DEFAULT TRUE,
        requires_network BOOLEAN DEFAULT FALSE,
        dependencies TEXT,
        pre_conditions TEXT,
        post_conditions TEXT,
        script_hash TEXT,
        version TEXT DEFAULT '1.0',
        execution_count INTEGER DEFAULT 0,
        last_executed TIMESTAMP,
        execution_history TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id)
    );

    -- Table des workflows
    CREATE TABLE IF NOT EXISTS workflows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workflow_id TEXT UNIQUE NOT NULL,
        workflow_type TEXT NOT NULL DEFAULT 'full_assessment',
        target TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        parameters TEXT,
        priority TEXT DEFAULT 'normal',
        created_by TEXT DEFAULT 'system',
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        estimated_duration INTEGER,
        actual_duration REAL,
        current_step TEXT,
        total_steps INTEGER DEFAULT 0,
        completed_steps INTEGER DEFAULT 0,
        progress_percentage INTEGER DEFAULT 0,
        scan_id TEXT,
        analysis_id TEXT,
        script_ids TEXT,
        vulnerabilities_found INTEGER DEFAULT 0,
        scripts_generated INTEGER DEFAULT 0,
        critical_issues INTEGER DEFAULT 0,
        workflow_logs TEXT,
        error_logs TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
        FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
    );

    -- Table de liaison scan-vulnérabilités
    CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        confidence TEXT DEFAULT 'medium',
        false_positive BOOLEAN DEFAULT FALSE,
        verified BOOLEAN DEFAULT FALSE,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
        UNIQUE(scan_id, vulnerability_id)
    );

    -- Table de liaison analyse-vulnérabilités
    CREATE TABLE IF NOT EXISTS analysis_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        analysis_id TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        ai_severity_assessment TEXT,
        ai_priority_score INTEGER DEFAULT 5,
        ai_recommended_actions TEXT,
        ai_business_impact TEXT,
        ai_confidence REAL DEFAULT 0.0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id),
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id),
        UNIQUE(analysis_id, vulnerability_id)
    );

    -- Table de métadonnées système
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT,
        description TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Index pour les performances
    CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
    CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service ON vulnerabilities(affected_service);
    CREATE INDEX IF NOT EXISTS idx_scripts_vulnerability ON scripts(vulnerability_id);
    CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
    CREATE INDEX IF NOT EXISTS idx_scan_vulns_scan ON scan_vulnerabilities(scan_id);
    CREATE INDEX IF NOT EXISTS idx_scan_vulns_vuln ON scan_vulnerabilities(vulnerability_id);
    """


def init_database(db_path: Path):
    """Initialise la base de données avec le schéma complet"""
    try:
        # Créer le répertoire si nécessaire
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Se connecter à la base de données
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Activer les clés étrangères
        cursor.execute("PRAGMA foreign_keys = ON")
        
        # Obtenir le schéma complet
        schema_sql = get_schema_sql()
        
        # Exécuter le schéma (SQLite exécute plusieurs statements)
        cursor.executescript(schema_sql)
        
        conn.commit()
        conn.close()
        
        print(f"✅ Base de données initialisée avec succès: {db_path}")
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors de l'initialisation de la base de données: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Chemin de la base de données du dashboard
    BASE_DIR = Path(__file__).parent  # src/web
    ROOT_DIR = BASE_DIR.parent.parent  # Racine du projet
    DATA_DIR = ROOT_DIR / "data"
    DB_PATH = DATA_DIR / "database" / "vulnerability_agent.db"
    
    print(f"🔧 Initialisation de la base de données...")
    print(f"📁 Chemin: {DB_PATH}")
    
    if init_database(DB_PATH):
        print("✅ Initialisation terminée avec succès!")
    else:
        print("❌ Échec de l'initialisation")
        sys.exit(1)
