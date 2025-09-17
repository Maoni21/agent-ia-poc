-- =====================================================================
-- Schema de base de données pour l'Agent IA de Cybersécurité
-- Version: 1.0.0
-- Date: 2025-01-15
-- Description: Création des tables principales et indexes optimisés
-- =====================================================================

-- Activer les clés étrangères
PRAGMA foreign_keys = ON;

-- =====================================================================
-- TABLE PRINCIPALE DES SCANS
-- =====================================================================

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('quick', 'full', 'stealth', 'aggressive', 'custom')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),

    -- Timestamps
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration REAL, -- Durée en secondes

    -- Configuration du scan
    nmap_version TEXT,
    nmap_args TEXT, -- Arguments Nmap utilisés
    scan_parameters TEXT, -- JSON avec paramètres détaillés
    timeout_seconds INTEGER DEFAULT 300,

    -- Résultats techniques
    host_status TEXT DEFAULT 'unknown' CHECK (host_status IN ('up', 'down', 'unknown')),
    open_ports_count INTEGER DEFAULT 0,
    services_detected INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,

    -- Métadonnées
    created_by TEXT DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK (duration IS NULL OR duration >= 0)
);

-- =====================================================================
-- TABLE DES VULNÉRABILITÉS
-- =====================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,

    -- Classification
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cvss_score REAL CHECK (cvss_score >= 0 AND cvss_score <= 10),
    cvss_vector TEXT,

    -- Description et impact
    description TEXT NOT NULL,
    impact TEXT,
    exploitability TEXT CHECK (exploitability IN ('EASY', 'MEDIUM', 'HARD', 'UNKNOWN')),

    -- Service affecté
    affected_service TEXT NOT NULL,
    affected_versions TEXT, -- JSON array des versions affectées
    affected_port INTEGER,
    affected_protocol TEXT DEFAULT 'tcp' CHECK (affected_protocol IN ('tcp', 'udp', 'sctp')),

    -- Références externes
    cve_ids TEXT, -- JSON array des CVE IDs
    cwe_ids TEXT, -- JSON array des CWE IDs
    references TEXT, -- JSON array des URLs de référence

    -- Détection
    detection_method TEXT,
    detection_confidence TEXT CHECK (detection_confidence IN ('LOW', 'MEDIUM', 'HIGH', 'CONFIRMED')),
    false_positive_likelihood TEXT CHECK (false_positive_likelihood IN ('LOW', 'MEDIUM', 'HIGH')),

    -- Remédiation
    remediation_available BOOLEAN DEFAULT FALSE,
    remediation_complexity TEXT CHECK (remediation_complexity IN ('LOW', 'MEDIUM', 'HIGH')),
    patch_available BOOLEAN DEFAULT FALSE,
    workaround_available BOOLEAN DEFAULT FALSE,

    -- Métadonnées
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================================
-- TABLE DES SERVICES DÉTECTÉS
-- =====================================================================

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT UNIQUE NOT NULL,
    scan_id TEXT NOT NULL,

    -- Informations réseau
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp', 'sctp')),
    state TEXT NOT NULL CHECK (state IN ('open', 'closed', 'filtered', 'open|filtered', 'closed|filtered')),

    -- Informations service
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    service_info TEXT,
    banner TEXT,

    -- Métadonnées
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    UNIQUE(scan_id, port, protocol)
);

-- =====================================================================
-- TABLE DES ANALYSES IA
-- =====================================================================

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT UNIQUE NOT NULL,

    -- Contexte d'analyse
    target_system TEXT NOT NULL,
    business_context TEXT, -- JSON avec contexte métier

    -- Configuration IA
    ai_model_used TEXT,
    ai_provider TEXT DEFAULT 'openai',
    model_version TEXT,
    temperature REAL DEFAULT 0.3,
    max_tokens INTEGER,

    -- Résultats
    confidence_score REAL CHECK (confidence_score >= 0 AND confidence_score <= 1),
    processing_time REAL, -- Temps en secondes
    tokens_consumed INTEGER,

    -- Données d'analyse
    analysis_summary TEXT, -- JSON avec résumé
    risk_assessment TEXT, -- JSON avec évaluation des risques
    remediation_plan TEXT, -- JSON avec plan de remédiation
    priority_matrix TEXT, -- JSON avec matrice de priorité

    -- Compteurs
    vulnerabilities_analyzed INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    recommendations_count INTEGER DEFAULT 0,

    -- Métadonnées
    analyzed_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    CHECK (confidence_score IS NULL OR confidence_score BETWEEN 0 AND 1),
    CHECK (processing_time IS NULL OR processing_time >= 0)
);

-- =====================================================================
-- TABLE DES SCRIPTS DE CORRECTION
-- =====================================================================

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id TEXT UNIQUE NOT NULL,
    vulnerability_id TEXT NOT NULL,

    -- Configuration cible
    target_system TEXT NOT NULL,
    execution_context TEXT DEFAULT 'production',

    -- Type et contenu
    script_type TEXT NOT NULL DEFAULT 'main' CHECK (script_type IN ('main', 'rollback', 'validation', 'pre_check', 'post_check')),
    script_content TEXT NOT NULL,
    script_language TEXT DEFAULT 'bash' CHECK (script_language IN ('bash', 'powershell', 'python', 'sql')),

    -- Sécurité et validation
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    validation_status TEXT DEFAULT 'pending' CHECK (validation_status IN ('pending', 'approved', 'rejected', 'review_required')),
    safety_score REAL CHECK (safety_score >= 0 AND safety_score <= 1),

    -- Métadonnées d'exécution
    estimated_duration TEXT,
    requires_reboot BOOLEAN DEFAULT FALSE,
    requires_sudo BOOLEAN DEFAULT TRUE,
    requires_backup BOOLEAN DEFAULT TRUE,

    -- Dépendances et prérequis
    dependencies TEXT, -- JSON array des dépendances
    prerequisites TEXT, -- JSON array des prérequis

    -- Génération
    generated_by TEXT, -- Modèle IA utilisé
    generation_prompt_hash TEXT,
    script_hash TEXT, -- Hash du contenu pour détecter les modifications

    -- Statistiques d'usage
    execution_count INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0,
    last_executed TIMESTAMP,

    -- Métadonnées
    generated_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    CHECK (safety_score IS NULL OR safety_score BETWEEN 0 AND 1),
    CHECK (success_rate >= 0 AND success_rate <= 1),
    CHECK (execution_count >= 0)
);

-- =====================================================================
-- TABLE DES WORKFLOWS
-- =====================================================================

CREATE TABLE IF NOT EXISTS workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT UNIQUE NOT NULL,

    -- Configuration
    workflow_type TEXT NOT NULL CHECK (workflow_type IN ('scan_only', 'scan_and_analyze', 'full_workflow', 'analyze_existing', 'generate_scripts', 'custom')),
    name TEXT,
    target TEXT NOT NULL,

    -- État
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'paused')),
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'critical')),

    -- Paramètres
    parameters TEXT, -- JSON avec paramètres du workflow
    estimated_duration INTEGER, -- Durée estimée en secondes

    -- Progression
    current_step TEXT,
    progress_percentage INTEGER DEFAULT 0 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    steps_completed INTEGER DEFAULT 0,
    total_steps INTEGER DEFAULT 0,

    -- Timestamps
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration REAL, -- Durée réelle en secondes

    -- Résultats
    result_summary TEXT, -- JSON avec résumé des résultats
    error_message TEXT,
    error_code INTEGER,

    -- Métadonnées
    created_by TEXT DEFAULT 'system',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    CHECK (completed_at IS NULL OR completed_at >= started_at),
    CHECK (duration IS NULL OR duration >= 0),
    CHECK (steps_completed <= total_steps)
);

-- =====================================================================
-- TABLES DE LIAISON
-- =====================================================================

-- Liaison Scan <-> Vulnérabilités
CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,

    -- Contexte de détection
    detection_confidence REAL DEFAULT 0.5,
    false_positive_flag BOOLEAN DEFAULT FALSE,
    verified BOOLEAN DEFAULT FALSE,

    -- Métadonnées
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    UNIQUE(scan_id, vulnerability_id)
);

-- Liaison Analyse <-> Vulnérabilités
CREATE TABLE IF NOT EXISTS analysis_vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    vulnerability_id TEXT NOT NULL,

    -- Résultats d'analyse spécifiques
    priority_score INTEGER CHECK (priority_score >= 1 AND priority_score <= 10),
    business_impact TEXT,
    recommended_actions TEXT, -- JSON array
    remediation_urgency TEXT CHECK (remediation_urgency IN ('immediate', 'urgent', 'normal', 'low')),

    -- Métadonnées
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contraintes
    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    UNIQUE(analysis_id, vulnerability_id)
);

-- Liaison Workflow <-> Scans
CREATE TABLE IF NOT EXISTS workflow_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    execution_order INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (workflow_id) REFERENCES workflows(workflow_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    UNIQUE(workflow_id, scan_id)
);

-- =====================================================================
-- TABLE DE MÉTADONNÉES ET CONFIGURATION
-- =====================================================================

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT,
    data_type TEXT DEFAULT 'string' CHECK (data_type IN ('string', 'integer', 'float', 'boolean', 'json')),
    description TEXT,
    is_system BOOLEAN DEFAULT TRUE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insérer les métadonnées système
INSERT OR REPLACE INTO metadata (key, value, description, is_system) VALUES
    ('schema_version', '1.0.0', 'Version du schéma de base de données', TRUE),
    ('created_at', datetime('now'), 'Date de création de la base', TRUE),
    ('application_version', '1.0.0', 'Version de l\'application', TRUE),
    ('last_migration', datetime('now'), 'Date de la dernière migration', TRUE),
    ('max_scan_retention_days', '90', 'Rétention maximum des scans en jours', FALSE),
    ('auto_cleanup_enabled', 'true', 'Nettoyage automatique activé', FALSE),
    ('backup_frequency_hours', '24', 'Fréquence de sauvegarde en heures', FALSE);

-- =====================================================================
-- TABLE D'AUDIT ET LOGS
-- =====================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Contexte
    entity_type TEXT NOT NULL, -- 'scan', 'vulnerability', 'script', etc.
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL, -- 'CREATE', 'UPDATE', 'DELETE', 'EXECUTE'

    -- Détails
    old_values TEXT, -- JSON avec anciennes valeurs
    new_values TEXT, -- JSON avec nouvelles valeurs
    changes_summary TEXT,

    -- Utilisateur et session
    user_id TEXT DEFAULT 'system',
    session_id TEXT,
    ip_address TEXT,
    user_agent TEXT,

    -- Métadonnées
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT DEFAULT 'INFO' CHECK (severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

-- =====================================================================
-- INDEXES POUR OPTIMISATION DES PERFORMANCES
-- =====================================================================

-- Index primaires pour les recherches fréquentes
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_type ON scans(scan_type);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss ON vulnerabilities(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_service ON vulnerabilities(affected_service);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_port ON vulnerabilities(affected_port);

CREATE INDEX IF NOT EXISTS idx_services_scan ON services(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);
CREATE INDEX IF NOT EXISTS idx_services_state ON services(state);

CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target_system);
CREATE INDEX IF NOT EXISTS idx_analyses_date ON analyses(analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_confidence ON analyses(confidence_score DESC);

CREATE INDEX IF NOT EXISTS idx_scripts_vulnerability ON scripts(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_scripts_system ON scripts(target_system);
CREATE INDEX IF NOT EXISTS idx_scripts_risk ON scripts(risk_level);
CREATE INDEX IF NOT EXISTS idx_scripts_status ON scripts(validation_status);

CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflows_type ON workflows(workflow_type);
CREATE INDEX IF NOT EXISTS idx_workflows_priority ON workflows(priority);
CREATE INDEX IF NOT EXISTS idx_workflows_created ON workflows(created_at DESC);

-- Index composés pour requêtes complexes
CREATE INDEX IF NOT EXISTS idx_scan_vulns_composite ON scan_vulnerabilities(scan_id, vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_analysis_vulns_composite ON analysis_vulnerabilities(analysis_id, vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp DESC);

-- Index pour les recherches par plage de dates
CREATE INDEX IF NOT EXISTS idx_scans_date_range ON scans(created_at, completed_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_seen ON vulnerabilities(first_seen, last_seen);

-- =====================================================================
-- VUES POUR SIMPLIFIER LES REQUÊTES COMPLEXES
-- =====================================================================

-- Vue des scans avec statistiques
CREATE VIEW IF NOT EXISTS v_scans_summary AS
SELECT
    s.scan_id,
    s.target,
    s.scan_type,
    s.status,
    s.started_at,
    s.completed_at,
    s.duration,
    COUNT(sv.vulnerability_id) as vulnerabilities_count,
    COUNT(CASE WHEN v.severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN v.severity = 'HIGH' THEN 1 END) as high_count,
    COUNT(CASE WHEN v.severity = 'MEDIUM' THEN 1 END) as medium_count,
    COUNT(CASE WHEN v.severity = 'LOW' THEN 1 END) as low_count,
    AVG(v.cvss_score) as avg_cvss_score,
    MAX(v.cvss_score) as max_cvss_score
FROM scans s
LEFT JOIN scan_vulnerabilities sv ON s.scan_id = sv.scan_id
LEFT JOIN vulnerabilities v ON sv.vulnerability_id = v.vulnerability_id
GROUP BY s.scan_id, s.target, s.scan_type, s.status, s.started_at, s.completed_at, s.duration;

-- Vue des vulnérabilités enrichies
CREATE VIEW IF NOT EXISTS v_vulnerabilities_enriched AS
SELECT
    v.*,
    COUNT(sv.scan_id) as detection_frequency,
    MAX(sv.detected_at) as last_detected,
    MIN(sv.detected_at) as first_detected,
    COUNT(s.script_id) as scripts_available,
    AVG(s.safety_score) as avg_script_safety
FROM vulnerabilities v
LEFT JOIN scan_vulnerabilities sv ON v.vulnerability_id = sv.vulnerability_id
LEFT JOIN scripts s ON v.vulnerability_id = s.vulnerability_id
GROUP BY v.vulnerability_id;

-- Vue des workflows actifs
CREATE VIEW IF NOT EXISTS v_active_workflows AS
SELECT
    w.*,
    COUNT(ws.scan_id) as associated_scans
FROM workflows w
LEFT JOIN workflow_scans ws ON w.workflow_id = ws.workflow_id
WHERE w.status IN ('pending', 'running', 'paused')
GROUP BY w.workflow_id;

-- =====================================================================
-- TRIGGERS POUR MAINTENIR L'INTÉGRITÉ DES DONNÉES
-- =====================================================================

-- Trigger pour mettre à jour le timestamp updated_at
CREATE TRIGGER IF NOT EXISTS tr_scans_updated
    AFTER UPDATE ON scans
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE scans SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS tr_vulnerabilities_updated
    AFTER UPDATE ON vulnerabilities
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE vulnerabilities SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS tr_analyses_updated
    AFTER UPDATE ON analyses
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE analyses SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS tr_scripts_updated
    AFTER UPDATE ON scripts
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE scripts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS tr_workflows_updated
    AFTER UPDATE ON workflows
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE workflows SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Trigger pour l'audit automatique
CREATE TRIGGER IF NOT EXISTS tr_audit_scans_insert
    AFTER INSERT ON scans
    FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (entity_type, entity_id, action, new_values)
    VALUES ('scan', NEW.scan_id, 'CREATE',
            json_object(
                'target', NEW.target,
                'scan_type', NEW.scan_type,
                'status', NEW.status
            ));
END;

CREATE TRIGGER IF NOT EXISTS tr_audit_scans_update
    AFTER UPDATE ON scans
    FOR EACH ROW
BEGIN
    INSERT INTO audit_logs (entity_type, entity_id, action, old_values, new_values)
    VALUES ('scan', NEW.scan_id, 'UPDATE',
            json_object('status', OLD.status, 'updated_at', OLD.updated_at),
            json_object('status', NEW.status, 'updated_at', NEW.updated_at));
END;

-- =====================================================================
-- CONFIGURATION INITIALE ET DONNÉES DE RÉFÉRENCE
-- =====================================================================

-- Configuration des niveaux de sécurité par défaut
INSERT OR IGNORE INTO metadata (key, value, description) VALUES
    ('default_scan_timeout', '300', 'Timeout par défaut pour les scans (secondes)'),
    ('max_concurrent_scans', '3', 'Nombre maximum de scans simultanés'),
    ('script_validation_required', 'true', 'Validation obligatoire des scripts'),
    ('auto_backup_enabled', 'true', 'Sauvegarde automatique activée'),
    ('vulnerability_retention_days', '365', 'Rétention des vulnérabilités (jours)');

-- =====================================================================
-- OPTIMISATIONS SQLITE FINALES
-- =====================================================================

-- Optimiser les statistiques pour le query planner
ANALYZE;

-- Configuration finale des PRAGMAs (sera surchargée par l'application)
PRAGMA optimize;