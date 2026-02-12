# 📋 Cahier des Charges - Vulnerability Agent IA
## Transformation PoC → Produit Commercial

**Date de création** : 12 février 2026  
**Version** : 1.0  
**Objectif** : Transformer le prototype actuel en plateforme SaaS multi-tenant commercialisable

---

## 🎯 VISION DU PROJET

### Objectif Final
Créer une plateforme SaaS de détection et correction automatisée de vulnérabilités qui concurrence Tenable avec :
- Multi-tenancy complet (plusieurs clients isolés)
- Interface web moderne et intuitive
- Système d'authentification et RBAC
- IA générative pour analyse et correction
- Scalabilité pour grandes entreprises
- Modèle de pricing compétitif

### État Actuel (Baseline)
```
✅ CE QUI FONCTIONNE :
- Scanner Nmap fonctionnel (CLI)
- Analyse IA avec GPT-4/Claude (CLI)
- Génération de scripts de remédiation (CLI)
- Structure backend FastAPI
- Frontend Next.js (UI basique)
- Docker Compose setup

❌ CE QUI MANQUE :
- Système d'authentification (login/register)
- Multi-tenancy (isolation des clients)
- Base de données complète (actuellement JSON)
- Connexion Frontend ↔ Backend
- Gestion des assets (serveurs clients)
- RBAC (rôles et permissions)
- Agent d'application automatique des correctifs
- Système de déploiement chez les clients
```

### Estimation de Complétude
**~35% d'un MVP commercial**

---

## 📐 ARCHITECTURE CIBLE

### Architecture Multi-Tenant SaaS

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENTS / UTILISATEURS                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (Next.js)                        │
│  - Dashboard                                                 │
│  - Assets Management                                         │
│  - Scan Results                                              │
│  - Vulnerability Analysis                                    │
│  - Remediation Scripts                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓ REST API + WebSocket
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND API (FastAPI)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    Auth     │  │   Scans     │  │   Assets    │         │
│  │  JWT/RBAC   │  │  Management │  │  Management │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │ Vulns API   │  │  AI Engine  │  │ Remediation │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  WORKER LAYER (Celery)                       │
│  - Background Scans                                          │
│  - AI Analysis Jobs                                          │
│  - Script Generation                                         │
│  - Remediation Execution                                     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  CORE ENGINE (Python)                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Collector  │  │  Analyzer  │  │ Generator  │            │
│  │  (Nmap)    │  │   (AI)     │  │  (Scripts) │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│  ┌────────────┐                                             │
│  │ Executor   │  (Agent d'application des correctifs)       │
│  └────────────┘                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│               DATABASE (PostgreSQL)                          │
│  - organizations (tenants)                                   │
│  - users (auth + RBAC)                                       │
│  - assets (serveurs clients)                                 │
│  - scans (historique)                                        │
│  - vulnerabilities                                           │
│  - cve_database (base locale CVE)                            │
│  - remediation_scripts                                       │
│  - audit_logs                                                │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗄️ SCHÉMA DE BASE DE DONNÉES

### Modèle de Données Complet

```sql
-- ============================================
-- TABLE 1: ORGANIZATIONS (Multi-tenant)
-- ============================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    
    -- Subscription
    subscription_tier VARCHAR(50) NOT NULL DEFAULT 'free',
        -- Values: 'free', 'pro', 'business', 'enterprise'
    max_assets INTEGER NOT NULL DEFAULT 10,
    max_scans_per_month INTEGER,
    
    -- Billing
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(50) DEFAULT 'active',
        -- Values: 'active', 'past_due', 'canceled', 'trialing'
    trial_ends_at TIMESTAMP,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_tier CHECK (subscription_tier IN ('free', 'pro', 'business', 'enterprise'))
);

CREATE INDEX idx_org_slug ON organizations(slug);
CREATE INDEX idx_org_tier ON organizations(subscription_tier);


-- ============================================
-- TABLE 2: USERS (Authentication + RBAC)
-- ============================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Authentication
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    
    -- RBAC
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
        -- Values: 'admin', 'manager', 'analyst', 'viewer'
    permissions JSONB DEFAULT '[]',
        -- Custom permissions: ['can_execute_remediation', 'can_delete_assets', ...]
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    last_login_at TIMESTAMP,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_role CHECK (role IN ('admin', 'manager', 'analyst', 'viewer'))
);

CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_org ON users(organization_id);
CREATE INDEX idx_user_role ON users(role);


-- ============================================
-- TABLE 3: ASSETS (Serveurs/Machines des clients)
-- ============================================
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Identification
    hostname VARCHAR(255),
    ip_address INET NOT NULL,
    mac_address MACADDR,
    
    -- Classification
    asset_type VARCHAR(50) NOT NULL DEFAULT 'server',
        -- Values: 'server', 'workstation', 'network_device', 'container', 'cloud_instance'
    os VARCHAR(255),
    os_version VARCHAR(100),
    
    -- Organization
    tags TEXT[] DEFAULT '{}',
        -- Example: ['production', 'web-server', 'critical', 'pci-dss']
    environment VARCHAR(50),
        -- Values: 'production', 'staging', 'development', 'test'
    business_criticality VARCHAR(50) DEFAULT 'medium',
        -- Values: 'critical', 'high', 'medium', 'low'
    
    -- Location
    datacenter VARCHAR(100),
    cloud_provider VARCHAR(50),
        -- Values: 'aws', 'azure', 'gcp', 'on-premise'
    region VARCHAR(100),
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_seen TIMESTAMP,
    monitoring_enabled BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_asset_type CHECK (asset_type IN ('server', 'workstation', 'network_device', 'container', 'cloud_instance')),
    CONSTRAINT check_criticality CHECK (business_criticality IN ('critical', 'high', 'medium', 'low'))
);

CREATE INDEX idx_asset_org ON assets(organization_id);
CREATE INDEX idx_asset_ip ON assets(ip_address);
CREATE INDEX idx_asset_type ON assets(asset_type);
CREATE INDEX idx_asset_env ON assets(environment);
CREATE INDEX idx_asset_tags ON assets USING GIN(tags);


-- ============================================
-- TABLE 4: SCANS
-- ============================================
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    
    -- Scan Configuration
    scan_type VARCHAR(50) NOT NULL,
        -- Values: 'quick', 'full', 'stealth', 'compliance', 'custom'
    scan_profile VARCHAR(100),
        -- Values: 'pci_dss', 'hipaa', 'cis_benchmark', 'custom'
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'queued',
        -- Values: 'queued', 'running', 'completed', 'failed', 'cancelled'
    progress INTEGER DEFAULT 0,
        -- 0-100
    
    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    
    -- Results Summary
    total_ports_scanned INTEGER DEFAULT 0,
    open_ports_count INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    
    -- Risk Score
    risk_score DECIMAL(4,2),
        -- 0.00 - 10.00
    
    -- Raw Data
    nmap_output TEXT,
    scan_results JSONB,
        -- Raw JSON results from Nmap
    
    -- Error Handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    -- Metadata
    triggered_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_scan_type CHECK (scan_type IN ('quick', 'full', 'stealth', 'compliance', 'custom')),
    CONSTRAINT check_status CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_scan_org ON scans(organization_id);
CREATE INDEX idx_scan_asset ON scans(asset_id);
CREATE INDEX idx_scan_status ON scans(status);
CREATE INDEX idx_scan_date ON scans(created_at DESC);


-- ============================================
-- TABLE 5: VULNERABILITIES
-- ============================================
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- CVE Information
    cve_id VARCHAR(50),
        -- Example: 'CVE-2024-1234'
    title VARCHAR(500) NOT NULL,
    description TEXT,
    
    -- Severity
    severity VARCHAR(20) NOT NULL,
        -- Values: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    cvss_score DECIMAL(3,1),
        -- 0.0 - 10.0
    cvss_vector VARCHAR(200),
        -- Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    
    -- Affected Component
    affected_package VARCHAR(255),
        -- Example: 'apache2', 'openssl'
    affected_version VARCHAR(100),
    fixed_version VARCHAR(100),
    port INTEGER,
    protocol VARCHAR(10),
        -- Values: 'tcp', 'udp'
    service VARCHAR(100),
        -- Example: 'http', 'ssh', 'mysql'
    
    -- Detection
    detection_method VARCHAR(50),
        -- Values: 'version_detection', 'script_scan', 'banner_grab', 'manual'
    confidence VARCHAR(20) DEFAULT 'medium',
        -- Values: 'high', 'medium', 'low'
    
    -- AI Analysis
    ai_analyzed BOOLEAN DEFAULT FALSE,
    ai_analysis JSONB,
        -- {
        --   "summary": "...",
        --   "business_impact": "...",
        --   "exploitability": "...",
        --   "false_positive_likelihood": 0.1,
        --   "priority_score": 9
        -- }
    ai_priority_score INTEGER,
        -- 1-10
    false_positive BOOLEAN DEFAULT FALSE,
    
    -- Remediation
    remediation_available BOOLEAN DEFAULT FALSE,
    remediation_complexity VARCHAR(20),
        -- Values: 'low', 'medium', 'high'
    remediation_script_id UUID,
    remediation_status VARCHAR(50) DEFAULT 'pending',
        -- Values: 'pending', 'in_progress', 'completed', 'failed', 'skipped'
    remediation_notes TEXT,
    
    -- Status
    status VARCHAR(50) DEFAULT 'open',
        -- Values: 'open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'
    assigned_to UUID REFERENCES users(id),
    resolved_at TIMESTAMP,
    resolved_by UUID REFERENCES users(id),
    
    -- References
    references JSONB DEFAULT '[]',
        -- [{"type": "cve", "url": "https://..."}, ...]
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(50),
        -- Values: 'unproven', 'proof_of_concept', 'functional', 'high'
    
    -- Metadata
    first_detected_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP DEFAULT NOW(),
    detection_count INTEGER DEFAULT 1,
    
    CONSTRAINT check_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    CONSTRAINT check_confidence CHECK (confidence IN ('high', 'medium', 'low')),
    CONSTRAINT check_vuln_status CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive'))
);

CREATE INDEX idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_org ON vulnerabilities(organization_id);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_status ON vulnerabilities(status);
CREATE INDEX idx_vuln_score ON vulnerabilities(cvss_score DESC);


-- ============================================
-- TABLE 6: CVE_DATABASE (Base locale)
-- ============================================
CREATE TABLE cve_database (
    cve_id VARCHAR(50) PRIMARY KEY,
        -- Example: 'CVE-2024-1234'
    
    -- Basic Info
    description TEXT,
    published_date DATE,
    last_modified DATE,
    
    -- CVSS
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(200),
    cvss_v2_score DECIMAL(3,1),
    severity VARCHAR(20),
    
    -- Affected Products
    affected_products JSONB DEFAULT '[]',
        -- [{"vendor": "apache", "product": "httpd", "versions": ["2.4.1", "2.4.2"]}]
    
    -- CWE (Common Weakness Enumeration)
    cwe_ids TEXT[],
        -- ['CWE-79', 'CWE-89']
    
    -- References
    references JSONB DEFAULT '[]',
        -- [{"url": "...", "source": "NVD"}, ...]
    
    -- Exploit
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(50),
    exploit_references JSONB DEFAULT '[]',
    
    -- Metadata
    source VARCHAR(50) DEFAULT 'NVD',
        -- Values: 'NVD', 'MITRE', 'Vendor'
    last_synced_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cve_date ON cve_database(published_date DESC);
CREATE INDEX idx_cve_score ON cve_database(cvss_v3_score DESC);
CREATE INDEX idx_cve_severity ON cve_database(severity);


-- ============================================
-- TABLE 7: REMEDIATION_SCRIPTS
-- ============================================
CREATE TABLE remediation_scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Script Info
    script_type VARCHAR(50) NOT NULL,
        -- Values: 'bash', 'ansible', 'powershell', 'python'
    script_content TEXT NOT NULL,
    rollback_script TEXT,
    
    -- Metadata
    target_os VARCHAR(100),
        -- Example: 'ubuntu-22.04', 'centos-8', 'windows-server-2019'
    requires_reboot BOOLEAN DEFAULT FALSE,
    requires_sudo BOOLEAN DEFAULT TRUE,
    estimated_duration_minutes INTEGER,
    
    -- Safety
    risk_level VARCHAR(20) DEFAULT 'MEDIUM',
        -- Values: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    validation_performed BOOLEAN DEFAULT FALSE,
    validation_results JSONB,
    
    -- Execution
    execution_status VARCHAR(50) DEFAULT 'pending',
        -- Values: 'pending', 'approved', 'running', 'completed', 'failed', 'rolled_back'
    executed_at TIMESTAMP,
    executed_by UUID REFERENCES users(id),
    execution_output TEXT,
    exit_code INTEGER,
    
    -- AI Generation
    generated_by VARCHAR(50),
        -- Values: 'gpt-4', 'claude-3', 'manual'
    generation_prompt TEXT,
    
    -- Approval Workflow
    requires_approval BOOLEAN DEFAULT TRUE,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP,
    approval_notes TEXT,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_script_type CHECK (script_type IN ('bash', 'ansible', 'powershell', 'python')),
    CONSTRAINT check_risk CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

CREATE INDEX idx_script_vuln ON remediation_scripts(vulnerability_id);
CREATE INDEX idx_script_org ON remediation_scripts(organization_id);
CREATE INDEX idx_script_status ON remediation_scripts(execution_status);


-- ============================================
-- TABLE 8: AUDIT_LOGS
-- ============================================
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Event
    event_type VARCHAR(100) NOT NULL,
        -- Examples: 'user.login', 'scan.created', 'vulnerability.resolved', 'script.executed'
    event_category VARCHAR(50),
        -- Values: 'auth', 'scan', 'vulnerability', 'remediation', 'admin'
    
    -- Details
    resource_type VARCHAR(50),
        -- Example: 'scan', 'asset', 'user'
    resource_id UUID,
    action VARCHAR(50),
        -- Values: 'create', 'read', 'update', 'delete', 'execute'
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    metadata JSONB DEFAULT '{}',
        -- Additional context
    
    -- Status
    status VARCHAR(20),
        -- Values: 'success', 'failure'
    error_message TEXT,
    
    -- Timestamp
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_action CHECK (action IN ('create', 'read', 'update', 'delete', 'execute'))
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_type ON audit_logs(event_type);
CREATE INDEX idx_audit_date ON audit_logs(created_at DESC);


-- ============================================
-- TABLE 9: API_KEYS (Pour intégrations)
-- ============================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    -- Key
    key_hash VARCHAR(255) UNIQUE NOT NULL,
        -- Hashed API key (never store plain text)
    key_prefix VARCHAR(20),
        -- First 8 chars for identification (e.g., 'sk_live_abc123...')
    name VARCHAR(255),
        -- Example: 'Production API Key', 'CI/CD Integration'
    
    -- Permissions
    scopes TEXT[] DEFAULT '{}',
        -- Example: ['scans:read', 'scans:write', 'vulnerabilities:read']
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    
    -- Expiration
    expires_at TIMESTAMP,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_apikey_org ON api_keys(organization_id);
CREATE INDEX idx_apikey_hash ON api_keys(key_hash);


-- ============================================
-- TABLE 10: NOTIFICATIONS
-- ============================================
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    -- Notification
    type VARCHAR(50) NOT NULL,
        -- Values: 'scan_completed', 'critical_vulnerability', 'remediation_completed', 'scan_failed'
    title VARCHAR(255) NOT NULL,
    message TEXT,
    
    -- Priority
    priority VARCHAR(20) DEFAULT 'normal',
        -- Values: 'low', 'normal', 'high', 'urgent'
    
    -- Related Resources
    related_resource_type VARCHAR(50),
        -- Example: 'scan', 'vulnerability'
    related_resource_id UUID,
    
    -- Status
    read BOOLEAN DEFAULT FALSE,
    read_at TIMESTAMP,
    
    -- Delivery
    sent_via TEXT[] DEFAULT '{}',
        -- Example: ['email', 'webhook', 'ui']
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT check_priority CHECK (priority IN ('low', 'normal', 'high', 'urgent'))
);

CREATE INDEX idx_notif_user ON notifications(user_id);
CREATE INDEX idx_notif_org ON notifications(organization_id);
CREATE INDEX idx_notif_read ON notifications(read);
CREATE INDEX idx_notif_date ON notifications(created_at DESC);
```

---

## 🔐 AUTHENTIFICATION & RBAC

### Système de Rôles

```python
ROLES_PERMISSIONS = {
    "admin": {
        "description": "Accès complet à l'organization",
        "permissions": [
            # Users
            "users:create", "users:read", "users:update", "users:delete",
            # Assets
            "assets:create", "assets:read", "assets:update", "assets:delete",
            # Scans
            "scans:create", "scans:read", "scans:update", "scans:delete",
            # Vulnerabilities
            "vulnerabilities:read", "vulnerabilities:update", "vulnerabilities:delete",
            # Remediation
            "remediation:create", "remediation:execute", "remediation:approve",
            # Organization
            "organization:update", "organization:billing",
            # API Keys
            "apikeys:create", "apikeys:read", "apikeys:revoke"
        ]
    },
    
    "manager": {
        "description": "Gestionnaire de sécurité",
        "permissions": [
            # Assets
            "assets:create", "assets:read", "assets:update",
            # Scans
            "scans:create", "scans:read",
            # Vulnerabilities
            "vulnerabilities:read", "vulnerabilities:update",
            # Remediation
            "remediation:create", "remediation:approve"
        ]
    },
    
    "analyst": {
        "description": "Analyste sécurité",
        "permissions": [
            # Assets
            "assets:read",
            # Scans
            "scans:create", "scans:read",
            # Vulnerabilities
            "vulnerabilities:read", "vulnerabilities:update",
            # Remediation
            "remediation:create"
        ]
    },
    
    "viewer": {
        "description": "Lecture seule",
        "permissions": [
            "assets:read",
            "scans:read",
            "vulnerabilities:read"
        ]
    }
}
```

### Implémentation JWT

```python
# backend/src/api/auth.py

from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(user_id: str, organization_id: str, role: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": user_id,
        "org_id": organization_id,
        "role": role,
        "exp": expire
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
```

---

## 📋 ROADMAP DE DÉVELOPPEMENT

### PHASE 1 : Infrastructure (Semaines 1-4)

#### Semaine 1 : Base de données PostgreSQL
```
OBJECTIF : Migrer de JSON vers PostgreSQL avec schema complet

TÂCHES :
1. Créer les migrations Alembic
   - Fichier : backend/alembic/versions/001_create_schema.py
   - Contenu : Toutes les tables du schéma ci-dessus

2. Implémenter les modèles SQLAlchemy
   - Fichier : backend/src/database/models.py
   - Classes : Organization, User, Asset, Scan, Vulnerability, etc.

3. Créer les fonctions d'initialisation
   - Fichier : backend/src/database/init_db.py
   - Fonction pour créer admin par défaut
   - Seed data pour testing

4. Tester les migrations
   - Commande : alembic upgrade head
   - Vérifier toutes les tables créées
   - Tester rollback : alembic downgrade -1

PROMPT POUR CURSOR :
"Crée les modèles SQLAlchemy pour toutes les tables définies dans le schéma.
Utilise les mêmes noms de colonnes et contraintes. Ajoute les relationships
entre les tables (Organization.users, Asset.scans, etc.)"
```

#### Semaine 2 : Authentification JWT
```
OBJECTIF : Système de login/register fonctionnel

TÂCHES :
1. Créer le module d'authentification
   - Fichier : backend/src/api/auth.py
   - Endpoints : /auth/register, /auth/login, /auth/me

2. Implémenter JWT middleware
   - Fichier : backend/src/api/dependencies.py
   - Fonction : get_current_user(), require_permission()

3. Ajouter RBAC
   - Fichier : backend/src/core/permissions.py
   - Décorateurs : @require_role("admin"), @require_permission("scans:create")

4. Tester avec Postman/Insomnia
   - Créer un compte
   - Se connecter
   - Appeler /auth/me avec le token

PROMPT POUR CURSOR :
"Implémente un système d'authentification JWT complet avec :
- Endpoint /auth/register pour créer un compte (crée aussi l'organization)
- Endpoint /auth/login qui retourne un JWT
- Middleware get_current_user() qui vérifie le JWT
- RBAC avec vérification des permissions"
```

#### Semaine 3 : Multi-tenancy
```
OBJECTIF : Isolation complète des données par organization

TÂCHES :
1. Ajouter organization_id partout
   - Fichier : Tous les endpoints API
   - Règle : TOUJOURS filtrer par current_user.organization_id

2. Créer un middleware de filtrage
   - Fichier : backend/src/api/middleware/tenant_filter.py
   - Auto-ajoute organization_id dans toutes les queries

3. Tests d'isolation
   - Créer 2 organizations
   - Vérifier qu'elles ne voient pas les données l'une de l'autre

PROMPT POUR CURSOR :
"Ajoute le multi-tenancy à tous les endpoints.
Règle : chaque requête doit automatiquement filtrer par
current_user.organization_id. Crée un decorator @tenant_scoped
qui s'assure qu'on n'accède qu'aux ressources de notre organization."
```

#### Semaine 4 : Connexion Frontend ↔ Backend
```
OBJECTIF : Frontend peut appeler le backend avec JWT

TÂCHES :
1. Configurer Axios avec intercepteurs
   - Fichier : frontend/lib/api.js
   - Intercepteur pour ajouter JWT automatiquement
   - Gestion des erreurs 401

2. Créer les services frontend
   - Fichier : frontend/lib/services/authService.js
   - Fonctions : login(), register(), logout(), getMe()

3. Créer pages login/register
   - Fichier : frontend/pages/login.js
   - Fichier : frontend/pages/register.js
   - Design avec Material-UI

4. Protéger les routes
   - Fichier : frontend/components/ProtectedRoute.js
   - Redirection vers /login si pas authentifié

PROMPT POUR CURSOR :
"Crée un système d'authentification frontend complet :
- Page de login avec form (email, password)
- Page de register avec form (email, password, nom, nom organization)
- Service authService qui appelle l'API backend
- Stockage du JWT dans localStorage
- ProtectedRoute component qui vérifie l'auth avant d'afficher les pages"
```

---

### PHASE 2 : Fonctionnalités Core (Semaines 5-8)

#### Semaine 5-6 : Gestion des Assets
```
OBJECTIF : Interface pour gérer les serveurs des clients

TÂCHES :
1. API Backend
   - GET /assets - Liste des assets
   - POST /assets - Ajouter un asset
   - GET /assets/{id} - Détails d'un asset
   - PUT /assets/{id} - Modifier un asset
   - DELETE /assets/{id} - Supprimer un asset

2. Frontend - Page Assets
   - Fichier : frontend/pages/assets.js
   - Table avec liste des assets
   - Bouton "Add Asset" ouvre un modal
   - Formulaire : hostname, IP, type, environment, tags

3. Validation
   - IP valide (IPv4/IPv6)
   - Hostname valide
   - Pas de doublons d'IP dans la même organization

PROMPT POUR CURSOR :
"Crée un CRUD complet pour les assets :
Backend : endpoints /assets avec filtrage par organization_id
Frontend : page avec Material-UI Table, bouton Add Asset, modal avec form
Validation : IP doit être valide, pas de doublon"
```

#### Semaine 7 : Système de Scans
```
OBJECTIF : Lancer des scans depuis le frontend

TÂCHES :
1. API Backend
   - POST /scans - Créer un scan (ajoute dans queue Celery)
   - GET /scans - Liste des scans
   - GET /scans/{id} - Détails + vulnérabilités
   - WebSocket /ws/scans/{id} - Progression en temps réel

2. Celery Worker
   - Fichier : backend/src/workers/scan_worker.py
   - Task : execute_scan(scan_id)
   - Utilise le Collector existant
   - Envoie updates via WebSocket

3. Frontend
   - Fichier : frontend/pages/scans/new.js
   - Sélection asset
   - Choix type de scan (quick, full, stealth)
   - Bouton "Start Scan"

PROMPT POUR CURSOR :
"Implémente le système de scans :
Backend : endpoint POST /scans qui crée un scan et lance une Celery task
Celery task : exécute le scan Nmap et envoie les updates via WebSocket
Frontend : page pour lancer un scan, affiche la progression en temps réel"
```

#### Semaine 8 : Analyse IA & Scripts
```
OBJECTIF : Connecter les fonctionnalités IA existantes

TÂCHES :
1. API Backend
   - POST /vulnerabilities/{id}/analyze - Analyse IA
   - POST /vulnerabilities/{id}/generate-script - Génère script
   - GET /remediation-scripts/{id} - Récupère un script

2. Intégrer le code existant
   - Utiliser le Analyzer existant
   - Utiliser le Generator existant
   - Sauvegarder résultats en BDD

3. Frontend
   - Bouton "Analyze with AI" sur chaque vulnérabilité
   - Affichage de l'analyse IA
   - Bouton "Generate Fix" pour créer le script
   - Affichage du script avec syntax highlighting

PROMPT POUR CURSOR :
"Connecte les fonctionnalités IA existantes :
- Endpoint qui appelle le Analyzer pour analyser une vulnérabilité
- Sauvegarde le résultat dans vulnerability.ai_analysis
- Endpoint qui génère un script de remédiation
- Sauvegarde dans remediation_scripts table
Frontend : boutons pour déclencher ces actions, affichage des résultats"
```

---

### PHASE 3 : Features Avancées (Semaines 9-12)

#### Semaine 9-10 : Agent d'Exécution
```
OBJECTIF : Appliquer automatiquement les correctifs

TÂCHES :
1. SSH Agent
   - Fichier : backend/src/core/executor.py
   - Connexion SSH aux assets
   - Exécution du script
   - Capture output et exit code

2. Sécurité
   - Stockage sécurisé des credentials SSH
   - Sandbox pour tester les scripts
   - Rollback automatique en cas d'erreur

3. Workflow d'approbation
   - Scripts doivent être approuvés avant exécution
   - Notification aux admins
   - Logs d'exécution complets

PROMPT POUR CURSOR :
"Crée un agent d'exécution de scripts :
- Connexion SSH aux assets (utilise Paramiko)
- Exécution sécurisée du script bash
- Capture output en temps réel
- En cas d'erreur, exécute le rollback script
- Sauvegarde tout dans remediation_scripts (execution_status, output, exit_code)"
```

#### Semaine 11 : Intégrations
```
OBJECTIF : Intégrer avec outils externes

TÂCHES :
1. Webhooks
   - Fichier : backend/src/integrations/webhooks.py
   - Envoyer notifications sur événements
   - Event types : scan_completed, critical_vulnerability, etc.

2. Slack Integration
   - Envoyer alerts sur Slack channel
   - Commandes Slack : /vulnscan status, /vulnscan list

3. API Keys
   - Générer des API keys pour intégrations
   - Endpoints : POST /api-keys, GET /api-keys, DELETE /api-keys/{id}

PROMPT POUR CURSOR :
"Ajoute un système de webhooks :
- Table webhook_subscriptions avec (organization_id, url, events[])
- Quand un événement se produit, envoie un POST au webhook
- Retry logic en cas d'échec
- Page frontend pour configurer les webhooks"
```

#### Semaine 12 : Reporting & Dashboards
```
OBJECTIF : Tableaux de bord et rapports

TÂCHES :
1. Dashboard API
   - Endpoint : GET /dashboard/stats
   - Métriques : total assets, scans this month, open vulnerabilities,
     avg risk score, trend data

2. Frontend Dashboard
   - Fichier : frontend/pages/dashboard.js
   - Cards avec stats
   - Charts (Risk over time, Vulnerability distribution, Top affected assets)
   - Utiliser Recharts ou Chart.js

3. Export PDF
   - Générer rapport PDF avec vulnérabilités
   - Utiliser weasyprint ou reportlab

PROMPT POUR CURSOR :
"Crée un dashboard avec statistiques :
Backend : endpoint qui calcule les métriques de sécurité
Frontend : page avec Material-UI Cards et Charts
Affiche : nombre d'assets, scans du mois, vulns ouvertes,
graphique de trend du risk score sur 30 jours"
```

---

## 🚀 DÉPLOIEMENT

### Architecture de Déploiement

```yaml
# docker-compose.production.yml

version: '3.8'

services:
  # Frontend Next.js
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - NEXT_PUBLIC_API_URL=https://api.vulnagent.com
    restart: always
    networks:
      - vulnagent-network

  # Backend FastAPI
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://vulnagent:${DB_PASSWORD}@db:5432/vulnagent_prod
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    restart: always
    networks:
      - vulnagent-network

  # Celery Worker
  worker:
    build:
      context: ./backend
      dockerfile: Dockerfile.prod
    command: celery -A src.workers.celery_app worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://vulnagent:${DB_PASSWORD}@db:5432/vulnagent_prod
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    restart: always
    networks:
      - vulnagent-network

  # PostgreSQL
  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=vulnagent
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=vulnagent_prod
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: always
    networks:
      - vulnagent-network

  # Redis (pour Celery)
  redis:
    image: redis:7-alpine
    restart: always
    networks:
      - vulnagent-network

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - frontend
      - backend
    restart: always
    networks:
      - vulnagent-network

volumes:
  postgres_data:

networks:
  vulnagent-network:
    driver: bridge
```

### Déploiement chez les Clients

**Option 1 : SaaS Cloud (Recommandé)**
```
┌──────────────────────────────────────┐
│      Client 1 (Acme Corp)            │
│  - Se connecte via web browser       │
│  - Données isolées (tenant_id)       │
└──────────────────────────────────────┘
           │
           ↓
┌──────────────────────────────────────┐
│   Votre Infrastructure Cloud         │
│   (AWS/Azure/GCP)                    │
│  - Multi-tenant                      │
│  - Tous les clients partagent        │
│  - Isolation par organization_id     │
└──────────────────────────────────────┘
```

**Option 2 : On-Premise (Grandes Entreprises)**
```
┌──────────────────────────────────────┐
│  Infrastructure Client (Acme Corp)   │
│                                      │
│  ┌────────────────────────────────┐ │
│  │  Docker Compose                │ │
│  │  - Frontend                    │ │
│  │  - Backend                     │ │
│  │  - PostgreSQL                  │ │
│  │  - Workers                     │ │
│  └────────────────────────────────┘ │
│                                      │
│  Vous fournissez :                  │
│  - docker-compose.yml               │
│  - Scripts d'installation           │
│  - Documentation                    │
└──────────────────────────────────────┘
```

**Script d'Installation On-Premise**
```bash
#!/bin/bash
# install.sh

echo "=== VulnAgent Installation ==="

# 1. Vérifier Docker
if ! command -v docker &> /dev/null; then
    echo "Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
fi

# 2. Créer .env
cat > .env << EOF
DB_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET_KEY=$(openssl rand -base64 32)
OPENAI_API_KEY=your-api-key-here
EOF

# 3. Lancer
docker-compose up -d

# 4. Init DB
docker-compose exec backend alembic upgrade head

# 5. Créer admin
docker-compose exec backend python -m src.scripts.create_admin \
  --email admin@company.com \
  --password changeme123

echo "=== Installation Complete ==="
echo "Access at: http://localhost:3000"
echo "Default credentials: admin@company.com / changeme123"
```

---

## 📊 MODÈLE DE PRICING

### Tiers de Subscription

```python
PRICING_TIERS = {
    "free": {
        "price_monthly": 0,
        "price_yearly": 0,
        "max_assets": 10,
        "max_scans_per_month": 50,
        "features": [
            "Basic vulnerability scanning",
            "AI analysis (limited)",
            "Community support"
        ],
        "stripe_price_id": None
    },
    
    "pro": {
        "price_monthly": 99,
        "price_yearly": 990,  # 2 mois gratuits
        "max_assets": 100,
        "max_scans_per_month": 1000,
        "features": [
            "Advanced scanning",
            "Unlimited AI analysis",
            "Script generation",
            "Email support",
            "API access"
        ],
        "stripe_price_id": "price_pro_monthly"
    },
    
    "business": {
        "price_monthly": 499,
        "price_yearly": 4990,
        "max_assets": 1000,
        "max_scans_per_month": None,  # Illimité
        "features": [
            "Everything in Pro",
            "Multi-user (up to 10)",
            "RBAC",
            "SSO/SAML",
            "Priority support 24/7",
            "Custom integrations",
            "SLA 99.9%"
        ],
        "stripe_price_id": "price_business_monthly"
    },
    
    "enterprise": {
        "price_monthly": "Custom",
        "price_yearly": "Custom",
        "max_assets": None,  # Illimité
        "max_scans_per_month": None,
        "features": [
            "Everything in Business",
            "On-premise deployment option",
            "Unlimited users",
            "Dedicated support engineer",
            "Custom SLA",
            "Professional services",
            "Compliance reports (SOC 2, ISO)"
        ],
        "stripe_price_id": None
    }
}
```

---

## 🎯 MÉTRIQUES DE SUCCÈS

### KPIs Techniques
```
SEMAINE 4 :
- ✅ Auth fonctionne (login/register)
- ✅ Multi-tenancy implémenté
- ✅ Frontend connecté au backend

SEMAINE 8 :
- ✅ Scans fonctionnent depuis le frontend
- ✅ Analyse IA opérationnelle
- ✅ Génération de scripts

SEMAINE 12 :
- ✅ Agent d'exécution fonctionnel
- ✅ Dashboards et reporting
- ✅ Déploiement Docker complet
```

### KPIs Business (Post-lancement)
```
MOIS 1-3 :
- 100 utilisateurs free tier
- 10 clients payants (pro/business)
- $1,000 MRR

MOIS 6 :
- 1,000 utilisateurs free tier
- 50 clients payants
- $10,000 MRR

MOIS 12 :
- 10,000 utilisateurs free tier
- 200 clients payants
- $50,000 MRR
```

---

## 🛠️ STACK TECHNIQUE FINAL

```yaml
Backend:
  Language: Python 3.10+
  Framework: FastAPI
  Database: PostgreSQL 15
  ORM: SQLAlchemy
  Migrations: Alembic
  Auth: JWT (python-jose)
  Password: bcrypt (passlib)
  Task Queue: Celery
  Broker: Redis
  AI: OpenAI API / Anthropic API
  Scanning: Nmap + python-nmap
  SSH: Paramiko

Frontend:
  Framework: Next.js 14
  UI Library: Material-UI (MUI)
  State: React Hooks
  HTTP Client: Axios
  WebSocket: socket.io-client
  Charts: Recharts
  Forms: react-hook-form

Infrastructure:
  Containerization: Docker + Docker Compose
  Reverse Proxy: Nginx
  SSL: Let's Encrypt (Certbot)
  Monitoring: Prometheus + Grafana (optionnel)
  Logs: ELK Stack (optionnel)

Deployment:
  Cloud: AWS / Azure / GCP
  CI/CD: GitHub Actions
  Registry: Docker Hub / AWS ECR
```

---

## 📝 CHECKLIST DE DÉVELOPPEMENT

### Phase 1 : Infrastructure ✅
```
□ Migration PostgreSQL complète
□ Modèles SQLAlchemy créés
□ Migrations Alembic fonctionnelles
□ Authentification JWT implémentée
□ Endpoints /auth/register, /auth/login, /auth/me
□ Middleware get_current_user()
□ Multi-tenancy dans tous les endpoints
□ Tests d'isolation entre tenants
□ Frontend login/register pages
□ ProtectedRoute component
□ Axios configured with JWT interceptors
```

### Phase 2 : Features Core ✅
```
□ CRUD Assets complet (backend + frontend)
□ System de scans fonctionnel
□ Celery worker pour scans asynchrones
□ WebSocket pour progression temps réel
□ Analyse IA connectée
□ Génération de scripts connectée
□ Page de détails des vulnérabilités
□ Affichage des scripts générés
```

### Phase 3 : Features Avancées ✅
```
□ Agent SSH d'exécution
□ Système de rollback
□ Workflow d'approbation
□ Webhooks
□ API Keys pour intégrations
□ Dashboard avec métriques
□ Export PDF
□ Notifications
```

### Phase 4 : Production ✅
```
□ Docker Compose production-ready
□ Nginx reverse proxy configuré
□ SSL/TLS avec Let's Encrypt
□ Logs centralisés
□ Monitoring basique
□ Backup automatique PostgreSQL
□ Script d'installation on-premise
□ Documentation complète
```

---

## 🎓 GUIDES CURSOR

### Guide 1 : Créer les Modèles SQLAlchemy

**Prompt pour Cursor :**
```
Crée les modèles SQLAlchemy pour mon application de gestion de vulnérabilités.

TABLES NÉCESSAIRES :
1. organizations (id, name, slug, subscription_tier, max_assets, created_at)
2. users (id, organization_id, email, hashed_password, full_name, role, is_active)
3. assets (id, organization_id, hostname, ip_address, asset_type, os, tags, environment, is_active)
4. scans (id, organization_id, asset_id, scan_type, status, started_at, completed_at, vulnerabilities_count)
5. vulnerabilities (id, scan_id, organization_id, cve_id, title, severity, cvss_score, description, status)
6. remediation_scripts (id, vulnerability_id, organization_id, script_content, rollback_script, execution_status)
7. audit_logs (id, organization_id, user_id, event_type, resource_type, resource_id, created_at)

RÈGLES :
- Utilise UUID pour tous les ID
- Ajoute les relationships entre tables (Organization.users, Scan.vulnerabilities, etc.)
- Ajoute les indexes sur les colonnes fréquemment requêtées
- Utilise des Enums pour les champs avec valeurs limitées (severity, status, role, etc.)

Fichier : backend/src/database/models.py
```

### Guide 2 : Créer l'Auth JWT

**Prompt pour Cursor :**
```
Implémente un système d'authentification JWT complet.

ENDPOINTS NÉCESSAIRES :
1. POST /auth/register
   - Input : email, password, full_name, organization_name
   - Crée une nouvelle organization
   - Crée un user admin dans cette organization
   - Hash le password avec bcrypt

2. POST /auth/login
   - Input : email, password
   - Vérifie le password
   - Retourne un JWT token avec payload : {sub: user_id, org_id: organization_id, role: role}

3. GET /auth/me
   - Requires JWT
   - Retourne les infos de l'utilisateur connecté

DEPENDENCIES :
- Crée get_current_user() qui décode le JWT et retourne le User
- Crée require_permission(permission: str) pour le RBAC

Fichiers : 
- backend/src/api/routes/auth.py
- backend/src/api/dependencies.py
```

### Guide 3 : Connecter Frontend → Backend

**Prompt pour Cursor :**
```
Connecte le frontend Next.js au backend FastAPI avec authentification JWT.

FICHIERS À CRÉER :

1. frontend/lib/api.js
   - Instance Axios configurée avec baseURL
   - Interceptor pour ajouter le JWT automatiquement depuis localStorage
   - Interceptor pour gérer les erreurs 401 (redirect vers /login)

2. frontend/lib/services/authService.js
   - login(email, password) : appelle POST /auth/login, sauvegarde le token
   - register(data) : appelle POST /auth/register
   - logout() : supprime le token et redirect
   - getMe() : appelle GET /auth/me

3. frontend/pages/login.js
   - Form avec email + password
   - Appelle authService.login()
   - Redirect vers /dashboard après succès

4. frontend/components/ProtectedRoute.js
   - Composant qui wraps les pages protégées
   - Vérifie si token existe dans localStorage
   - Redirect vers /login si pas de token

UTILISE Material-UI pour les composants.
```

### Guide 4 : Créer le CRUD Assets

**Prompt pour Cursor :**
```
Crée un CRUD complet pour la gestion des assets (serveurs).

BACKEND (backend/src/api/routes/assets.py) :
- GET /assets : liste des assets de l'organization (filtré par current_user.organization_id)
- POST /assets : créer un asset (validate IP, pas de doublon)
- GET /assets/{id} : détails d'un asset
- PUT /assets/{id} : modifier un asset
- DELETE /assets/{id} : supprimer un asset

FRONTEND (frontend/pages/assets.js) :
- Material-UI Table avec la liste des assets
- Colonnes : hostname, IP, type, environment, tags, last_seen
- Bouton "Add Asset" qui ouvre un Dialog
- Form dans le Dialog : hostname, ip_address, asset_type, environment, tags
- Actions : Edit (ouvre Dialog), Delete (confirmation)

VALIDATION :
- IP doit être IPv4 ou IPv6 valide
- Hostname optionnel mais si présent, doit être valide
- Pas de doublon d'IP dans la même organization
```

### Guide 5 : Système de Scans

**Prompt pour Cursor :**
```
Implémente le système de scans avec Celery et WebSocket.

BACKEND :

1. API (backend/src/api/routes/scans.py) :
   - POST /scans : crée un scan, lance la Celery task, retourne scan_id
   - GET /scans : liste des scans de l'organization
   - GET /scans/{id} : détails + liste des vulnérabilités

2. Celery Worker (backend/src/workers/scan_worker.py) :
   - Task : execute_scan(scan_id)
   - Steps :
     a) Récupère le scan et l'asset depuis la DB
     b) Lance le Collector.scan(asset.ip_address)
     c) Parse les résultats
     d) Crée les Vulnerability objects
     e) Update scan.status = 'completed'
     f) Envoie WebSocket update à chaque étape

3. WebSocket (backend/src/api/websocket.py) :
   - Route : /ws/scans/{scan_id}
   - Envoie : {"progress": 45, "status": "scanning", "message": "Analyzing port 80..."}

FRONTEND :

1. Page (frontend/pages/scans/new.js) :
   - Select pour choisir l'asset
   - Select pour le scan_type (quick, full, stealth)
   - Bouton "Start Scan"
   - Après click : créé le scan via API, redirect vers /scans/{id}

2. Page (frontend/pages/scans/[id].js) :
   - Connecte au WebSocket /ws/scans/{id}
   - Affiche une ProgressBar qui se met à jour en temps réel
   - Quand status = 'completed', affiche la liste des vulnérabilités trouvées
```

---

## 📚 DOCUMENTATION COMPLÉMENTAIRE

### Comment Tenable stocke les CVE

D'après mes recherches, Tenable utilise :

1. **Base de données locale CVE**
   - Synchronisation quotidienne avec NVD (National Vulnerability Database)
   - +77,000 CVE stockés localement
   - Champs : CVE ID, CVSS score, description, affected products, references

2. **Plugins Nessus**
   - +100,000 plugins de détection
   - Chaque plugin teste une vulnérabilité spécifique
   - Format : script Nessus Attack Scripting Language (NASL)

3. **Structure de stockage**
   ```
   vulnerabilities table:
   - cve_id (primary key)
   - cvss_score
   - severity
   - description
   - affected_products (JSON)
   - detection_plugins (array of plugin_ids)
   - exploit_available (boolean)
   - patch_available (boolean)
   - vendor_advisories (array of URLs)
   ```

4. **Mise à jour**
   - Téléchargement quotidien depuis NVD
   - Update des plugins automatique
   - Versioning des plugins

**Vous devriez faire pareil :**
```python
# Script de synchronisation CVE
# backend/src/scripts/sync_cve.py

import requests
from datetime import datetime, timedelta

def sync_nvd_cve():
    """Télécharge et importe les CVE depuis NVD"""
    
    # NVD API
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Récupérer les CVE des 30 derniers jours
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
    
    params = {
        "pubStartDate": start_date.isoformat(),
        "pubEndDate": end_date.isoformat()
    }
    
    response = requests.get(base_url, params=params)
    data = response.json()
    
    for cve in data.get("vulnerabilities", []):
        cve_item = cve["cve"]
        
        # Extraire les infos
        cve_id = cve_item["id"]
        description = cve_item["descriptions"][0]["value"]
        
        # CVSS
        cvss = cve_item.get("metrics", {}).get("cvssMetricV31", [{}])[0]
        cvss_score = cvss.get("cvssData", {}).get("baseScore")
        cvss_vector = cvss.get("cvssData", {}).get("vectorString")
        
        # Sauvegarder en DB
        db_cve = CVEDatabase(
            cve_id=cve_id,
            description=description,
            cvss_v3_score=cvss_score,
            cvss_v3_vector=cvss_vector,
            published_date=cve_item["published"],
            last_synced_at=datetime.utcnow()
        )
        db.merge(db_cve)
    
    db.commit()
    print(f"Synced {len(data['vulnerabilities'])} CVE")
```

---

## ✅ PROCHAINES ÉTAPES IMMÉDIATES

### À faire cette semaine :

1. **Lundi-Mardi : Base de données**
   ```bash
   cd backend
   alembic revision -m "create_complete_schema"
   # Copier le schéma SQL ci-dessus dans la migration
   alembic upgrade head
   ```

2. **Mercredi : Authentification**
   - Implémenter /auth/register, /auth/login, /auth/me
   - Tester avec Postman

3. **Jeudi : Frontend Login**
   - Créer pages login.js et register.js
   - Tester le flow complet

4. **Vendredi : Premier endpoint multi-tenant**
   - GET /assets avec filtrage par organization_id
   - Tester avec 2 organizations différentes

### Questions à se poser :

1. **Quel modèle de déploiement privilégier ?**
   - SaaS cloud multi-tenant (recommandé au début)
   - On-premise (pour grandes entreprises plus tard)

2. **Quelle AI utiliser ?**
   - OpenAI GPT-4 (plus cher, meilleur qualité)
   - Anthropic Claude (bon rapport qualité/prix)
   - Local LLaMA (gratuit, moins bon)

3. **Quelle stack pour l'agent d'exécution ?**
   - SSH direct (simple)
   - Ansible (plus robuste)
   - Agent installé sur les serveurs (plus complexe)

---

**FIN DU CAHIER DES CHARGES**

Ce document doit être votre référence principale pour les 12 prochaines semaines.
Utilisez-le avec Cursor pour générer le code étape par étape.

**Bon courage ! 🚀**