# 📋 CAHIER DES CHARGES - Ce qui reste à faire
## Vulnerability Agent IA - Roadmap vers MVP Commercial

**Date** : 12 février 2026  
**État actuel** : ~65% d'un MVP commercial  
**Objectif** : Atteindre 100% en 6 semaines

---

## 📊 ÉTAT ACTUEL DÉTAILLÉ

### ✅ BACKEND - CE QUI EST FAIT (85%)

#### Base de données ✅
- [x] 10 tables PostgreSQL créées
- [x] Modèles SQLAlchemy complets
- [x] Migrations Alembic fonctionnelles
- [x] Relationships entre tables

#### Authentification & Sécurité ✅
- [x] JWT authentication
- [x] `/auth/register` - Crée organization + user admin
- [x] `/auth/login` - Retourne JWT
- [x] `/auth/me` - Infos user connecté
- [x] Middleware `get_current_user()`
- [x] RBAC avec `require_permission()`
- [x] Multi-tenancy avec `tenant_scoped()`

#### CRUD Assets ✅
- [x] `GET /api/v1/assets` - Liste filtrée par organization
- [x] `POST /api/v1/assets` - Création avec validation IP
- [x] `GET /api/v1/assets/{id}` - Détails
- [x] `PUT /api/v1/assets/{id}` - Modification
- [x] `DELETE /api/v1/assets/{id}` - Suppression
- [x] Validation IPv4/IPv6
- [x] Pas de doublons IP par organization

#### Système de Scans ✅
- [x] `POST /api/v1/scans` - Création + lancement Celery task
- [x] `GET /api/v1/scans` - Liste filtrée
- [x] `GET /api/v1/scans/{id}` - Détails + vulnérabilités
- [x] WebSocket `/ws/scans/{id}` - Progression temps réel
- [x] Celery worker `execute_scan()`
- [x] Intégration Collector (Nmap)
- [x] Création automatique des Vulnerabilities en BDD

---

### ❌ BACKEND - CE QUI MANQUE (15%)

#### 1. Analyse IA des vulnérabilités
**Fichier à créer** : `backend/src/api/routes/vulnerabilities.py`

**Endpoints manquants** :
```python
POST /api/v1/vulnerabilities/{id}/analyze
- Input : vulnerability_id
- Action : 
  1. Récupère la vulnerability depuis la BDD
  2. Appelle Analyzer.analyze_vulnerability()
  3. Sauvegarde résultat dans vulnerability.ai_analysis (JSONB)
  4. Calcule vulnerability.ai_priority_score
- Output : { ai_analysis: {...}, priority_score: 8 }

GET /api/v1/vulnerabilities
- Liste des vulnerabilities (filtrée par organization)
- Avec filtres : severity, status, asset_id, scan_id

GET /api/v1/vulnerabilities/{id}
- Détails d'une vulnerability
```

**Intégration** : Utiliser le code existant `backend/src/core/analyzer.py`

#### 2. Génération de scripts de remédiation
**Fichier à créer** : `backend/src/api/routes/remediation.py`

**Endpoints manquants** :
```python
POST /api/v1/vulnerabilities/{id}/generate-script
- Input : vulnerability_id, target_os (ubuntu, centos, etc.)
- Action :
  1. Récupère la vulnerability
  2. Appelle Generator.generate_fix_script()
  3. Crée un RemediationScript en BDD
- Output : { script_id, script_content, rollback_script }

GET /api/v1/remediation-scripts/{id}
- Détails d'un script

PUT /api/v1/remediation-scripts/{id}/approve
- Approuver un script (passe en status 'approved')
- Requis avant exécution
```

**Intégration** : Utiliser le code existant `backend/src/core/generator.py`

#### 3. Agent d'exécution SSH
**Fichier à créer** : `backend/src/workers/executor_worker.py`

**Tâche Celery** :
```python
@celery_app.task
def execute_remediation_script(script_id: str):
    """
    1. Récupère le script depuis la BDD
    2. Récupère l'asset associé (via vulnerability → scan → asset)
    3. Connexion SSH à l'asset
    4. Exécute le script
    5. Capture output et exit_code
    6. Si erreur : exécute le rollback_script
    7. Met à jour script.execution_status, execution_output, exit_code
    """
```

**Endpoint** :
```python
POST /api/v1/remediation-scripts/{id}/execute
- Lance la Celery task execute_remediation_script
- Retourne task_id pour tracking
```

**Dépendances** : `paramiko` pour SSH

#### 4. Dashboard statistiques
**Fichier à créer** : `backend/src/api/routes/dashboard.py`

**Endpoint** :
```python
GET /api/v1/dashboard/stats
- Retourne :
  {
    "total_assets": 25,
    "active_assets": 23,
    "total_scans": 150,
    "scans_this_month": 42,
    "total_vulnerabilities": 234,
    "open_vulnerabilities": 180,
    "by_severity": {
      "CRITICAL": 12,
      "HIGH": 45,
      "MEDIUM": 89,
      "LOW": 34
    },
    "avg_risk_score": 6.7,
    "trend_30_days": [
      {"date": "2026-01-13", "vulnerabilities": 200, "risk_score": 7.2},
      {"date": "2026-01-20", "vulnerabilities": 195, "risk_score": 7.0},
      ...
    ]
  }
```

#### 5. Webhooks (optionnel pour MVP)
**Fichier** : `backend/src/integrations/webhooks.py` existe déjà

**À compléter** :
```python
# Table webhook_subscriptions déjà dans models.py ?
# Sinon à ajouter

POST /api/v1/webhooks
- Créer un webhook subscription
- Input : { url, events: ['scan_completed', 'critical_vulnerability'] }

GET /api/v1/webhooks
- Liste des webhooks

DELETE /api/v1/webhooks/{id}
- Supprimer un webhook
```

**Events à envoyer** :
- `scan_completed` : Quand un scan se termine
- `critical_vulnerability` : Quand une vuln CRITICAL est trouvée
- `remediation_completed` : Quand un script s'exécute avec succès

#### 6. Export PDF (optionnel pour MVP)
**Fichier à créer** : `backend/src/api/routes/reports.py`

```python
GET /api/v1/scans/{id}/report/pdf
- Génère un PDF avec :
  - Résumé du scan
  - Liste des vulnérabilités
  - Recommandations
- Utilise weasyprint ou reportlab
```

---

### ❌ FRONTEND - CE QUI MANQUE (40%)

#### 1. Layout avec Navigation
**Fichier à créer** : `frontend/components/Layout.js`

```jsx
// Navigation sidebar avec menu :
- Dashboard
- Assets
- Scans
- Vulnerabilities
- Settings
- Logout

// AppBar avec :
- Logo
- Nom de l'organization
- Avatar utilisateur
```

**Utiliser** : Material-UI Drawer + AppBar

#### 2. Page Assets complète
**Fichier à créer** : `frontend/pages/assets.js`

```jsx
// Composants :
- Material-UI DataGrid avec liste des assets
- Colonnes : hostname, IP, type, environment, tags, last_seen, actions
- Bouton "Add Asset" → ouvre Dialog
- Dialog avec form : hostname, ip_address, asset_type, environment, tags
- Actions par ligne : Edit (Dialog), Delete (confirmation)

// Features :
- Recherche/filtrage
- Tri par colonne
- Pagination
```

#### 3. Pages Scans
**Fichiers à créer** :

##### `frontend/pages/scans/index.js`
```jsx
// Liste des scans avec :
- DataGrid Material-UI
- Colonnes : asset, type, status, started_at, vulnerabilities_found, actions
- Bouton "New Scan" → redirect vers /scans/new
- Click sur ligne → redirect vers /scans/[id]
- Filtres : status, date range
```

##### `frontend/pages/scans/new.js`
```jsx
// Formulaire création scan :
- Select asset (liste des assets de l'org)
- Select scan_type : quick, full, stealth, compliance
- Bouton "Start Scan"
- Après submit : redirect vers /scans/[id]
```

##### `frontend/pages/scans/[id].js`
```jsx
// Page détails scan avec :
- En-tête : Asset, Type, Status, Durée
- Si status = 'running' :
  - ProgressBar en temps réel (WebSocket)
  - Messages de progression
- Si status = 'completed' :
  - Résumé : total ports, vulns found, risk score
  - Graphique distribution vulns par severity
  - DataGrid avec liste des vulnérabilités
  - Bouton "Analyze All with AI"
```

**WebSocket client** :
```javascript
// Hook useWebSocket
const ws = new WebSocket(`ws://localhost:8000/ws/scans/${scanId}`);
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  setProgress(data.progress);
  setStatus(data.status);
  setMessage(data.message);
};
```

#### 4. Pages Vulnerabilities
**Fichiers à créer** :

##### `frontend/pages/vulnerabilities/index.js`
```jsx
// Liste des vulnérabilités avec :
- DataGrid Material-UI
- Colonnes : CVE ID, Title, Severity, CVSS, Asset, Status, Actions
- Filtres : severity, status, asset
- Recherche par CVE ou titre
- Click sur ligne → redirect vers /vulnerabilities/[id]
```

##### `frontend/pages/vulnerabilities/[id].js`
```jsx
// Détails vulnerability avec :
- En-tête : CVE, Title, Severity badge, CVSS score
- Description complète
- Affected package, version, port
- References (liens cliquables)

// Actions :
- Bouton "Analyze with AI" → appelle POST /vulnerabilities/{id}/analyze
  - Affiche résultat dans Card : 
    - Business impact
    - Exploitability
    - Priority score
    - Recommendations

- Bouton "Generate Fix Script" → appelle POST /vulnerabilities/{id}/generate-script
  - Affiche le script dans CodeBlock avec syntax highlighting
  - Affiche le rollback script
  - Bouton "Approve & Execute" (si role = admin)
```

#### 5. Dashboard amélioré
**Fichier à améliorer** : `frontend/components/Dashboard.js`

```jsx
// Remplacer le contenu actuel par :

// Cards avec statistiques :
- Total Assets
- Active Scans
- Open Vulnerabilities  
- Average Risk Score

// Charts :
- Line Chart : Risk score trend (30 derniers jours)
- Bar Chart : Vulns by severity
- Pie Chart : Vulns by status (open, in_progress, resolved)

// Recent Activity :
- Liste des derniers scans
- Liste des vulns critiques récentes
```

**Utiliser** : Recharts ou Chart.js

#### 6. Page Settings (optionnel)
**Fichier** : `frontend/pages/settings.js`

```jsx
// Tabs :
- Organization : nom, plan, billing
- Users : liste des users, invite, rôles
- API Keys : générer, révoquer
- Webhooks : configurer URL et events
```

---

## 🎯 ROADMAP DÉTAILLÉE - 6 SEMAINES

### **SEMAINE 1 : Frontend - Pages essentielles**

#### Jour 1-2 : Layout + Navigation
```bash
FICHIERS :
- frontend/components/Layout.js
- frontend/components/Sidebar.js
- frontend/components/AppBar.js

PROMPT CURSOR :
"Crée un Layout Material-UI complet avec :
- Sidebar gauche avec menu : Dashboard, Assets, Scans, Vulnerabilities, Logout
- AppBar en haut avec nom de l'org et avatar utilisateur
- Responsive (menu collapse sur mobile)
- Utilise MUI Drawer et AppBar"
```

#### Jour 3-4 : Page Assets
```bash
FICHIER : frontend/pages/assets.js

PROMPT CURSOR :
"Crée la page Assets complète avec :
- DataGrid Material-UI avec colonnes : hostname, IP, type, environment, tags
- Bouton 'Add Asset' qui ouvre un Dialog
- Form dans Dialog : hostname, ip_address, asset_type, environment, tags (chips)
- Actions Edit/Delete par ligne
- Appelle assetsService pour CRUD
- Gestion erreurs avec Snackbar"
```

#### Jour 5 : Dashboard stats
```bash
FICHIER : frontend/components/Dashboard.js

PROMPT CURSOR :
"Crée un Dashboard avec :
- 4 Cards : Total Assets, Active Scans, Open Vulns, Avg Risk Score
- Appelle GET /api/v1/dashboard/stats (à créer backend aussi)
- Line Chart avec Recharts : risk score trend 30j
- Bar Chart : vulns by severity
- Liste : derniers scans"
```

---

### **SEMAINE 2 : Frontend - Pages Scans**

#### Jour 1-2 : Liste Scans
```bash
FICHIER : frontend/pages/scans/index.js

PROMPT CURSOR :
"Crée la page liste des scans avec :
- DataGrid MUI : asset, type, status, started_at, vulns_found
- Bouton 'New Scan'
- Click ligne → redirect /scans/[id]
- Badge de couleur pour status (running=blue, completed=green, failed=red)"
```

#### Jour 3 : Nouveau Scan
```bash
FICHIER : frontend/pages/scans/new.js

PROMPT CURSOR :
"Page pour créer un scan :
- Select asset (liste depuis assetsService.getAssets())
- Select scan_type : quick, full, stealth
- Bouton 'Start Scan'
- Après submit POST /scans, redirect vers /scans/{id}"
```

#### Jour 4-5 : Détails Scan + WebSocket
```bash
FICHIER : frontend/pages/scans/[id].js

PROMPT CURSOR :
"Page détails scan avec :
- Si status=running : ProgressBar + WebSocket /ws/scans/{id}
- Si completed : résumé + table vulns + chart distribution
- Utilise useEffect + WebSocket API
- Chart avec Recharts (pie chart severity distribution)"
```

---

### **SEMAINE 3 : Backend - Analyse IA + Scripts**

#### Jour 1-2 : Endpoints Vulnerabilities
```bash
FICHIER : backend/src/api/routes/vulnerabilities.py

PROMPT CURSOR :
"Crée les endpoints :
- GET /api/v1/vulnerabilities : liste filtrée par org
- GET /api/v1/vulnerabilities/{id} : détails
- POST /api/v1/vulnerabilities/{id}/analyze : 
  - Appelle Analyzer.analyze_vulnerability()
  - Sauvegarde dans vulnerability.ai_analysis
  - Calcule ai_priority_score
- Utilise le Analyzer existant dans src/core/analyzer.py"
```

#### Jour 3 : Endpoints Remediation
```bash
FICHIER : backend/src/api/routes/remediation.py

PROMPT CURSOR :
"Crée les endpoints :
- POST /api/v1/vulnerabilities/{id}/generate-script :
  - Appelle Generator.generate_fix_script()
  - Crée RemediationScript en BDD avec status='pending'
- GET /api/v1/remediation-scripts/{id} : détails
- PUT /api/v1/remediation-scripts/{id}/approve : passe en 'approved'
- Utilise le Generator existant dans src/core/generator.py"
```

#### Jour 4-5 : Dashboard Stats Backend
```bash
FICHIER : backend/src/api/routes/dashboard.py

PROMPT CURSOR :
"Endpoint GET /api/v1/dashboard/stats qui retourne :
- Compte assets, scans, vulns (filtré par org)
- Distribution par severity
- Avg risk score
- Trend 30 jours : query GROUP BY date avec vulns count et avg risk
- Utilise SQLAlchemy aggregations"
```

---

### **SEMAINE 4 : Frontend - Vulnerabilities**

#### Jour 1-2 : Liste Vulnerabilities
```bash
FICHIER : frontend/pages/vulnerabilities/index.js

PROMPT CURSOR :
"Page liste vulns avec :
- DataGrid MUI : CVE, Title, Severity (badge), CVSS, Asset, Status
- Filtres : severity (select), status (select), asset (autocomplete)
- Recherche texte (CVE ou titre)
- Click ligne → redirect /vulnerabilities/[id]"
```

#### Jour 3-5 : Détails Vulnerability + IA
```bash
FICHIER : frontend/pages/vulnerabilities/[id].js

PROMPT CURSOR :
"Page détails vuln avec :
- Card principale : CVE, titre, description, CVSS, severity badge
- Card technique : package, version, port, references
- Bouton 'Analyze with AI' :
  - Appelle POST /vulnerabilities/{id}/analyze
  - Affiche résultat dans Card expandable
- Bouton 'Generate Fix' :
  - Appelle POST /vulnerabilities/{id}/generate-script
  - Affiche script avec react-syntax-highlighter
  - Bouton 'Approve & Execute' (si admin)"
```

---

### **SEMAINE 5 : Backend - Agent d'exécution**

#### Jour 1-3 : SSH Executor
```bash
FICHIER : backend/src/workers/executor_worker.py

PROMPT CURSOR :
"Crée une Celery task execute_remediation_script(script_id) :
- Récupère RemediationScript depuis BDD
- Récupère l'Asset (via vuln → scan → asset)
- Utilise Paramiko pour connexion SSH
- Exécute le script bash
- Capture stdout, stderr, exit_code
- Si exit_code != 0 : exécute rollback_script
- Sauvegarde output et status en BDD
- Gestion timeout (5 min max)"
```

#### Jour 4 : Endpoint Execute
```bash
FICHIER : backend/src/api/routes/remediation.py (modifier)

PROMPT CURSOR :
"Ajoute endpoint :
POST /api/v1/remediation-scripts/{id}/execute
- Vérifie que status='approved'
- Vérifie permission 'remediation:execute'
- Lance execute_remediation_script.delay(script_id)
- Retourne task_id pour tracking"
```

#### Jour 5 : Credentials SSH sécurisés
```bash
FICHIER : backend/src/database/models.py (modifier Asset)

PROMPT CURSOR :
"Ajoute colonnes à Asset :
- ssh_username (encrypted)
- ssh_password (encrypted)
- ssh_private_key (encrypted)
Utilise Fernet (cryptography library) pour chiffrement
Crée utils/crypto.py avec encrypt/decrypt helpers"
```

---

### **SEMAINE 6 : Polish + Tests + Documentation**

#### Jour 1-2 : Webhooks (optionnel)
```bash
FICHIERS :
- backend/src/api/routes/webhooks.py
- backend/src/integrations/webhooks.py (compléter)

PROMPT CURSOR :
"Système de webhooks :
- Table webhook_subscriptions (org_id, url, events[], is_active)
- Endpoints CRUD webhooks
- Fonction send_webhook_event(org_id, event_type, payload)
- Retry logic avec exponential backoff
- Appeler dans : scan_worker (scan_completed), après analyse IA (critical_vuln)"
```

#### Jour 3 : Export PDF
```bash
FICHIER : backend/src/api/routes/reports.py

PROMPT CURSOR :
"Endpoint GET /api/v1/scans/{id}/report/pdf :
- Génère PDF avec reportlab ou weasyprint
- Sections : résumé scan, vulns par severity, recommandations
- Retourne PDF en bytes avec Content-Type: application/pdf
- Frontend : bouton Download Report qui fetch et télécharge"
```

#### Jour 4 : Tests E2E
```bash
FICHIERS : backend/tests/test_e2e.py

"Tests end-to-end :
1. Créer organization + user
2. Login → récupérer JWT
3. Créer asset
4. Créer scan
5. Attendre completion (mock ou réel)
6. Vérifier vulns créées
7. Analyser une vuln
8. Générer script
9. Approuver script
Utilise pytest + httpx"
```

#### Jour 5 : Documentation
```bash
FICHIERS :
- README.md (compléter)
- docs/API.md
- docs/DEPLOYMENT.md
- docs/USER_GUIDE.md

"Documentation complète :
- Installation (Docker, local)
- Configuration (.env variables)
- API endpoints (liste complète avec exemples curl)
- Guide utilisateur (screenshots)
- Architecture (diagrammes)
- Troubleshooting"
```

---

## 📋 CHECKLIST FINALE MVP

### Backend ✅
- [x] Base de données PostgreSQL
- [x] Authentification JWT
- [x] Multi-tenancy
- [x] CRUD Assets
- [x] Scans + Celery
- [ ] Analyse IA endpoints
- [ ] Scripts remédiation endpoints
- [ ] Agent SSH exécution
- [ ] Dashboard stats endpoint
- [ ] Webhooks (optionnel)
- [ ] Export PDF (optionnel)

### Frontend ✅
- [x] Pages login/register
- [x] ProtectedRoute
- [x] Services API (auth, assets)
- [ ] Layout + Navigation
- [ ] Page Assets complète
- [ ] Pages Scans (liste, new, détails)
- [ ] Pages Vulnerabilities (liste, détails)
- [ ] Dashboard avec stats
- [ ] Settings (optionnel)

### Infrastructure ✅
- [x] Docker Compose
- [x] Alembic migrations
- [x] Redis (Celery broker)
- [ ] Nginx reverse proxy (prod)
- [ ] SSL/HTTPS (prod)
- [ ] CI/CD GitHub Actions (optionnel)

### Documentation ✅
- [ ] README complet
- [ ] API documentation
- [ ] User guide
- [ ] Deployment guide

---

## 🚀 PROMPTS CURSOR RAPIDES

### Backend - Analyse IA
```
Crée backend/src/api/routes/vulnerabilities.py avec :
- GET /api/v1/vulnerabilities : liste (org_id filter)
- GET /api/v1/vulnerabilities/{id} : détails
- POST /api/v1/vulnerabilities/{id}/analyze :
  → Récupère vuln depuis BDD
  → Appelle src.core.analyzer.Analyzer.analyze_vulnerability()
  → Sauvegarde résultat dans vuln.ai_analysis (JSONB)
  → Calcule vuln.ai_priority_score (1-10)
  → Retourne le résultat
Utilise tenant_scoped, require_permission
```

### Backend - Scripts Remediation
```
Crée backend/src/api/routes/remediation.py avec :
- POST /api/v1/vulnerabilities/{id}/generate-script :
  → Appelle src.core.generator.Generator.generate_fix_script()
  → Crée RemediationScript en BDD (status='pending')
  → Retourne script_id, script_content, rollback_script
- GET /api/v1/remediation-scripts/{id} : détails
- PUT /api/v1/remediation-scripts/{id}/approve : status='approved'
Utilise le Generator existant
```

### Backend - Dashboard Stats
```
Crée backend/src/api/routes/dashboard.py avec :
GET /api/v1/dashboard/stats qui retourne JSON :
{
  total_assets, active_assets, total_scans, scans_this_month,
  total_vulnerabilities, open_vulnerabilities,
  by_severity: {CRITICAL: X, HIGH: Y, ...},
  avg_risk_score,
  trend_30_days: [{date, vulnerabilities_count, risk_score}, ...]
}
Utilise SQLAlchemy aggregations, GROUP BY, filtré par organization_id
```

### Frontend - Layout
```
Crée frontend/components/Layout.js avec Material-UI :
- Sidebar gauche (Drawer) : menu Dashboard, Assets, Scans, Vulnerabilities, Logout
- AppBar en haut : logo, nom org, avatar user
- Responsive (drawer collapse mobile)
- Active link highlight
- Utilise useRouter pour navigation
```

### Frontend - Page Assets
```
Crée frontend/pages/assets.js avec :
- DataGrid MUI : hostname, IP, type, environment, tags, last_seen
- Bouton 'Add Asset' → Dialog avec form
- Form : hostname, ip_address, asset_type (select), environment (select), tags (Autocomplete multiple)
- Actions Edit/Delete par ligne
- Appelle assetsService.getAssets(), createAsset(), updateAsset(), deleteAsset()
- Snackbar pour messages succès/erreur
```

### Frontend - Page Scans Liste
```
Crée frontend/pages/scans/index.js avec :
- DataGrid MUI : asset.hostname, type, status (badge coloré), started_at, vulnerabilities_count
- Bouton 'New Scan' → router.push('/scans/new')
- Click sur ligne → router.push(`/scans/${id}`)
- Filtres : status (running, completed, failed)
- Appelle scansService.getScans()
```

### Frontend - Page Scan Détails + WebSocket
```
Crée frontend/pages/scans/[id].js avec :
- Si status='running' :
  → LinearProgress + useEffect WebSocket ws://localhost:8000/ws/scans/{id}
  → Affiche message progression en temps réel
- Si status='completed' :
  → Cards résumé : total ports, open ports, vulns found, risk score
  → Pie Chart (Recharts) : distribution vulns par severity
  → DataGrid : liste vulnérabilités avec click → /vulnerabilities/{id}
Utilise scansService.getScan(id)
```

### Frontend - Page Vulnerabilities Liste
```
Crée frontend/pages/vulnerabilities/index.js avec :
- DataGrid MUI : CVE, Title, Severity (Chip coloré), CVSS, Asset, Status
- Filtres : severity (Select multiple), status (Select), asset (Autocomplete)
- Recherche texte : CVE ou Title
- Click ligne → /vulnerabilities/{id}
- Appelle vulnerabilitiesService.getVulnerabilities()
```

### Frontend - Page Vulnerability Détails + IA
```
Crée frontend/pages/vulnerabilities/[id].js avec :
- Card principale : CVE badge, Title, Description, CVSS score gauge
- Card technique : affected_package, version, port, protocol, references (liens)
- Bouton 'Analyze with AI' :
  → POST /vulnerabilities/{id}/analyze
  → Affiche Collapse avec résultat : business_impact, exploitability, priority_score
- Bouton 'Generate Fix' :
  → POST /vulnerabilities/{id}/generate-script
  → Affiche script avec react-syntax-highlighter (bash)
  → Bouton 'Approve & Execute' (si role=admin)
Utilise vulnerabilitiesService
```

---

## 🎯 PRIORITÉS ABSOLUES POUR LE MVP

### Must-Have (Semaines 1-4)
1. ✅ Frontend Layout + Navigation
2. ✅ Page Assets complète
3. ✅ Pages Scans (liste, new, détails avec WebSocket)
4. ✅ Backend Analyse IA endpoints
5. ✅ Backend Scripts remediation endpoints
6. ✅ Pages Vulnerabilities (liste, détails)
7. ✅ Dashboard stats (backend + frontend)

### Should-Have (Semaines 5-6)
8. ✅ Agent SSH exécution
9. ⚠️ Tests E2E
10. ⚠️ Documentation complète

### Nice-to-Have (Post-MVP)
11. ❌ Webhooks
12. ❌ Export PDF
13. ❌ Page Settings
14. ❌ API Keys management UI
15. ❌ Multi-language
16. ❌ Notifications in-app

---

## 📊 ESTIMATION DE TEMPS

| Tâche | Jours | Semaine |
|-------|-------|---------|
| Layout + Navigation | 2 | S1 |
| Page Assets | 2 | S1 |
| Dashboard stats | 1 | S1 |
| Pages Scans (3 pages) | 5 | S2 |
| Backend IA + Scripts | 5 | S3 |
| Pages Vulnerabilities | 5 | S4 |
| Agent SSH | 4 | S5 |
| Credentials encryption | 1 | S5 |
| Tests + Doc | 2 | S6 |
| **TOTAL** | **27 jours** | **6 semaines** |

---

## 🎓 CONSEILS POUR UTILISER CE CDC AVEC CURSOR

1. **Copiez le prompt correspondant** à votre tâche du jour
2. **Collez dans Cursor Chat** (Cmd+L)
3. **Cursor génère le code** complet
4. **Testez immédiatement** (lancer backend + frontend)
5. **Commitez** après chaque feature qui marche

### Workflow quotidien recommandé :
```bash
# Matin
1. Lire la tâche du jour dans le CDC
2. Copier le prompt Cursor
3. Générer le code
4. Tester

# Après-midi
5. Debug si nécessaire
6. Améliorer le code
7. Git commit
8. Passer à la tâche suivante

# Fin de journée
9. Update la checklist
10. Noter ce qui reste à faire demain
```

---

**FIN DU CAHIER DES CHARGES**

✅ Vous avez maintenant une roadmap COMPLÈTE et ACTIONNABLE pour finir votre MVP en 6 semaines.

Bon courage ! 🚀