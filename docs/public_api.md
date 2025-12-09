# Documentation complète des API, fonctions et composants

Dernière mise à jour : 09/12/2025  
Cette page couvre l’ensemble des surfaces publiques du projet Agent IA de cybersécurité : API HTTP, classes principales du cœur applicatif, utilitaires et flux d’usage recommandés. Toutes les informations ci‑dessous sont extraites du code source et peuvent servir de référence fonctionnelle ou d’aide à l’intégration.

---

## 1. Vue d’ensemble de l’architecture

- **Frontière HTTP** : application FastAPI (`src/api/main.py`) exposée sur `http://<hôte>:8000`, documentation OpenAPI intégrée (`/docs`, `/redoc`).  
- **Couche métier** : `Supervisor` orchestre trois moteurs spécialisés (`Collector`, `Analyzer`, `Generator`) et pilote les workflows asynchrones.  
- **Persistance** : gestionnaire SQLite (`src/database/database.py`) avec création automatique de schémas, transactions et statistiques.  
- **Utilitaires** : modules partagés pour la sécurité (`src/utils/security.py`), les logs (`src/utils/logger.py`), la validation (`src/utils/validators.py`) et les parseurs (`src/utils/parsers.py`).  
- **Supervision** : fichiers JSON de résultat (`data/workflow_results`) et journaux structurés (`logs/*.log`).

---

## 2. API HTTP (FastAPI)

### 2.1 Base routes

| Méthode | Chemin | Description | Exemple |
| --- | --- | --- | --- |
| `GET` | `/` | Vérifie que l’API est en ligne et retourne la version courante. | `curl http://localhost:8000/` |
| `GET` | `/health` | Ping applicatif + dépendances (base, superviseur, IA). | `curl http://localhost:8000/health` |
| `GET` | `/metrics` | Retourne des compteurs de scans (placeholders actuels). | `curl http://localhost:8000/metrics` |

Ces routes ne requièrent pas d’authentification. Les journaux détaillent chaque requête grâce au middleware (`setup_middlewares`).

### 2.2 Authentification

Toutes les routes sous `/api/v1` acceptent un jeton Bearer optionnel (`HTTPBearer`).  
- Si aucun jeton n’est fourni : l’utilisateur est `anonymous`.  
- Sinon, l’utilisateur est `authenticated` (placeholder actuel pour intégrer un vrai fournisseur d’identité).

### 2.3 Endpoints de scans (`/api/v1/scans`)

#### 2.3.1 POST `/api/v1/scan`

- **Modèle de requête** : `ScanRequest`
  - `target` (IP ou FQDN, validation stricte)
  - `scan_type` (`quick`, `full`, `stealth`, `aggressive`, `custom`)
  - Champs optionnels : `nmap_args`, `timeout`, `ports`, `scripts`, `exclude_hosts`
- **Réponse** : `ScanResponse`
  - `scan_id`, `target`, `status` (initialement `pending`), `started_at`
- **Traitement** :
  1. Vérifie qu’aucun scan actif ne cible la même machine.
  2. Ajoute la tâche dans `active_tasks`.
  3. Lance `run_scan_task` en arrière-plan (workflow `SCAN_ONLY` via `Supervisor`).

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Authorization: Bearer demo-token" \
  -H "Content-Type: application/json" \
  -d '{
        "target": "192.168.1.10",
        "scan_type": "full",
        "timeout": 600,
        "ports": "22,80,443"
      }'
```

#### 2.3.2 GET `/api/v1/scan/{scan_id}/results`

Deux handlers partagent actuellement ce chemin :
- **Handler historique** : renvoie l’état courant (pending/running/completed) et, si besoin, lit directement les fichiers `data/workflow_results/<workflow_id>.json` pour reconstruire la réponse.  
- **Handler final** (avec `response_model=Dict[str, Any]`) : accessible uniquement si `active_tasks[scan_id].status == "completed"` et retourne les sections `summary`, `vulnerabilities`, `services`, `open_ports`.

> **Recommandation** : consommer le second (typé) pour des intégrations nouvelles. Le premier peut servir de fallback si la tâche a été purgée de la mémoire.

#### 2.3.3 GET `/api/v1/scans`

Liste paginée des scans de l’utilisateur courant (données maintenues en mémoire tant que le processus tourne).
- Query params : `limit`, `offset`, `status`.

#### 2.3.4 DELETE `/api/v1/scan/{scan_id}`

Annule un scan en cours après vérification du propriétaire.

### 2.4 Analyse IA (`/api/v1/analyze`)

`POST /api/v1/analyze` prend `AnalysisRequest` (liste de vulnérabilités, contexte business, profondeur).  
- Délègue à `Supervisor.analyze_vulnerabilities`, qui appelle `Analyzer.analyze_vulnerabilities_batch`.  
- Réponse `AnalysisResponse` : `analysis_id`, `summary`, `vulnerabilities` enrichies, `remediation_plan`.

### 2.5 Exploration d’une vulnérabilité

`GET /api/v1/vulnerability/{vuln_id}` retourne actuellement une payload statique (TODO base de données). Utile pour gabarits d’UI.

### 2.6 Génération/validation de scripts (`/api/v1/script/*`)

| Route | Description | Entrée | Sortie |
| --- | --- | --- | --- |
| `POST /script/generate` | Orchestration `WorkflowType.GENERATE_SCRIPTS` pour créer un script correctif. | `ScriptGenerationRequest` | `ScriptResponse` (script, rollback, risk_level, timestamps) |
| `POST /script/validate` | Score de sûreté d’un script existant via `Supervisor.validate_script`. | Body brut `script_content` | `validation_id`, `is_safe`, `risk_level`, `identified_risks`, `improvements` |

### 2.7 Rapports (`/api/v1/report/*`)

| Route | Description | Détails |
| --- | --- | --- |
| `POST /report/generate` | Lance `generate_report_task` en arrière-plan. | `ReportRequest` (type, format, `scan_id`/`analysis_id`, options d’inclusion). Retourne `ReportResponse` (statut `generating`). |
| `GET /report/{report_id}/download` | Sert un fichier via `FileResponse`. Le chemin `data/reports/report_<id>.pdf` doit exister. | À sécuriser (TODO ownership + existence). |

### 2.8 Schémas principaux (résumé)

| Modèle | Champs clés | Remarques |
| --- | --- | --- |
| `ScanRequest` | `target`, `scan_type`, `ports`, `timeout` | Validation regex sur IP/FQDN & ports (`schemas.py`). |
| `ScanResponse` | `scan_id`, `target`, `status`, `started_at` | Hérite de `BaseResponse`. |
| `AnalysisRequest` | `vulnerabilities_data`, `target_system`, `analysis_depth` | Limite 100 vulnérabilités. |
| `AnalysisResponse` | `summary`, `vulnerabilities`, `remediation_plan`, `ai_model_used` | Conserve `confidence_score` et horodatages. |
| `ScriptGenerationRequest` | `vulnerability_id`, `target_system`, `risk_tolerance` | Normalise le système (linux, ubuntu, windows…). |
| `ScriptResponse` | `script_content`, `rollback_script`, `risk_level`, `generated_at` | Validé par `ScriptRiskLevel`. |
| `ReportRequest` | `report_type`, `format`, `scan_id`/`analysis_id` | Validation conditionnelle (`model_validator`). |
| `BaseResponse` | `success`, `timestamp`, `message` | Utilisé partout. |

Pour la liste exhaustive, consulter `src/api/schemas.py`.

---

## 3. Composants métier

### 3.1 Supervisor (`src/core/supervisor.py`)

**Rôle** : orchestrateur central chargé de créer et suivre des workflows (`WorkflowType`).  
**Points clés** :

| Méthode | Description | Usage |
| --- | --- | --- |
| `start_workflow(workflow_type, target, parameters, priority)` | Crée un workflow et programme le processeur asynchrone. | Utilisé par les routes, mais peut être appelé directement via un service interne. |
| `wait_for_workflow(workflow_id, timeout=3600)` | Bloque jusqu’à la complétion, charge les résultats (`data/workflow_results`). | Indispensable pour récupérer les `WorkflowResult`. |
| `run_scan`, `run_complete_workflow`, `analyze_vulnerabilities`, `generate_fix_script` | Facades asynchrones pour les cas d’usage courants. | Exemple ci-dessous. |
| `get_workflow_status`, `list_workflows`, `cancel/pause/resume_workflow` | Fonctions d’administration. | À exposer dans un futur tableau de bord. |
| `set_progress_callback`, `set_completion_callback` | Permettent d’injecter de la télémétrie temps réel. | Utiles pour websockets/UI. |

```python
import asyncio
from src.core.supervisor import Supervisor, WorkflowType

async def full_assessment():
    supervisor = Supervisor()
    workflow_id = await supervisor.start_workflow(
        WorkflowType.FULL_WORKFLOW,
        target="prod.company.tld",
        parameters={"scan_type": "aggressive"},
        created_by="secops"
    )

    result = await supervisor.wait_for_workflow(workflow_id)
    print(result.scan_result.summary, result.analysis_result.remediation_plan)

asyncio.run(full_assessment())
```

**Internes importants** :
- `active_workflows` & `active_tasks` stockent l’état courant.
- `_workflow_processor` boucle qui répartit les tâches tout en respectant `max_concurrent_workflows`.
- `_execute_scan_task`/`_execute_analyze_task`/`_execute_generate_task` injectent des callbacks de progression et convertissent les résultats vers les dataclasses dédiées.
- Persistance des résultats dans `data/workflow_results/<workflow_id>.json`.

### 3.2 Collector (`src/core/collector.py`)

**But** : orchestrer Nmap, parser les résultats et enrichir les vulnérabilités.

Fonctionnalités principales :

- `scan_target(...)` : pipeline complet (validation de la cible, préparation des arguments, exécution asynchrone du scan, parsing, enrichissement, sauvegarde, statistiques).  
- `_prepare_nmap_args` : profils `quick/full/stealth/aggressive` + `custom`.  
- `_extract_vulnerabilities_from_scripts` : lecture des outputs NSE et détection automatique de CVE / patterns.  
- `import_scan_results` (placeholder) : pour intégrer des rapports existants (Nmap XML, JSON).  
- `quick_scan`, `bulk_scan`, `ScanScheduler` : utilitaires haut niveau (scans parallèles, planification).  
- `get_stats()` et `is_healthy()` : pour la supervision.

**Exemple** :

```python
from src.core.collector import Collector
import asyncio

async def demo_scan():
    collector = Collector()
    result = await collector.scan_target("192.168.1.15", scan_type="quick")
    print(result.summary, len(result.vulnerabilities))

asyncio.run(demo_scan())
```

### 3.3 Analyzer (`src/core/analyzer.py`)

- Supporte OpenAI **et** Anthropic, sélectionné via `config.get_config()["ai_provider"]`.  
- `analyze_vulnerabilities_batch` segmente les vulnérabilités, enrichit avec `NISTEnricher`, gère le retry sur les appels IA et fournit un `AnalysisResult` structuré.  
- `_create_remediation_plan` et `_create_analysis_summary` calculent des KPI (moyenne CVSS, priorités).  
- Stats internes : nombre d’analyses, temps moyen, appels NIST, etc.

### 3.4 Generator (`src/core/generator.py`)

- Génère des scripts correctifs avec fallback local si l’IA échoue.  
- `generate_fix_script` → `ScriptResult` contenant `fix_script`, `rollback_script`, risques, avertissements.  
- `_generate_script_with_retry` change de prompt si la réponse JSON est invalide.  
- `_generate_fallback_script` fournit un template bash sécurisé.

### 3.5 Database manager (`src/database/database.py`)

Fonctions publiques à retenir :

| Méthode | Description |
| --- | --- |
| `create_tables()` | Exécute les migrations SQL ou crée un schéma minimal (scans, vulnérabilités, analyses, scripts, workflows). |
| `insert/update/delete/select/count` | Abstractions CRUD avec gestion des timestamps. |
| `save_scan_result(ScanResult)` | Sauvegarde un scan complet puis associe les vulnérabilités via `scan_vulnerabilities`. |
| `get_scan_history`, `get_vulnerabilities_by_severity`, `cleanup_old_data` | Fonctions prêtes pour les dashboards. |
| `backup/restore/auto_backup` | Sauvegarde compressée et rétention. |
| `get_stats`, `health_check` | Vérifications d’intégrité et statistiques disque. |

Chaque thread réutilise sa propre connexion (`DatabaseConnection` + `threading.RLock`).

### 3.6 Suite sécurité (`src/utils/security.py`)

Composants majeurs :

- **InputValidator** : bloque patterns dangereux (injections shell/SQL, path traversal), sanitize les commandes.  
- **ScriptValidator** : liste noire de commandes, détection de patterns malveillants (`fork bomb`, `rm -rf /`, `download+execute`), validation syntaxique `bash -n`, recommandations automatiques.  
- **SecurityManager** : pipeline complet (validation, sandbox, détection d’anomalies, scoring global).  
- **ScriptSandbox** : exécution dans un environnement isolé (`ulimit`, `timeout`, wrappers).  
- **CryptoUtils** : hachages PBKDF2, HMAC, génération de tokens.  
- **SecurityAuditor** : journalise chaque action sensible dans `logs/security_audit.log`.

### 3.7 Utilitaires supplémentaires

- **Logger avancé** (`src/utils/logger.py`) : gestion des niveaux personnalisés (`TRACE`, `SUCCESS`), rotation, format JSON, masquage des données sensibles, décorateurs `@log_function_call`.  
- **Validators** (`src/utils/validators.py`) : +100 fonctions pour valider IP, domaines, ports, CVE, fichiers, JSON, scripts, configs.  
- **Parsers** (`src/utils/parsers.py`) : parseurs Nmap/XML, Tenable JSON, CSV, parser unifié (`UnifiedParser`) pour détecter le format automatiquement, génération de rapports résumés.

---

## 4. Scénarios d’usage recommandés

### 4.1 Lancer un scan complet et suivre sa progression

1. `POST /api/v1/scan` avec la cible.  
2. Poll `GET /api/v1/scan/{scan_id}/results` jusqu’à ce que `status == "completed"` ou qu’un fichier de workflow soit disponible.  
3. Les résultats contiennent : résumé, ports ouverts, vulnérabilités détaillées, services identifiés.

### 4.2 Analyser et prioriser des vulnérabilités existantes

1. Construire un `AnalysisRequest` avec un maximum de 100 vulnérabilités (triées par sévérité).  
2. `POST /api/v1/analyze`.  
3. Exploiter `analysis_result.remediation_plan` pour alimenter un backlog (actions immédiates, court terme, long terme).

### 4.3 Générer et contrôler un script correctif

1. `POST /api/v1/script/generate` (préciser `target_system` et `risk_tolerance`).  
2. Passer le script renvoyé dans `POST /api/v1/script/validate` pour obtenir `identified_risks` et recommandations.  
3. En production, exécuter le script via la sandbox (`SecurityManager.comprehensive_security_check`) ou votre propre pipeline CI/CD.

### 4.4 Produire un rapport client

1. `POST /api/v1/report/generate` en fournissant `scan_id` ou `analysis_id`.  
2. Attendre que le processus en arrière-plan écrive `data/reports/report_<id>.pdf`.  
3. Télécharger avec `GET /api/v1/report/{report_id}/download`.

---

## 5. Bonnes pratiques d’intégration

1. **Déploiement** : exécuter `uvicorn src.api.main:app` derrière un reverse proxy TLS.  
2. **Persistance durable** : monter `data/` et `logs/` sur un volume persistant (Docker/Kubernetes).  
3. **Surcapacité** : ajuster `max_concurrent_workflows`/`max_concurrent_tasks` dans `config.get_config()`.  
4. **Sécurité** : brancher un provider d’identité réel dans `get_current_user`, renforcer la validation des rapports (`download_report`).  
5. **Monitoring** : consommer `Supervisor.get_stats()` et les fichiers `logs/*.log` pour alimenter Prometheus/ELK.  
6. **Extensibilité** : ajouter de nouveaux `WorkflowType` ou branches dans `Generator`/`Analyzer` en conservant les dataclasses (`ScanResult`, `AnalysisResult`, `ScriptResult`).  
7. **Tests** : la suite `tests/` contient des scénarios unitaires (collector, analyzer, generator). Exécuter `pytest` avant chaque livraison.

---

## 6. Ressources complémentaires

- Documentation FastAPI auto-générée : `http://localhost:8000/docs`  
- Dashboard statique (prototype) : `src/web/static/dashboard.html`  
- Exemples de scripts/tâches : `scripts/*.sh`, `scripts/setup.py`

Pour toute contribution, suivre les conventions décrites dans ce document et dans le `README.md` racine. N’hésitez pas à enrichir cette page lorsque de nouvelles routes ou composants publics sont ajoutés.
