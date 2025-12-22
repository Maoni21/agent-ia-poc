## Agent IA de Cybersécurité — Détails techniques

Cette application implémente un **pipeline automatisé** de cybersécurité (scan → enrichissement → analyse IA → priorisation → génération de remédiations) avec un objectif clair : **produire des résultats exploitables** tout en conservant une **traçabilité** et une **validation sur sources officielles**.

### Atouts technologiques (pour experts)

- **LLM multi‑provider (OpenAI + Anthropic)** : le cœur d’analyse et de génération est compatible **GPT‑4** (et autres modèles OpenAI) et **Claude** (ex. `claude-sonnet-4-20250514`). Le provider est sélectionné par configuration (variable d’environnement `AI_PROVIDER=openai|anthropic` et/ou paramètre `ai_provider` lorsqu’une configuration est injectée sous forme de dictionnaire).
- **Vérification via NIST / NVD (source officielle)** : les CVE sont enrichis via l’API **NVD (NIST)** (`https://services.nvd.nist.gov/rest/json/cves/2.0`). On récupère notamment **CVSS**, **sévérité**, **description**, **références** et **liens de correctifs/vendor advisories** quand disponibles.
- **Architecture “workflow” asynchrone** : orchestration par `Supervisor` (asyncio) avec exécution par tâches (`scan`, `analyze`, `generate_scripts`) et **files d’attente** / limites de concurrence.
- **Sécurité opérationnelle** : validation d’inputs, **analyse statique** de scripts, détection de patterns malveillants, et **sandboxing** (exécution à blanc / syntax check) côté `src/utils/security.py`.

### Architecture logicielle (vue d’ensemble)

Le système est structuré en modules “core” orchestrés par un superviseur :

- **`Collector` (`src/core/collector.py`)** : exécute des scans Nmap (scripts NSE “vuln/safe/exploit” selon profil), extrait services/ports/indices de vulnérabilités (y compris détection de motifs CVE dans les outputs).
- **`Analyzer` (`src/core/analyzer.py`)** : enrichit d’abord les CVE via NVD/NIST, puis interroge un LLM pour produire une analyse structurée (JSON), et peut déclencher une **détection de faux positifs**.
- **`FalsePositiveDetector` (`src/core/false_positive_detector.py`)** : second passage LLM orienté “evidence-based” (versions, bannières, cohérence contexte) pour estimer si un finding est un faux positif (avec score de confiance).
- **`Generator` (`src/core/generator.py`)** : génère des scripts de correction (et rollback), avec mécanisme de **retry**, parsing strict du JSON et **fallback** si le LLM renvoie une réponse invalide.
- **`NISTEnricher` (`src/core/nist_enricher.py`)** : client NVD/NIST avec **cache mémoire** et **rate limiting** (pour respecter les quotas en l’absence d’API key).
- **API REST** : exposée via **FastAPI** (`src/api/main.py`, `src/api/routes.py`) pour lancer scans/analyses/génération et récupérer les résultats.
- **Persistance** : **SQLite** via `src/database/database.py` (PRAGMAs WAL/synchronous/cache, schéma/migrations, CRUD générique) et modèles “métier” dans `src/database/models.py`.

### Pipeline technique (de bout en bout)

1. **Scan & collecte (Nmap)**  
   - Exécution de Nmap via `python-nmap` + binaire système `nmap`.  
   - Profils de scan (exemples) : `quick`, `full`, `stealth`, `aggressive`.  
   - Sorties parsées : ports ouverts, services, versions, bannières, outputs des scripts NSE.

2. **Normalisation des vulnérabilités**  
   - Harmonisation des champs (`vulnerability_id`, `severity`, `cvss_score`, etc.) pour éviter les divergences de formats.

3. **Enrichissement officiel NIST/NVD (CVE)**  
   - Pour chaque `CVE-…`, appel NVD/NIST v2.0.  
   - Ajout au finding : `nist_verified`, `nist_url`, `cvss_vector`, `solution_links`, et métriques CVSS lorsque présentes.

4. **Analyse IA (LLM) en JSON strict**  
   - Le LLM reçoit un prompt demandant **uniquement du JSON** (pas de markdown).  
   - Parsing robuste : suppression éventuelle des fences ```json, retry sur prompt simplifié si JSON invalide.  
   - Sortie attendue : impact, exploitabilité, priorité, actions recommandées, etc.

5. **Détection de faux positifs (optionnel)**  
   - Analyse dédiée “forensic” du contexte (versions/bannières/OS/ports) + score de confiance.  
   - Résultats stockés sur chaque vulnérabilité : `is_false_positive`, `false_positive_confidence`, `false_positive_reasoning`.

6. **Génération de remédiations (scripts / rollback)**  
   - Génération d’un script bash (et rollback) en JSON strict.  
   - En cas d’échec LLM : **script fallback** minimal avec avertissements et prérequis.

### IA : providers, modèles, gouvernance des sorties

- **Providers supportés** :
  - **OpenAI** (ex. **GPT‑4**, `gpt-3.5-turbo`, etc.)
  - **Anthropic** (ex. **Claude**, `claude-sonnet-4-20250514`)
- **Stratégie “JSON-only”** :
  - Les modules `Analyzer` et `Generator` imposent un contrat de sortie **JSON valide**.
  - Nettoyage des réponses (suppression de fences), puis `json.loads()` ; **retry** si parsing échoue.
- **Maîtrise des coûts / latence** :
  - Limites configurables : nombre max de vulnérabilités analysées et scripts générés (ex. `MAX_VULNERABILITIES_TO_ANALYZE`, `MAX_SCRIPTS_TO_GENERATE`).

### Vérification NIST/NVD : ce qui est vérifié exactement

Quand un identifiant commence par `CVE-`, l’application interroge la **NVD (NIST)** afin de :

- **Récupérer le scoring CVSS** (v3.1/v3.0/v2 selon disponibilité).
- **Récupérer la sévérité** (baseSeverity) publiée avec la métrique.
- **Récupérer les références** et tenter d’extraire des **liens de correctifs** (patch/vendor advisory).
- **Fournir un lien direct** vers la fiche officielle : `https://nvd.nist.gov/vuln/detail/<CVE-ID>`.

Cette étape permet de **distinguer** :
- ce qui provient du scan (détection terrain : ports/services/bannières),
- et ce qui provient d’une **base officielle** (NIST/NVD : score, vecteur, références).

### Sécurité : réduction du risque “IA → exécution”

Le module `src/utils/security.py` fournit une couche défensive :

- **Validation/sanitisation des inputs** (prévention injections de commandes, path traversal, etc.).
- **Analyse de scripts bash** : détection de commandes dangereuses (ex. `rm`, `dd`, `mkfs`), patterns malveillants (fork bomb, téléchargement+pipe vers shell, etc.), contrôle de syntaxe (`bash -n`).
- **Sandboxing** : création d’environnement isolé (wrapper avec `ulimit` + `timeout`) et validation “dry-run”/syntaxe.
- **Audit trail** : événements structurés avec hash d’intégrité (journalisation sécurité).

### API REST (FastAPI)

L’API (namespace `/api/v1`) expose notamment :

- **`POST /api/v1/scan`** : démarrer un scan (exécuté en tâche de fond).
- **`GET /api/v1/scan/{scan_id}/results`** : récupérer l’état/résultats (stockage temporaire + fichiers `data/workflow_results/*.json`).
- **`POST /api/v1/analyze`** : analyser une liste de vulnérabilités.
- **`POST /api/v1/script/generate`** : générer un script de correction.
- **`POST /api/v1/script/validate`** : valider un script avant exécution (contrôle sécurité).
- **`GET /health`** : healthcheck.

### Persistance & traçabilité (SQLite)

Le stockage est basé sur SQLite, avec :

- **Schéma/migrations** + tables pour scans, vulnérabilités, analyses IA, scripts, workflows.
- **Optimisations SQLite** (WAL, cache, busy timeout…).
- **Possibilité de sauvegarde/maintenance** (backup, vacuum/analyze/reindex selon implémentation).

### Configuration (environnement)

Variables importantes (selon `config/settings.py`) :

- **`AI_PROVIDER`** : `openai` ou `anthropic`
- **`OPENAI_API_KEY`**, **`OPENAI_MODEL`** (ex. `gpt-4` pour analyses premium)
- **`ANTHROPIC_API_KEY`**, **`ANTHROPIC_MODEL`** (ex. `claude-sonnet-4-20250514`)
- **`NVD_API_KEY`** : optionnel (augmente les quotas / réduit les contraintes de rate limit côté NVD)
- **`MAX_TOKENS`**, **`TEMPERATURE`**
- **`MAX_VULNERABILITIES_TO_ANALYZE`**, **`MAX_SCRIPTS_TO_GENERATE`**

### Points importants (honnêteté technique)

- Le LLM **n’est pas** une source d’autorité “officielle” : il sert à **structurer, expliquer, prioriser et proposer** des remédiations. Les éléments de scoring/références CVE sont **ancrés** via la NVD (NIST) lorsque possible.
- Les scripts générés doivent être **revus** (au minimum) avant exécution en production ; la plateforme fournit des garde‑fous, mais la responsabilité d’exécution reste opérationnelle.
