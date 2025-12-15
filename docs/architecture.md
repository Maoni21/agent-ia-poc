## Architecture

### À qui s’adresse cette page ?
- Développeurs et reviewers techniques

### Ce que vous allez apprendre
- Les modules et responsabilités
- Le flux de données

### Vue “conteneurs” (simplifiée)
- **CLI** (`main.py`) : point d’entrée humain
- **API REST** (`src/api/`) : point d’entrée machine
- **Core** (`src/core/`) : logique métier
  - `Collector` : scan Nmap + extraction vulnérabilités
  - `Analyzer` : analyse IA (résumé + priorisation)
  - `Generator` : scripts de remédiation + rollback
  - `Supervisor` : orchestration des workflows
- **DB** (`src/database/`) : SQLite (scans, vulnérabilités, scripts, workflows)
- **Dashboard** (`src/web/`) : lecture + exploration

### Stockage
- `data/database/vulnerability_agent.db` : persistance SQLite
- `data/workflow_results/<workflow_id>.json` : résultats complets de workflows

### Limites PoC
- Concurrence et état en mémoire (par ex. tâches actives) : à industrialiser (Redis, queue, etc.)
- Sécurité des scripts : validation/revue à renforcer avant usage réel
