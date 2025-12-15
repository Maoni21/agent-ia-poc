# Agent IA (PoC) — Détection, analyse et remédiation de vulnérabilités

Ce dépôt contient un **Proof of Concept** d’agent IA orienté cybersécurité :
- **Scan** (via Nmap) d’une cible autorisée
- **Analyse IA** des vulnérabilités (priorisation + plan d’action)
- **Génération** de scripts de remédiation (avec rollback)
- **Stockage** des résultats (SQLite + fichiers JSON)
- **Dashboard web** pour explorer l’historique et les résultats

> **Avertissement légal** : scannez uniquement des systèmes que vous possédez ou pour lesquels vous avez une autorisation explicite.

## Documentation
- Démarrer rapidement : `docs/quickstart.md`
- Vue d’ensemble : `docs/overview.md`
- CLI : `docs/cli.md`
- API REST : `docs/api.md`
- Dashboard : `docs/dashboard.md`
- Architecture : `docs/architecture.md`
- Sécurité : `docs/security.md`
- Runbook : `docs/runbook.md`
- Glossaire : `docs/glossary.md`

## Quickstart (le plus simple)

### Prérequis
- Python **3.10+**
- (Optionnel, pour le scan) `nmap` installé sur la machine

### Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
cp .env.example .env
# Éditez .env et renseignez OPENAI_API_KEY
```

### Exemple 1 — Analyse IA d’un fichier (sans Nmap)
```bash
python3 main.py --analyze --analyze-file test_vulnerabilities.json --output data/reports/analysis.json --format json
```

### Exemple 2 — Génération de scripts à partir d’un fichier
```bash
python3 main.py --generate --analyze-file test_vulnerabilities.json --output data/scripts/scripts.json --format json
```

### Exemple 3 — Scan autorisé (démo)
```bash
python3 main.py --scan --target 127.0.0.1 --scan-type ultra-quick --output data/scans/scan.json --format json
```

## API REST (FastAPI)
```bash
python3 main.py --api --host 127.0.0.1 --port 8000
```
Puis ouvrez :
- OpenAPI Swagger : `http://127.0.0.1:8000/docs`

## Dashboard web
Le dashboard lit la base SQLite et les résultats de workflow sous `data/`.

```bash
python3 -m uvicorn src.web.dashboard_api:app --reload --port 8000
```
Puis ouvrez :
- Dashboard : `http://127.0.0.1:8000/`

## Notes PoC
- Par défaut, l’analyse et la génération sont **limitées** pour contrôler les coûts :
  - max vulnérabilités analysées : **10**
  - max scripts générés : **5**
  (configurable via `.env`)
