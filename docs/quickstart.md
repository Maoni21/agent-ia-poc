## Quickstart (10–15 min)

### À qui s’adresse cette page ?
- Toute personne qui veut exécuter une démo rapidement

### Ce que vous allez apprendre
- Installer, configurer et lancer une première exécution

### Prérequis
- Python **3.10+**
- (Optionnel, scan) `nmap` installé

### Installation
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
cp .env.example .env
```

Éditez `.env` et définissez **au minimum** :
- `OPENAI_API_KEY`

### Démo la plus simple (sans scan)
Analyse IA d’un jeu de vulnérabilités fourni (`test_vulnerabilities.json`) :

```bash
python3 main.py --analyze --analyze-file test_vulnerabilities.json --output data/reports/analysis.json --format json
```

Génération de scripts (toujours depuis le fichier) :

```bash
python3 main.py --generate --analyze-file test_vulnerabilities.json --output data/scripts/scripts.json --format json
```

### Démo scan (si Nmap est disponible)
```bash
python3 main.py --scan --target 127.0.0.1 --scan-type ultra-quick --output data/scans/scan.json --format json
```

### Lancer le dashboard
Le dashboard lit les résultats dans `data/database/` et `data/workflow_results/`.

```bash
python3 -m uvicorn src.web.dashboard_api:app --reload --port 8000
```
Ouvrez ensuite `http://127.0.0.1:8000/`.

### Dépannage rapide
- **Erreur OPENAI_API_KEY** : vérifiez `.env` (clé présente) et relancez.
- **Nmap non trouvé** : installez `nmap` (ex: `sudo apt-get install nmap`).
- **Port déjà utilisé** : changez `--port` (API/dashboard).
