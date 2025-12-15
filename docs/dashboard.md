## Dashboard web

### À qui s’adresse cette page ?
- Utilisateurs qui veulent consulter les résultats (lecture)

### Ce que vous allez apprendre
- Lancer le dashboard
- Comprendre d’où viennent les données

### Démarrer
```bash
python3 -m uvicorn src.web.dashboard_api:app --reload --port 8000
```
Ouvrez : `http://127.0.0.1:8000/`

### Données affichées
Le dashboard lit :
- la base SQLite : `data/database/vulnerability_agent.db`
- les workflows : `data/workflow_results/*.json`

### Si le dashboard est vide
- Lancez un workflow (CLI) pour générer des données :
```bash
python3 main.py --full-workflow --target 127.0.0.1 --scan-type quick
```
- Vérifiez que le fichier SQLite existe sous `data/database/`.
