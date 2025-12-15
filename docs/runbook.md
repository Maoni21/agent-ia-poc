## Runbook (exploitation / dépannage)

### À qui s’adresse cette page ?
- Mainteneurs / DevOps / DevSecOps

### Problèmes fréquents

#### 1) “OPENAI_API_KEY n’est pas définie”
- Vérifier `.env` et relancer.

#### 2) “Nmap non trouvé ou non fonctionnel”
- Installer `nmap`.
- Sur Debian/Ubuntu : `sudo apt-get install nmap`

#### 3) Le dashboard renvoie des erreurs SQLite
- Vérifier que `data/database/vulnerability_agent.db` existe.
- Initialiser la base :
```bash
python3 -c "from src.database.database import Database; Database().create_tables(); print('OK')"
```

#### 4) Port déjà utilisé
- Changer le port : `--port 8001` (API) ou `--port 8002` (dashboard).

#### 5) Analyse IA lente / coûteuse
- Ajuster dans `.env` : `MAX_TOKENS`, `MAX_VULNERABILITIES_TO_ANALYZE`, `MAX_SCRIPTS_TO_GENERATE`.
