## API REST (FastAPI)

### À qui s’adresse cette page ?
- Développeurs qui veulent intégrer le PoC (ou l’automatiser)

### Ce que vous allez apprendre
- Lancer l’API
- Tester les endpoints principaux

### Démarrer le serveur
Option A (via la CLI) :
```bash
python3 main.py --api --host 127.0.0.1 --port 8000
```

Option B (directement via Uvicorn) :
```bash
python3 -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

### Documentation interactive
- Swagger : `http://127.0.0.1:8000/docs`
- ReDoc : `http://127.0.0.1:8000/redoc`

### Endpoints utiles
- `GET /health` : santé
- `POST /api/v1/scan` : démarrer un scan (asynchrone)
- `GET /api/v1/scan/{scan_id}/results` : récupérer la progression/résultats
- `POST /api/v1/analyze` : analyser une liste de vulnérabilités (JSON)
- `POST /api/v1/script/generate` : générer un script de correction

### Exemples curl
#### Health
```bash
curl -s http://127.0.0.1:8000/health
```

#### Démarrer un scan
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"127.0.0.1","scan_type":"quick"}'
```

#### Lire les résultats d’un scan
```bash
curl -s http://127.0.0.1:8000/api/v1/scan/<scan_id>/results
```

### Auth
L’API accepte un `Authorization: Bearer <token>` mais l’implémentation actuelle est **permissive** (PoC).
