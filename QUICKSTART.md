# 🚀 Guide de démarrage rapide

## Option 1 : Avec Docker (Recommandé - Le plus simple)

### Étape 1 : Configuration

```bash
# Créer les fichiers .env depuis les exemples
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local
```

### Étape 2 : Éditer les fichiers .env

**`.env` (racine)** :
```env
POSTGRES_PASSWORD=password123
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=votre_cle_api_anthropic_ici
```

**`backend/.env`** :
```env
DATABASE_URL=postgresql://vulnagent:password123@db:5432/vulnerability_db
ANTHROPIC_API_KEY=votre_cle_api_anthropic_ici
AI_PROVIDER=anthropic
```

**`frontend/.env.local`** :
```env
REACT_APP_API_URL=http://localhost:8000
REACT_APP_WS_URL=ws://localhost:8000
```

### Étape 3 : Lancer avec Docker

```bash
# Lancer tous les services (backend + frontend + base de données)
docker-compose up

# Ou en arrière-plan :
docker-compose up -d
```

### Étape 4 : Accéder à l'application

- **Frontend** : http://localhost:3000
- **Backend API** : http://localhost:8000
- **Documentation API** : http://localhost:8000/docs

### Voir les logs

```bash
# Tous les services
docker-compose logs -f

# Seulement le backend
docker-compose logs -f backend

# Seulement le frontend
docker-compose logs -f frontend
```

### Arrêter les services

```bash
docker-compose down
```

---

## Option 2 : Développement local (Sans Docker)

### Prérequis

- Python 3.10+
- Node.js 18+
- Nmap installé
- PostgreSQL (optionnel, SQLite par défaut)

### Étape 1 : Backend

```bash
cd backend

# Créer un environnement virtuel
python -m venv .venv

# Activer l'environnement virtuel
# Sur macOS/Linux :
source .venv/bin/activate
# Sur Windows :
# .venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Créer le fichier .env
cp .env.example .env
# Éditer .env avec vos clés API

# Lancer le backend
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

Le backend sera accessible sur : http://localhost:8000

### Étape 2 : Frontend (dans un autre terminal)

```bash
cd frontend

# Installer les dépendances
npm install

# Créer le fichier .env.local
cp .env.example .env.local
# Éditer .env.local si nécessaire

# Lancer le frontend
npm run dev
```

Le frontend sera accessible sur : http://localhost:3000

---

## Option 3 : Avec Make (Plus simple)

### Installation initiale

```bash
# Configuration complète (crée les .env et installe les dépendances)
make setup
```

### Lancer en développement

```bash
# Avec Docker
make dev

# Ou séparément
make dev-backend    # Terminal 1
make dev-frontend   # Terminal 2
```

---

## 🔍 Vérification

### Vérifier que tout fonctionne

1. **Backend** : Ouvrir http://localhost:8000/docs
   - Vous devriez voir la documentation Swagger de l'API

2. **Frontend** : Ouvrir http://localhost:3000
   - Vous devriez voir l'interface web

3. **Test API** :
   ```bash
   curl http://localhost:8000/health
   ```
   Devrait retourner : `{"status":"healthy",...}`

---

## ⚠️ Problèmes courants

### Le backend ne démarre pas

```bash
# Vérifier les logs
docker-compose logs backend

# Vérifier que le port 8000 n'est pas déjà utilisé
lsof -i :8000
```

### Le frontend ne se connecte pas au backend

1. Vérifier que le backend est bien démarré
2. Vérifier `REACT_APP_API_URL` dans `frontend/.env.local`
3. Vérifier les CORS dans `backend/src/api/config.py`

### Erreur de base de données

```bash
# Si vous utilisez Docker, réinitialiser la base de données
docker-compose down -v
docker-compose up -d db
# Attendre quelques secondes que PostgreSQL démarre
docker-compose up -d backend frontend
```

### Port déjà utilisé

Si le port 3000 ou 8000 est déjà utilisé :

```bash
# Modifier dans docker-compose.yml :
# frontend: ports: "3001:3000"  (au lieu de 3000:3000)
# backend: ports: "8001:8000"   (au lieu de 8000:8000)
```

---

## 📝 Première utilisation

1. Ouvrir http://localhost:3000
2. Cliquer sur "Scans" dans le menu
3. Cliquer sur "Nouveau scan"
4. Entrer une adresse IP (ex: `192.168.1.1`) ou un domaine
5. Choisir le type de scan (recommandé : "Complet")
6. Cliquer sur "Lancer le scan"
7. Suivre la progression en temps réel

---

## 🎯 Commandes utiles

```bash
# Voir toutes les commandes disponibles
make help

# Arrêter tout
docker-compose down

# Redémarrer un service
docker-compose restart backend

# Rebuild les images
docker-compose build --no-cache

# Nettoyer tout
make clean
```

---

**Bon développement ! 🚀**
