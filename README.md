# 🛡️ Vulnerability Agent IA - Agent de Cybersécurité

Agent IA de détection et correction automatisée de vulnérabilités avec scan Nmap, analyse IA (GPT-4/Claude) et génération de scripts de correction.

## 📋 Architecture

Ce projet est structuré en **monorepo** avec :

- **Backend** : API REST FastAPI (Python 3.10+)
- **Frontend** : Application Next.js (React 18)
- **Base de données** : PostgreSQL (production) / SQLite (développement)
- **Orchestration** : Docker Compose

```
vulnerability-agent/
├── backend/              # Backend Python/FastAPI
│   ├── src/
│   │   ├── core/         # Logique métier (Collector, Analyzer, Generator, Supervisor)
│   │   ├── api/          # API REST FastAPI
│   │   ├── database/     # Base de données
│   │   └── utils/        # Utilitaires
│   ├── alembic/          # Migrations de base de données
│   ├── tests/            # Tests unitaires
│   └── Dockerfile
│
├── frontend/             # Frontend Next.js
│   ├── pages/            # Pages Next.js (routing automatique)
│   ├── components/       # Composants React
│   ├── lib/              # Services et utilitaires
│   └── Dockerfile
│
├── config/               # Configuration partagée
├── data/                 # Données (scans, résultats, etc.)
├── docker-compose.yml    # Orchestration Docker
└── Makefile             # Commandes pratiques
```

## 🚀 Installation rapide

### Prérequis

- Docker & Docker Compose
- Node.js 18+ (pour développement frontend)
- Python 3.10+ (pour développement backend)
- Nmap installé sur le système

### Installation avec Docker (recommandé)

```bash
# 1. Cloner le projet
git clone <repository-url>
cd vulnerability-agent

# 2. Configuration
cp .env.example .env
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env.local

# 3. Éditer les fichiers .env avec vos clés API
# - OPENAI_API_KEY ou ANTHROPIC_API_KEY
# - POSTGRES_PASSWORD

# 4. Lancer tout avec Docker Compose
make docker-up
# ou
docker-compose up -d

# 5. Accéder à l'application
# Frontend : http://localhost:3000
# Backend API : http://localhost:8000
# API Docs : http://localhost:8000/docs
```

### Installation locale (développement)

```bash
# 1. Configuration initiale
make setup

# 2. Installer les dépendances
make install

# 3. Lancer le backend
make dev-backend
# Dans un autre terminal :
make dev-frontend
```

## 📖 Utilisation

### Via l'interface web

1. Accéder à http://localhost:3000
2. Cliquer sur "Nouveau scan"
3. Entrer une adresse IP ou un domaine
4. Choisir le type de scan et workflow
5. Lancer le scan et suivre la progression en temps réel

### Via l'API REST

```bash
# Lancer un scan
curl -X POST http://localhost:8000/api/v2/scans/launch \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_type": "full",
    "workflow_type": "full"
  }'

# Lister les scans
curl http://localhost:8000/api/v2/scans

# Récupérer les résultats d'un scan
curl http://localhost:8000/api/v2/scans/{scan_id}/results
```

## 🛠️ Commandes Make

```bash
make help              # Afficher toutes les commandes disponibles

# Développement
make dev               # Lancer tout en développement (Docker)
make dev-backend       # Lancer seulement le backend
make dev-frontend      # Lancer seulement le frontend

# Installation
make install           # Installer toutes les dépendances
make install-backend   # Installer dépendances backend
make install-frontend  # Installer dépendances frontend

# Build
make build             # Build tout pour production
make build-backend     # Build backend
make build-frontend    # Build frontend

# Tests
make test              # Lancer tous les tests
make test-backend      # Tests backend
make test-frontend     # Tests frontend

# Docker
make docker-up         # Démarrer les containers
make docker-down       # Arrêter les containers
make docker-build      # Build les images
make docker-logs       # Voir les logs
make docker-restart    # Redémarrer les services

# Nettoyage
make clean             # Nettoyer tout
make clean-backend     # Nettoyer backend
make clean-frontend    # Nettoyer frontend
```

## 🔧 Configuration

### Variables d'environnement

**Racine (.env)** :
- `POSTGRES_PASSWORD` : Mot de passe PostgreSQL
- `AI_PROVIDER` : `openai` ou `anthropic`
- `OPENAI_API_KEY` : Clé API OpenAI (si provider=openai)
- `ANTHROPIC_API_KEY` : Clé API Anthropic (si provider=anthropic)

**Backend (backend/.env)** :
- `DATABASE_URL` : URL de connexion PostgreSQL
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` : Clés API
- `LOG_LEVEL` : Niveau de logging (INFO, DEBUG, etc.)

**Frontend (frontend/.env.local)** :
- `REACT_APP_API_URL` : URL de l'API backend
- `REACT_APP_WS_URL` : URL WebSocket

## 📊 Fonctionnalités

### Scans de vulnérabilités
- ✅ Scan Nmap avec différents types (quick, full, stealth, aggressive)
- ✅ Détection automatique de services et versions
- ✅ Identification des vulnérabilités via Vulners API
- ✅ Progression en temps réel via WebSocket

### Analyse IA
- ✅ Analyse approfondie des vulnérabilités avec GPT-4 ou Claude
- ✅ Évaluation des risques et priorités
- ✅ Recommandations de remédiation
- ✅ Détection de faux positifs

### Génération de scripts
- ✅ Génération automatique de scripts de correction (Bash/Ansible)
- ✅ Scripts de rollback
- ✅ Validation de sécurité des scripts
- ✅ Support multi-systèmes (Ubuntu, CentOS, etc.)

### Interface web
- ✅ Dashboard avec statistiques
- ✅ Liste des scans avec statut en temps réel
- ✅ Affichage détaillé des vulnérabilités
- ✅ Téléchargement de rapports PDF
- ✅ Interface moderne avec Material-UI

## 🗄️ Base de données

### PostgreSQL (Production/Docker)

La base de données PostgreSQL est automatiquement créée et configurée via Docker Compose.

```bash
# Accéder à PostgreSQL
docker-compose exec db psql -U vulnagent -d vulnerability_db

# Appliquer les migrations
make db-migrate
# ou
cd backend && alembic upgrade head
```

### SQLite (Développement local)

Pour le développement local sans Docker, SQLite est utilisé par défaut.

## 🧪 Tests

```bash
# Tests backend
cd backend
pytest -v tests/

# Tests frontend
cd frontend
npm test
```

## 📝 Documentation API

Une fois le backend lancé, la documentation interactive est disponible sur :
- **Swagger UI** : http://localhost:8000/docs
- **ReDoc** : http://localhost:8000/redoc

## 🐳 Docker

### Services Docker

- **backend** : API FastAPI sur le port 8000
- **frontend** : Application Next.js sur le port 3000
- **db** : PostgreSQL sur le port 5432

### Commandes Docker utiles

```bash
# Voir les logs
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f db

# Redémarrer un service
docker-compose restart backend

# Rebuild une image
docker-compose build --no-cache backend

# Accéder au shell d'un container
docker-compose exec backend bash
docker-compose exec frontend sh
```

## 🔒 Sécurité

- ⚠️ **Ne jamais exposer les containers sur Internet sans protection**
- ⚠️ **Changer tous les mots de passe par défaut en production**
- ⚠️ **Utiliser HTTPS en production**
- ⚠️ **Configurer un firewall approprié**
- ⚠️ **Ne pas commiter les fichiers .env**

## 📦 Structure des données

```
data/
├── database/              # Base de données SQLite (dev local)
├── workflow_results/      # Résultats des workflows (JSON)
├── scans/                 # Résultats de scans bruts
└── reports/               # Rapports PDF générés
```

## 🚧 Développement

### Ajouter une nouvelle fonctionnalité

1. Créer une branche : `git checkout -b feature/ma-fonctionnalite`
2. Développer dans `backend/src/core/` ou `frontend/components/`
3. Ajouter des tests
4. Créer une pull request

### Standards de code

- **Backend** : PEP 8, type hints, docstrings
- **Frontend** : ESLint, Prettier (via Next.js)
- **Commits** : Messages clairs en français ou anglais

## 🐛 Dépannage

### Le backend ne démarre pas

```bash
# Vérifier les logs
docker-compose logs backend

# Vérifier la connexion à la base de données
docker-compose exec backend python -c "from src.database.database import Database; db = Database(); print('OK')"
```

### Le frontend ne se connecte pas au backend

1. Vérifier que `REACT_APP_API_URL` dans `frontend/.env.local` pointe vers le bon URL
2. Vérifier que le backend est bien démarré
3. Vérifier les CORS dans `backend/src/api/config.py`

### Erreurs de base de données

```bash
# Réinitialiser la base de données (⚠️  supprime toutes les données)
make db-reset

# Appliquer les migrations
make db-migrate
```

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

## 👥 Contribution

Les contributions sont les bienvenues ! Veuillez :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

## 📞 Support

Pour toute question ou problème :
- Ouvrir une issue sur GitHub
- Consulter la documentation API : http://localhost:8000/docs

---

**Fait avec ❤️ par l'équipe CyberSec AI**
