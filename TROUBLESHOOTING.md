# 🔧 Guide de dépannage

## Problèmes courants lors du lancement Docker

### Erreur : `npm ci` échoue

**Solution** : Le Dockerfile a été modifié pour utiliser `npm install` au lieu de `npm ci`. Si le problème persiste :

```bash
# Nettoyer le cache Docker
docker-compose down
docker system prune -f

# Rebuild sans cache
docker-compose build --no-cache frontend
docker-compose up
```

### Warning : `OPENAI_API_KEY` variable is not set

**Solution** : C'est normal si vous utilisez Anthropic. Le warning a été corrigé dans docker-compose.yml. Vous pouvez l'ignorer ou ajouter dans `.env` :

```env
OPENAI_API_KEY=
```

### Erreur : Port déjà utilisé

Si les ports 3000, 8000 ou 5432 sont déjà utilisés :

```bash
# Vérifier quels processus utilisent les ports
lsof -i :3000
lsof -i :8000
lsof -i :5432

# Arrêter les processus ou modifier les ports dans docker-compose.yml
```

### Erreur : Build context trop volumineux

Si le build est lent à cause de fichiers volumineux :

```bash
# Vérifier que .dockerignore est bien configuré
cat backend/.dockerignore
cat frontend/.dockerignore

# Nettoyer les fichiers inutiles
make clean
```

### Erreur : Base de données ne démarre pas

```bash
# Vérifier les logs
docker-compose logs db

# Réinitialiser la base de données
docker-compose down -v
docker-compose up -d db
# Attendre 10 secondes
docker-compose up -d backend frontend
```

### Erreur : Frontend ne se connecte pas au backend

1. Vérifier que le backend est bien démarré :
   ```bash
   docker-compose ps
   curl http://localhost:8000/health
   ```

2. Vérifier les variables d'environnement dans `frontend/.env.local` :
   ```env
   REACT_APP_API_URL=http://localhost:8000
   ```

3. Vérifier les CORS dans `backend/src/api/config.py`

### Erreur : Module non trouvé dans le backend

```bash
# Rebuild le backend
docker-compose build --no-cache backend
docker-compose up backend
```

### Erreur : Next.js ne démarre pas

```bash
# Vérifier que node_modules est bien installé
docker-compose exec frontend ls -la node_modules

# Réinstaller les dépendances
docker-compose exec frontend npm install
```

## Solutions rapides

### Tout nettoyer et recommencer

```bash
# Arrêter tout
docker-compose down -v

# Nettoyer Docker
docker system prune -f

# Rebuild tout
docker-compose build --no-cache

# Relancer
docker-compose up
```

### Voir les logs en temps réel

```bash
# Tous les services
docker-compose logs -f

# Un service spécifique
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f db
```

### Accéder au shell d'un container

```bash
# Backend
docker-compose exec backend bash

# Frontend
docker-compose exec frontend sh

# Base de données
docker-compose exec db psql -U vulnagent -d vulnerability_db
```

## Commandes utiles

```bash
# Vérifier le statut
docker-compose ps

# Redémarrer un service
docker-compose restart backend

# Rebuild un service
docker-compose build backend
docker-compose up -d backend

# Voir l'utilisation des ressources
docker stats
```
