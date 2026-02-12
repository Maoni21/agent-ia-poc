# Guide de Déploiement - Vulnerability Agent IA

Ce document résume le déploiement du backend + frontend avec Docker Compose.

## Prérequis

- Docker et Docker Compose installés
- Une base PostgreSQL (embarquée via compose)
- Redis (pour Celery)

## Variables d'environnement principales

Créer un fichier `.env` à la racine avec au minimum :

```bash
JWT_SECRET_KEY=change-me
DATABASE_URL=postgresql://vulnagent:password@db:5432/vulnagent
CELERY_BROKER_URL=redis://redis:6379/0
OPENAI_API_KEY=votre_cle_openai
ENCRYPTION_KEY=cle-de-chiffrement-32-caracteres-minimum
```

## Lancer en développement

```bash
docker compose up --build
```

- Backend FastAPI disponible sur `http://localhost:8000`
- Frontend Next.js disponible sur `http://localhost:3000`

## Migrations de base de données

Depuis le conteneur backend :

```bash
alembic upgrade head
```

Les versions incluent :

- `001_create_complete_schema.py`
- `002_add_webhook_subscriptions.py`
- `003_add_ssh_credentials_to_assets.py`

