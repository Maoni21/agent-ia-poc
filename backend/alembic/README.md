# Migrations Alembic

Ce dossier contient les migrations de base de données pour PostgreSQL.

## Utilisation

### Créer une nouvelle migration

```bash
cd backend
alembic revision --autogenerate -m "Description de la migration"
```

### Appliquer les migrations

```bash
# Appliquer toutes les migrations en attente
alembic upgrade head

# Appliquer une migration spécifique
alembic upgrade <revision_id>

# Revenir en arrière d'une migration
alembic downgrade -1
```

### Voir l'historique des migrations

```bash
alembic history
```

### Voir la migration actuelle

```bash
alembic current
```

## Configuration

La configuration se fait via la variable d'environnement `DATABASE_URL` :

- **SQLite (développement local)** : `sqlite:///data/database/vulnerability_agent.db`
- **PostgreSQL (Docker/production)** : `postgresql://vulnagent:password@db:5432/vulnerability_db`

## Notes

- Les migrations sont automatiquement appliquées au démarrage du backend dans Docker
- En développement local, exécutez manuellement `alembic upgrade head`
- Assurez-vous que la variable `DATABASE_URL` est correctement configurée avant d'exécuter les migrations
