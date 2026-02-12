"""
Initialisation de la base PostgreSQL (Phase 1 – Semaine 1).

Ce module fournit :
- une fabrique de Session SQLAlchemy connectée à DATABASE_URL
- une fonction init_db() pour vérifier la connexion
- une fonction create_default_admin() pour créer une organisation et un admin de test
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from src.database.models import Base, Organization, User
from src.utils.security import get_password_hash
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def get_database_url() -> str:
    """
    Récupère l'URL de base de données depuis l'environnement.

    - Préférence : DATABASE_URL
    - Fallback dev : postgresql://vulnagent:password@localhost:5432/vulnagent_dev
    """
    url = os.getenv("DATABASE_URL")
    if url:
        # Adapter pour SQLAlchemy si nécessaire
        if url.startswith("postgresql://") and "postgresql+psycopg2" not in url:
            url = url.replace("postgresql://", "postgresql+psycopg2://")
        return url

    # Valeur par défaut pour le développement
    default_url = "postgresql+psycopg2://vulnagent:password@localhost:5432/vulnagent_dev"
    logger.warning(
        "DATABASE_URL non défini, utilisation de l'URL par défaut de développement: %s",
        default_url,
    )
    return default_url


SQLALCHEMY_DATABASE_URL = get_database_url()

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Session:
    """
    Dépendance FastAPI typique pour obtenir une session.

    Exemple d'utilisation dans un endpoint:

    def endpoint(db: Session = Depends(get_db)):
        ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Vérifie que la base est accessible.

    Les migrations Alembic sont responsables de la création des tables.
    Cette fonction peut être appelée au démarrage de l'application.
    """
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        logger.info("Connexion PostgreSQL OK (init_db).")
    except Exception as exc:  # pragma: no cover - log only
        logger.error("Échec de connexion à la base PostgreSQL: %s", exc)
        raise


def create_default_admin(
    email: str = "admin@company.com",
    password: str = "changeme123",
    organization_name: str = "Default Organization",
    organization_slug: str = "default-org",
) -> None:
    """
    Crée une organization + un utilisateur admin par défaut si inexistants.

    À utiliser après `alembic upgrade head`, par exemple via un script CLI.
    """
    db: Session = SessionLocal()
    try:
        # Vérifier si un user existe déjà avec cet email
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            logger.info("Utilisateur admin par défaut déjà présent (%s), rien à faire.", email)
            return

        # Vérifier / créer l'organisation
        org = db.query(Organization).filter(Organization.slug == organization_slug).first()
        if not org:
            org = Organization(
                id=uuid.uuid4(),
                name=organization_name,
                slug=organization_slug,
                subscription_tier="free",
                max_assets=10,
            )
            db.add(org)
            db.flush()  # pour récupérer org.id
            logger.info("Organisation par défaut créée (%s).", organization_slug)

        # Créer l'utilisateur admin
        admin_user = User(
            id=uuid.uuid4(),
            organization_id=org.id,
            email=email,
            hashed_password=get_password_hash(password),
            full_name="Default Admin",
            role="admin",
            is_active=True,
            is_verified=True,
        )
        db.add(admin_user)
        db.commit()

        logger.info("Utilisateur admin par défaut créé (%s / %s).", email, password)
    except Exception as exc:  # pragma: no cover - log only
        db.rollback()
        logger.error("Erreur lors de la création de l'admin par défaut: %s", exc)
        raise
    finally:
        db.close()


__all__ = [
    "engine",
    "SessionLocal",
    "get_db",
    "init_db",
    "create_default_admin",
]

