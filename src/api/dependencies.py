"""Dépendances partagées pour l'application FastAPI."""

from typing import Dict, Any, Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.database.database import Database
from src.core.supervisor import Supervisor

security = HTTPBearer(auto_error=False)

# Instances globales partagées
supervisor_instance: Optional[Supervisor] = None
database_instance: Optional[Database] = None


def get_database() -> Database:
    """Retourne l'instance initialisée de la base de données."""
    if database_instance is None:
        raise HTTPException(
            status_code=500,
            detail="Base de données non initialisée",
        )
    return database_instance


def get_supervisor() -> Supervisor:
    """Retourne l'instance initialisée du superviseur."""
    if supervisor_instance is None:
        raise HTTPException(
            status_code=500,
            detail="Superviseur non initialisé",
        )
    return supervisor_instance


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Dict[str, Any]:
    """
    Dépendance pour l'authentification.

    Actuellement : exige un token (ex: Bearer <token>), mais ne le valide pas encore
    cryptographiquement. À renforcer avec une vraie vérification JWT/API key.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentification requise")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Token manquant")

    # TODO: Valider réellement le token (JWT, API key, etc.)
    return {"user_id": "authenticated", "role": "user", "token": token}
