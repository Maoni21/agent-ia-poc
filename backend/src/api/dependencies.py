"""Dépendances partagées pour l'application FastAPI (DB, Supervisor, Auth JWT/RBAC)."""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

# Ajouter backend au PYTHONPATH pour que les imports \"from src.\" pointent sur le backend unifié
BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.core.supervisor import Supervisor
from src.core.permissions import has_permission
from src.database.database import Database
from src.database.init_db import get_db
from src.database.models import User
from src.utils.logger import setup_logger
from dotenv import load_dotenv

logger = setup_logger(__name__)

# Même logique que config.settings : garantir backend/.env même si l'import ne passe pas par config en premier
load_dotenv(BACKEND_DIR.parent / ".env")
load_dotenv(BACKEND_DIR / ".env", override=True)

security = HTTPBearer(auto_error=False)

# Instances globales partagées (pour l'ancien moteur SQLite + Supervisor)
supervisor_instance: Optional[Supervisor] = None
database_instance: Optional[Database] = None


def get_database() -> Database:
    """Retourne l'instance initialisée de la base de données (moteur SQLite historique)."""
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


# === CONFIG JWT ===

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

_DEV_JWT_FALLBACK = (
    "dev-insecure-jwt-key-change-in-production-min-32-characters-long"
)


def get_jwt_secret_key() -> str:
    """Clé de signature JWT ; en dev uniquement si ALLOW_JWT_DEV_SECRET=1."""
    key = os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY")
    if key:
        return key
    if os.getenv("ALLOW_JWT_DEV_SECRET", "").lower() in ("1", "true", "yes"):
        logger.warning(
            "JWT: ALLOW_JWT_DEV_SECRET activé — définir JWT_SECRET_KEY en production."
        )
        return _DEV_JWT_FALLBACK
    return ""


def decode_token(token: str) -> Dict[str, Any]:
    """Décode et valide un JWT, retourne le payload."""
    secret = get_jwt_secret_key()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Clé JWT non configurée côté serveur.",
        )
    try:
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Dépendance d'authentification principale.

    - Lit le header Authorization: Bearer <token>
    - Valide le JWT
    - Charge l'utilisateur SQLAlchemy correspondant
    - Retourne un dict sérialisé (id, organization_id, role, permissions, ...)
    """
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentification requise")

    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token manquant")

    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide (sub manquant)")

    try:
        user_uuid = uuid.UUID(user_id)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalide (sub incorrect)")

    user: Optional[User] = db.query(User).filter(User.id == user_uuid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Compte désactivé")

    return {
        "id": user.id,
        "organization_id": user.organization_id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "permissions": user.permissions or [],
        "is_active": user.is_active,
        "is_verified": user.is_verified,
    }


def require_permission(permission: str) -> Callable:
    """
    Dépendance RBAC basée sur une permission (ex: 'scans:create').

    À utiliser dans les endpoints protégés :

        @router.post(..., dependencies=[Depends(require_permission("scans:create"))])
    """

    async def _dependency(current_user: Dict[str, Any] = Depends(get_current_user)) -> None:
        role = current_user["role"]
        custom_perms = current_user.get("permissions") or []
        if not has_permission(role, permission, custom_perms):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' requise",
            )

    return _dependency


def require_role(*roles: str) -> Callable:
    """
    Dépendance RBAC par rôle.

    Exemple:
        @router.delete(..., dependencies=[Depends(require_role("admin"))])
    """

    async def _dependency(current_user: Dict[str, Any] = Depends(get_current_user)) -> None:
        if current_user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rôle requis: {', '.join(roles)}",
            )

    return _dependency

