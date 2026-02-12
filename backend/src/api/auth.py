"""
Endpoints d'authentification JWT (Phase 1 – Semaine 2).

- POST /auth/register : crée une organization + un user admin
- POST /auth/login    : vérifie le mot de passe et retourne un JWT
- GET  /auth/me       : retourne l'utilisateur courant
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from src.database.init_db import get_db
from src.database.models import Organization, User
from src.utils.logger import setup_logger
from src.utils.security import CryptoUtils
from .dependencies import get_current_user

logger = setup_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


# === CONFIG JWT ===

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

if not JWT_SECRET_KEY:
    logger.warning("JWT_SECRET_KEY n'est pas défini dans l'environnement.")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool

    class Config:
        from_attributes = True


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    organization_name: str


def create_access_token(user: User) -> str:
    """Crée un JWT conforme au cahier des charges."""
    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY non configuré.")

    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role,
        "exp": expire,
    }
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def slugify(name: str) -> str:
    """Slug simpliste pour l'organization."""
    return (
        name.strip()
        .lower()
        .replace(" ", "-")
        .replace("_", "-")
    )


def hash_password(password: str) -> tuple[str, str]:
    """Utilise CryptoUtils.hash_password pour obtenir (hash, salt)."""
    return CryptoUtils.hash_password(password)


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    return CryptoUtils.verify_password(password, hash_hex, salt_hex)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    db: Session = Depends(get_db),
):
    """
    Crée une nouvelle organization + un utilisateur admin.
    - Email unique
    - Slug unique pour l'organization
    """
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Un utilisateur avec cet email existe déjà.",
        )

    org_slug = slugify(payload.organization_name)
    existing_org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if existing_org:
        org_slug = f"{org_slug}-{uuid.uuid4().hex[:6]}"

    organization = Organization(
        id=uuid.uuid4(),
        name=payload.organization_name,
        slug=org_slug,
        subscription_tier="free",
        max_assets=10,
    )
    db.add(organization)
    db.flush()

    pwd_hash, pwd_salt = hash_password(payload.password)
    hashed_password = f"{pwd_hash}:{pwd_salt}"

    user = User(
        id=uuid.uuid4(),
        organization_id=organization.id,
        email=payload.email,
        hashed_password=hashed_password,
        full_name=payload.full_name,
        role="admin",
        is_active=True,
        is_verified=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("Nouvelle organization (%s) et admin (%s) créés.", organization.slug, user.email)
    return user


@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Authentifie un utilisateur via email/password et retourne un JWT.
    """
    user: Optional[User] = db.query(User).filter(User.email == form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides",
        )

    try:
        stored_hash, stored_salt = user.hashed_password.split(":")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Mot de passe stocké dans un format invalide.",
        )

    if not verify_password(form_data.password, stored_hash, stored_salt):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants invalides",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé",
        )

    access_token = create_access_token(user)
    return Token(access_token=access_token)


@router.get("/me", response_model=UserOut)
def me(current_user: dict = Depends(get_current_user)) -> UserOut:
    """
    Retourne l'utilisateur courant (dépend de get_current_user qui valide le JWT).
    """
    return UserOut(
        id=current_user["id"],
        organization_id=current_user["organization_id"],
        email=current_user["email"],
        full_name=current_user.get("full_name"),
        role=current_user["role"],
        is_active=current_user["is_active"],
        is_verified=current_user["is_verified"],
    )


