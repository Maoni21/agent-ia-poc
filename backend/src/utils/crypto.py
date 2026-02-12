"""
Utilitaires de chiffrement pour données sensibles (SSH, secrets, etc.).

Utilise Fernet (cryptography) avec une clé dérivée de ENCRYPTION_KEY ou JWT_SECRET_KEY.
"""

from __future__ import annotations

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from src.utils.logger import setup_logger

logger = setup_logger(__name__)

_fernet: Optional[Fernet] = None


def _build_fernet() -> Optional[Fernet]:
    """
    Construit un objet Fernet à partir des variables d'environnement.

    Priorité:
    - ENCRYPTION_KEY (recommandé, 32+ caractères)
    - JWT_SECRET_KEY (fallback raisonnable)
    """
    raw = os.getenv("ENCRYPTION_KEY") or os.getenv("JWT_SECRET_KEY")
    if not raw:
        logger.warning(
            "Aucune clé de chiffrement trouvée (ENCRYPTION_KEY ou JWT_SECRET_KEY). "
            "Les fonctions encrypt/decrypt fonctionneront en mode best-effort."
        )
        return None

    # On dérive une clé 32 bytes puis on l'encode en base64 urlsafe pour Fernet
    try:
        key_material = raw.encode("utf-8")
        if len(key_material) < 32:
            key_material = key_material.ljust(32, b"0")
        else:
            key_material = key_material[:32]
        fernet_key = base64.urlsafe_b64encode(key_material)
        return Fernet(fernet_key)
    except Exception as exc:  # pragma: no cover - log only
        logger.error("Erreur lors de la création de la clé Fernet: %s", exc)
        return None


def get_fernet() -> Optional[Fernet]:
    """Retourne une instance unique de Fernet (ou None si indisponible)."""
    global _fernet
    if _fernet is None:
        _fernet = _build_fernet()
    return _fernet


def encrypt_value(value: Optional[str]) -> Optional[bytes]:
    """
    Chiffre une chaîne de caractères en bytes.

    Si aucune clé n'est disponible, retourne une version encodée en bytes non chiffrée
    (pour éviter les erreurs, mais avec un warning dans les logs).
    """
    if value is None:
        return None

    f = get_fernet()
    data = value.encode("utf-8")

    if not f:
        logger.warning(
            "encrypt_value appelé alors qu'aucune clé Fernet n'est disponible. "
            "La valeur sera stockée en clair (bytes)."
        )
        return data

    return f.encrypt(data)


def decrypt_value(token: Optional[bytes]) -> Optional[str]:
    """
    Déchiffre des bytes vers une chaîne de caractères.

    Si la clé Fernet n'est pas disponible, tente un simple decode() des bytes.
    """
    if token is None:
        return None

    f = get_fernet()
    if not f:
        try:
            return token.decode("utf-8")
        except Exception:
            return None

    try:
        decrypted = f.decrypt(token)
        return decrypted.decode("utf-8")
    except InvalidToken:  # pragma: no cover - log only
        logger.error("Token Fernet invalide lors du déchiffrement.")
        return None
    except Exception as exc:  # pragma: no cover - log only
        logger.error("Erreur lors du déchiffrement Fernet: %s", exc)
        return None


__all__ = ["encrypt_value", "decrypt_value", "get_fernet"]

