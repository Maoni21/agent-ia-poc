"""
Package database - Gestion de la persistance
"""

# === EXCEPTIONS ===

class DatabaseError(Exception):
    """Exception de base pour les erreurs de base de données"""
    pass


class ConnectionError(DatabaseError):
    """Erreur de connexion à la base de données"""
    pass


# === IMPORTS ===

from .database import Database

__version__ = "1.0.0"

__all__ = [
    "Database",
    "DatabaseError",
    "ConnectionError",
]
