"""
Package utils - Utilitaires transversaux
"""

# === EXCEPTIONS ===

class ValidationError(Exception):
    """Exception levée lors d'une erreur de validation"""
    pass


class ParserError(Exception):
    """Exception levée lors d'une erreur de parsing"""
    pass


class SecurityError(Exception):
    """Exception levée lors d'une erreur de sécurité"""
    pass


# === IMPORTS ===

from .logger import setup_logger
from .validators import validate_ip_address, validate_domain, validate_port
from .decorators import handle_errors, retry, timeout

__version__ = "1.0.0"

__all__ = [
    # Fonctions principales
    "setup_logger",
    "validate_ip_address",
    "validate_domain",
    "validate_port",
    "handle_errors",
    "retry",
    "timeout",

    # Exceptions
    "ValidationError",
    "ParserError",
    "SecurityError",
]
