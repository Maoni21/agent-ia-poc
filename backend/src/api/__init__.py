"""
Package API REST pour l'Agent IA de Cybersécurité
"""

# Importer la config d'abord
from .config import API_CONFIG, ENDPOINTS, __version__, APIErrorCodes, ERROR_MESSAGES

# Puis les autres modules
try:
    from .main import create_app, app
    from .routes import router
except ImportError:
    # Si les modules n'existent pas encore, pas grave
    create_app = None
    app = None
    router = None

# Exports
__all__ = [
    "create_app",
    "app",
    "router",
    "API_CONFIG",
    "ENDPOINTS",
    "__version__",
    "APIErrorCodes",      # Ajoutez cette ligne
    "ERROR_MESSAGES",     # Ajoutez cette ligne
]