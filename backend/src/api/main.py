"""
Application FastAPI principale pour l'Agent IA de Cybersécurité

Ce module contient la configuration et l'initialisation de l'application FastAPI
qui expose l'API REST pour interagir avec l'agent IA de cybersécurité.
"""

import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
import uvicorn

import sys
from pathlib import Path

# Ajouter backend au PYTHONPATH pour que les imports \"from src.\" pointent sur le backend unifié
BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Ajouter la racine du projet pour config
ROOT_DIR = BACKEND_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from config import get_config, LOG_LEVEL
from src.database.database import Database
from src.utils.logger import setup_logger
from src.core.supervisor import Supervisor
from .config import (
    API_CONFIG,
    MIDDLEWARE_CONFIG,
    APIErrorCodes,
    ERROR_MESSAGES,
    API_TAGS,
)
from . import dependencies
from .dependencies import get_database, get_supervisor, get_current_user
from .api_v1 import router as api_v1_router
from .routes.scans import ws_router as scans_ws_router
from .scan_v2 import router as scan_v2_router, ws_router as scan_v2_ws_router
from .auth import router as auth_router

# Configuration du logging
logger = setup_logger(__name__)

# === GESTION DU CYCLE DE VIE DE L'APPLICATION ===

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestionnaire du cycle de vie de l'application FastAPI
    Initialise les ressources au démarrage et les nettoie à l'arrêt
    """
    # Démarrage
    logger.info("🚀 Démarrage de l'API Agent IA Cybersécurité")

    try:
        # Initialiser la configuration
        config = get_config()
        logger.info(f"Configuration chargée: {config.openai_model}")

        # Initialiser la base de données
        dependencies.database_instance = Database()
        dependencies.database_instance.create_tables()
        logger.info("✅ Base de données initialisée")

        # Initialiser le superviseur
        dependencies.supervisor_instance = Supervisor()
        logger.info("✅ Superviseur initialisé")

        # Vérifications de santé
        await health_checks()

        logger.info("✅ API démarrée avec succès")

    except Exception as e:
        logger.error(f"❌ Erreur lors du démarrage: {e}")
        raise

    # L'application est prête
    yield

    # Arrêt
    logger.info("🛑 Arrêt de l'API Agent IA Cybersécurité")

    try:
        # Nettoyage des ressources
        if dependencies.supervisor_instance:
            await dependencies.supervisor_instance.shutdown()
            dependencies.supervisor_instance = None
            logger.info("✅ Superviseur arrêté")

        if dependencies.database_instance:
            dependencies.database_instance.close()
            dependencies.database_instance = None
            logger.info("✅ Base de données fermée")

    except Exception as e:
        logger.error(f"❌ Erreur lors de l'arrêt: {e}")

    logger.info("✅ Arrêt terminé")


# === VÉRIFICATIONS DE SANTÉ ===

async def health_checks():
    """Vérifications de santé au démarrage"""

    # Vérifier la base de données
    try:
        get_database().get_connection()
        logger.info("✅ Connexion base de données OK")
    except Exception as e:
        logger.error(f"❌ Base de données indisponible: {e}")
        raise

    # Vérifier la configuration OpenAI
    try:
        config = get_config()
        if not config.openai_api_key:
            logger.warning("⚠️ Clé OpenAI non configurée")
        else:
            logger.info("✅ Configuration OpenAI OK")
    except Exception as e:
        logger.error(f"❌ Configuration invalide: {e}")
        raise


# === CRÉATION DE L'APPLICATION ===

def create_app() -> FastAPI:
    """
    Factory pour créer l'application FastAPI

    Returns:
        FastAPI: Instance de l'application configurée
    """

    # Créer l'application FastAPI
    app = FastAPI(
        title=API_CONFIG["title"],
        description=API_CONFIG["description"],
        version=API_CONFIG["version"],
        contact=API_CONFIG["contact"],
        license_info=API_CONFIG["license_info"],
        lifespan=lifespan,
        openapi_tags=API_TAGS,
    )

    # Ajouter les middlewares
    setup_middlewares(app)

    # Ajouter les gestionnaires d'erreur
    setup_error_handlers(app)

    # Routes API v1 (PostgreSQL + Celery + stats dashboard)
    app.include_router(api_v1_router)

    # Authentification (JWT)
    app.include_router(auth_router)

    # Routes API v2 (scan historique)
    app.include_router(scan_v2_router)

    # WebSockets pour la progression des scans
    app.include_router(scan_v2_ws_router)  # historique
    app.include_router(scans_ws_router)    # nouveau basé BDD/Celery

    # Configuration OpenAPI personnalisée
    setup_openapi(app)

    return app


# === CONFIGURATION DES MIDDLEWARES ===

def setup_middlewares(app: FastAPI):
    """Configure les middlewares de l'application"""

    # CORS - Autoriser le frontend React
    app.add_middleware(
        CORSMiddleware,
        allow_origins=MIDDLEWARE_CONFIG["cors"]["allow_origins"],
        allow_credentials=MIDDLEWARE_CONFIG["cors"]["allow_credentials"],
        allow_methods=MIDDLEWARE_CONFIG["cors"]["allow_methods"],
        allow_headers=MIDDLEWARE_CONFIG["cors"]["allow_headers"],
    )

    # Compression
    app.add_middleware(
        GZipMiddleware,
        minimum_size=MIDDLEWARE_CONFIG["compression"]["minimum_size"]
    )

    # Middleware de logging des requêtes
    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        """Middleware pour logger les requêtes"""
        start_time = time.time()

        # Logger la requête entrante
        logger.info(f"🔄 {request.method} {request.url.path}")

        # Traiter la requête
        response = await call_next(request)

        # Logger la réponse
        process_time = time.time() - start_time
        logger.info(
            f"✅ {request.method} {request.url.path} "
            f"- {response.status_code} - {process_time:.3f}s"
        )

        return response

    # Middleware de rate limiting (basique)
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Middleware basique de rate limiting"""
        # TODO: Implémenter un rate limiting plus sophistiqué
        # Pour l'instant, on laisse passer toutes les requêtes
        response = await call_next(request)
        return response


# === GESTIONNAIRES D'ERREUR ===

def setup_error_handlers(app: FastAPI):
    """Configure les gestionnaires d'erreur personnalisés"""

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Gestionnaire pour les erreurs HTTP"""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "type": "http_error"
                },
                "success": False,
                "timestamp": time.time()
            }
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Gestionnaire pour les erreurs générales"""
        logger.error(f"❌ Erreur non gérée: {exc}", exc_info=True)

        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": APIErrorCodes.INTERNAL_ERROR,
                    "message": ERROR_MESSAGES[APIErrorCodes.INTERNAL_ERROR],
                    "type": "internal_error"
                },
                "success": False,
                "timestamp": time.time()
            }
        )

    @app.exception_handler(ValueError)
    async def validation_exception_handler(request: Request, exc: ValueError):
        """Gestionnaire pour les erreurs de validation"""
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": APIErrorCodes.VALIDATION_ERROR,
                    "message": str(exc),
                    "type": "validation_error"
                },
                "success": False,
                "timestamp": time.time()
            }
        )


# === CONFIGURATION OPENAPI ===

def setup_openapi(app: FastAPI):
    """Configure la documentation OpenAPI personnalisée"""

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=API_CONFIG["title"],
            version=API_CONFIG["version"],
            description=API_CONFIG["description"],
            routes=app.routes,
        )

        # Ajouter des informations supplémentaires
        openapi_schema["info"]["x-logo"] = {
            "url": "/static/logo.png"
        }

        # Ajouter la sécurité
        openapi_schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            }
        }

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi


# === CRÉATION DE L'INSTANCE GLOBALE ===

# Créer l'application
app = create_app()


# === ENDPOINTS DE BASE ===

@app.get("/", tags=["root"])
async def root():
    """Endpoint racine"""
    return {
        "message": "API Agent IA de Cybersécurité",
        "version": API_CONFIG["version"],
        "status": "running",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health", tags=["health"])
async def health_check():
    """Endpoint de vérification de santé"""
    try:
        # Vérifier la base de données
        db = get_database()
        db.get_connection()

        # Vérifier le superviseur
        supervisor = get_supervisor()

        return {
            "status": "healthy",
            "timestamp": time.time(),
            "version": API_CONFIG["version"],
            "services": {
                "database": "operational",
                "supervisor": "operational",
                "ai_service": "operational"  # TODO: vérifier vraiment
            }
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "timestamp": time.time(),
                "error": str(e)
            }
        )


@app.get("/metrics", tags=["health"])
async def metrics():
    """Endpoint pour les métriques de monitoring"""
    try:
        db = get_database()

        # Statistiques basiques
        stats = {
            "total_scans": 0,  # TODO: implémenter
            "active_scans": 0,  # TODO: implémenter
            "total_vulnerabilities": 0,  # TODO: implémenter
            "uptime": time.time(),  # TODO: calculer le vrai uptime
        }

        return {
            "metrics": stats,
            "timestamp": time.time()
        }

    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail="Metrics unavailable")


# === POINT D'ENTRÉE POUR DÉVELOPPEMENT ===

if __name__ == "__main__":
    # Configuration pour le développement
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level=LOG_LEVEL.lower(),
        access_log=True
    )