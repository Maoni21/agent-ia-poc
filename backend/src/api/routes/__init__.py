from fastapi import APIRouter

from .assets import router as assets_router
from .scans import router as scans_router, ws_router as scans_ws_router
from .vulnerabilities import router as vulns_router
from .integrations import router as integrations_router
from .dashboard import router as dashboard_router

# Router racine v1
router = APIRouter(prefix="/api/v1")

# On monte les sous-routers dessus
router.include_router(assets_router)
router.include_router(scans_router)
router.include_router(vulns_router)
router.include_router(integrations_router)
router.include_router(dashboard_router)

# Les websockets de scans restent incluses dans main.py