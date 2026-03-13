"""
Configuration pytest pour l'Agent IA de Cybersécurité.

Ajoute la racine du projet (agent-ia-poc) au PYTHONPATH pour que
l'import `from config import ...` trouve le package config à la racine.
"""
import sys
from pathlib import Path

# Racine du projet = parent du dossier backend
BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
