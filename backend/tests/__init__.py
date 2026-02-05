"""
Package de tests pour l'Agent IA
"""

import sys
from pathlib import Path

# Ajouter src au path
TEST_ROOT = Path(__file__).parent
PROJECT_ROOT = TEST_ROOT.parent
SRC_PATH = PROJECT_ROOT / "src"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

__version__ = "1.0.0"
