"""
Package core pour l'Agent IA de Cybersécurité
"""

# Importer les exceptions et constantes D'ABORD
from .exceptions import (
    CoreException,
    CollectorException,
    AnalyzerException,
    GeneratorException,
    SupervisorException,
    CoreErrorCodes,
    ERROR_MESSAGES,
    TASK_STATUS,
    OPERATION_TYPES,
    DEFAULT_CONFIG,
)

# Maintenant importer les modules
from .collector import Collector, ScanResult
from .analyzer import Analyzer, AnalysisResult
from .generator import Generator, ScriptResult
from .supervisor import Supervisor

# Version
__version__ = "1.0.0"

# Exports complets
__all__ = [
    # Modules
    "Collector",
    "Analyzer",
    "Generator",
    "Supervisor",

    # Modèles
    "ScanResult",
    "AnalysisResult",
    "ScriptResult",

    # Exceptions
    "CoreException",
    "CollectorException",
    "AnalyzerException",
    "GeneratorException",
    "SupervisorException",

    # Constantes
    "CoreErrorCodes",
    "ERROR_MESSAGES",
    "TASK_STATUS",
    "OPERATION_TYPES",
    "DEFAULT_CONFIG",
]


# === FONCTIONS UTILITAIRES ===

def get_core_version() -> str:
    """Retourne la version du package core"""
    return __version__


def create_supervisor(config: dict = None):
    """Factory pour créer un Supervisor"""
    return Supervisor(config=config)
