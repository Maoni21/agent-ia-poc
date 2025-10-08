"""
Package principal de l'Agent IA de Cybersécurité
"""

from .core import Collector, Analyzer, Generator, Supervisor
from .database import Database

__version__ = "1.0.0"

__all__ = [
    "Collector",
    "Analyzer", 
    "Generator",
    "Supervisor",
    "Database",
    "__version__",
]
