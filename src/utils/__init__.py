"""
Package utils pour l'Agent IA de Cybersécurité

Ce package contient tous les utilitaires transversaux utilisés
par les différents modules de l'application.
"""

from .logger import setup_logger, get_logger

from .validators import (
    validate_ip_address,
    validate_domain,
    validate_port,
)

from .parsers import (
    NmapParser,
    ParseResult,
    ParsedVulnerability,
    ParsedHost,
)

# Aliases pour compatibilité
NmapXMLParser = NmapParser
NmapJSONParser = NmapParser

# Version du package utils
__version__ = "1.0.0"

# Export des éléments principaux
__all__ = [
    "__version__",
    "setup_logger",
    "get_logger",
    "validate_ip_address",
    "validate_domain",
    "validate_port",
    "NmapParser",
    "NmapXMLParser",
    "NmapJSONParser",
    "ParseResult",
    "ParsedVulnerability",
    "ParsedHost",
]
