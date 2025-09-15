"""
Package de configuration pour l'Agent IA de Cybersécurité

Ce package contient toutes les configurations nécessaires pour le fonctionnement
de l'application : paramètres généraux, prompts IA, base de vulnérabilités, etc.
"""

from .settings import (
    # Configuration générale
    Config,
    get_config,

    # Paramètres de scan
    NMAP_DEFAULT_ARGS,
    SCAN_TIMEOUT,

    # Paramètres IA
    OPENAI_MODEL,
    MAX_TOKENS,

    # Chemins
    DATABASE_PATH,
    LOG_PATH,
    DATA_PATH
)

from .prompts import (
    # Templates de prompts
    VULNERABILITY_ANALYSIS_PROMPT,
    SCRIPT_GENERATION_PROMPT,
    PRIORITY_ASSESSMENT_PROMPT
)

# Version du package de configuration
__version__ = "1.0.0"

# Export des éléments principaux
__all__ = [
    # Configuration
    "Config",
    "get_config",

    # Constantes de scan
    "NMAP_DEFAULT_ARGS",
    "SCAN_TIMEOUT",

    # Constantes IA
    "OPENAI_MODEL",
    "MAX_TOKENS",

    # Chemins
    "DATABASE_PATH",
    "LOG_PATH",
    "DATA_PATH",

    # Prompts
    "VULNERABILITY_ANALYSIS_PROMPT",
    "SCRIPT_GENERATION_PROMPT",
    "PRIORITY_ASSESSMENT_PROMPT",
]