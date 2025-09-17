"""Package de configuration pour l'Agent IA de Cybersécurité."""

from .settings import (
    Config,
    get_config,
    validate_config,
    get_nmap_config,
    get_llm_config,
    NMAP_DEFAULT_ARGS,
    SCAN_TIMEOUT,
    OPENAI_MODEL,
    MAX_TOKENS,
    LOG_LEVEL,
    LOG_FILE,
    DATABASE_PATH,
    DATA_PATH,
    LOG_PATH,
    VULNERABILITY_DB_PATH,
)

from .prompts import (
    VULNERABILITY_ANALYSIS_PROMPT,
    SCRIPT_GENERATION_PROMPT,
    PRIORITY_ASSESSMENT_PROMPT,
)

__version__ = "1.0.0"

__all__ = [
    "Config",
    "get_config",
    "validate_config",
    "get_nmap_config",
    "get_llm_config",
    "NMAP_DEFAULT_ARGS",
    "SCAN_TIMEOUT",
    "OPENAI_MODEL",
    "MAX_TOKENS",
    "LOG_LEVEL",
    "LOG_FILE",
    "DATABASE_PATH",
    "DATA_PATH",
    "LOG_PATH",
    "VULNERABILITY_DB_PATH",
    "VULNERABILITY_ANALYSIS_PROMPT",
    "SCRIPT_GENERATION_PROMPT",
    "PRIORITY_ASSESSMENT_PROMPT",
]
