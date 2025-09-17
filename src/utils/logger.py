"""
Module de logging avancé pour l'Agent IA de Cybersécurité

Ce module fournit un système de logging centralisé, structuré et performant
avec support des couleurs, rotation des fichiers, formatage JSON,
et intégration avec les différents modules de l'application.

Fonctionnalités :
- Logging coloré pour la console
- Rotation automatique des fichiers de log
- Formatage structuré (JSON, texte)
- Niveaux de log configurables par module
- Logging asynchrone pour les performances
- Intégration avec les systèmes de monitoring
- Filtrage et masquage des données sensibles
"""

import asyncio
import json
import logging
import logging.handlers
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Union, TextIO
from contextlib import contextmanager
import queue
import atexit

# === CONSTANTES ET CONFIGURATION ===

# Niveaux de log personnalisés
TRACE_LEVEL = 5
SUCCESS_LEVEL = 25

# Ajout des niveaux personnalisés
logging.addLevelName(TRACE_LEVEL, "TRACE")
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

# Configuration par défaut
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DETAILED_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s"
COLORED_LOG_FORMAT = "%(log_color)s%(asctime)s - %(name)s - %(levelname)s%(reset)s - %(message)s"
JSON_LOG_FORMAT = "json"

# Couleurs pour les niveaux de log
LOG_COLORS = {
    'TRACE': 'cyan',
    'DEBUG': 'blue',
    'INFO': 'white',
    'SUCCESS': 'green',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'bold_red',
}

# Niveaux de log disponibles
LOG_LEVELS = {
    'TRACE': TRACE_LEVEL,
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'SUCCESS': SUCCESS_LEVEL,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

# Configuration par défaut du logging
DEFAULT_LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": DEFAULT_LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "detailed": {
            "format": DETAILED_LOG_FORMAT,
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "json": {
            "()": "src.utils.logger.JSONFormatter"
        },
        "colored": {
            "()": "src.utils.logger.ColoredFormatter",
            "format": COLORED_LOG_FORMAT
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "colored",
            "stream": "ext://sys.stdout"
        },
        "file_info": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "INFO",
            "formatter": "detailed",
            "filename": "logs/app.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5
        },
        "file_error": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "detailed",
            "filename": "logs/error.log",
            "maxBytes": 10485760,
            "backupCount": 5
        }
    },
    "loggers": {
        "src": {
            "level": "INFO",
            "handlers": ["console", "file_info", "file_error"],
            "propagate": False
        },
        "src.core.collector": {
            "level": "DEBUG",
            "handlers": ["console", "file_info"],
            "propagate": False
        },
        "src.core.analyzer": {
            "level": "DEBUG",
            "handlers": ["console", "file_info"],
            "propagate": False
        }
    },
    "root": {
        "level": "WARNING",
        "handlers": ["console"]
    }
}

# Données sensibles à masquer dans les logs
SENSITIVE_PATTERNS = [
    r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9_\-]+)',
    r'password["\s]*[:=]["\s]*([^\s"]+)',
    r'token["\s]*[:=]["\s]*([a-zA-Z0-9_\-\.]+)',
    r'secret["\s]*[:=]["\s]*([a-zA-Z0-9_\-]+)',
    r'authorization["\s]*:["\s]*([a-zA-Z0-9_\-\.]+)'
]


# === CLASSES DE FORMATAGE ===

class ColoredFormatter(logging.Formatter):
    """
    Formateur avec couleurs pour la console

    Utilise des codes ANSI pour colorer les logs selon leur niveau.
    Compatible avec la plupart des terminaux modernes.
    """

    # Codes couleur ANSI
    COLORS = {
        'black': '\033[30m',
        'red': '\033[31m',
        'green': '\033[32m',
        'yellow': '\033[33m',
        'blue': '\033[34m',
        'magenta': '\033[35m',
        'cyan': '\033[36m',
        'white': '\033[37m',
        'bold_red': '\033[1;31m',
        'bold_green': '\033[1;32m',
        'bold_yellow': '\033[1;33m',
        'reset': '\033[0m'
    }

    def __init__(self, format_string=None):
        super().__init__()
        self.format_string = format_string or COLORED_LOG_FORMAT

        # Vérifier si on est dans un terminal supportant les couleurs
        self.use_colors = (
                                  hasattr(sys.stderr, 'isatty') and sys.stderr.isatty() and
                                  os.environ.get('TERM') != 'dumb'
                          ) or os.environ.get('FORCE_COLOR') == '1'

    def format(self, record):
        if not self.use_colors:
            # Format sans couleurs
            formatter = logging.Formatter(
                self.format_string.replace('%(log_color)s', '').replace('%(reset)s', '')
            )
            return formatter.format(record)

        # Ajouter les couleurs au record
        level_color = self.COLORS.get(LOG_COLORS.get(record.levelname, 'white'), '')
        reset_color = self.COLORS['reset']

        record.log_color = level_color
        record.reset = reset_color

        formatter = logging.Formatter(self.format_string)
        return formatter.format(record)


class JSONFormatter(logging.Formatter):
    """
    Formateur JSON pour logging structuré

    Convertit les logs en format JSON pour faciliter l'analyse
    et l'intégration avec des systèmes de monitoring.
    """

    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "thread": record.thread,
            "thread_name": record.threadName,
            "process": record.process,
        }

        # Ajouter les informations d'exception si présentes
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info) if record.exc_info else None
            }

        # Ajouter les données extra
        for key, value in record.__dict__.items():
            if key not in log_entry and not key.startswith('_') and key not in [
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                'filename', 'module', 'lineno', 'funcName', 'created',
                'msecs', 'relativeCreated', 'thread', 'threadName',
                'processName', 'process', 'exc_info', 'exc_text', 'stack_info'
            ]:
                log_entry["extra"] = log_entry.get("extra", {})
                log_entry["extra"][key] = value

        return json.dumps(log_entry, ensure_ascii=False, default=str)


class SensitiveDataFilter(logging.Filter):
    """
    Filtre pour masquer les données sensibles dans les logs

    Utilise des expressions régulières pour détecter et masquer
    les clés API, mots de passe, tokens, etc.
    """

    def __init__(self, patterns=None):
        super().__init__()
        self.patterns = patterns or SENSITIVE_PATTERNS
        import re
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.patterns]

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._mask_sensitive_data(record.msg)

        # Masquer dans les arguments aussi
        if hasattr(record, 'args') and record.args:
            record.args = tuple(
                self._mask_sensitive_data(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )

        return True

    def _mask_sensitive_data(self, text):
        """Masque les données sensibles dans un texte"""
        for pattern in self.compiled_patterns:
            text = pattern.sub(r'\1***MASKED***', text)
        return text


class ContextualLogger:
    """
    Logger avec contexte automatique

    Ajoute automatiquement des informations contextuelles
    aux logs (ID de scan, utilisateur, session, etc.)
    """

    def __init__(self, logger, context=None):
        self.logger = logger
        self.context = context or {}
        self._local = threading.local()

    def set_context(self, **kwargs):
        """Définit le contexte pour les logs suivants"""
        self.context.update(kwargs)

    def clear_context(self):
        """Efface le contexte"""
        self.context.clear()

    def _log_with_context(self, level, msg, *args, **kwargs):
        """Log avec contexte ajouté"""
        extra = kwargs.get('extra', {})
        extra.update(self.context)
        kwargs['extra'] = extra

        self.logger.log(level, msg, *args, **kwargs)

    def trace(self, msg, *args, **kwargs):
        self._log_with_context(TRACE_LEVEL, msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self._log_with_context(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._log_with_context(logging.INFO, msg, *args, **kwargs)

    def success(self, msg, *args, **kwargs):
        self._log_with_context(SUCCESS_LEVEL, msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log_with_context(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._log_with_context(logging.ERROR, msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._log_with_context(logging.CRITICAL, msg, *args, **kwargs)

    def exception(self, msg, *args, **kwargs):
        kwargs['exc_info'] = True
        self._log_with_context(logging.ERROR, msg, *args, **kwargs)


class AsyncLogHandler(logging.Handler):
    """
    Handler de logging asynchrone pour de meilleures performances

    Évite de bloquer l'application lors d'opérations d'écriture
    de logs sur disque ou réseau.
    """

    def __init__(self, target_handler, queue_size=1000):
        super().__init__()
        self.target_handler = target_handler
        self.log_queue = queue.Queue(maxsize=queue_size)
        self.worker_thread = threading.Thread(target=self._log_worker, daemon=True)
        self.worker_thread.start()
        self.shutdown_event = threading.Event()

        # Enregistrer le cleanup à la fermeture
        atexit.register(self.close)

    def emit(self, record):
        try:
            # Ajouter le record à la queue sans bloquer
            self.log_queue.put_nowait(record)
        except queue.Full:
            # Si la queue est pleine, on peut soit ignorer, soit forcer
            # Ici on force l'écriture synchrone pour ne pas perdre le log
            self.target_handler.emit(record)

    def _log_worker(self):
        """Worker thread qui traite les logs de manière asynchrone"""
        while not self.shutdown_event.is_set():
            try:
                # Attendre un record avec timeout
                record = self.log_queue.get(timeout=1.0)
                if record is None:  # Signal de fin
                    break

                # Traiter le record avec le handler cible
                self.target_handler.emit(record)
                self.log_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                # En cas d'erreur, on continue pour ne pas planter le worker
                print(f"Erreur dans le worker de log: {e}", file=sys.stderr)

    def close(self):
        """Ferme proprement le handler asynchrone"""
        if not self.shutdown_event.is_set():
            self.shutdown_event.set()

            # Vider la queue
            try:
                while True:
                    record = self.log_queue.get_nowait()
                    self.target_handler.emit(record)
            except queue.Empty:
                pass

            # Attendre que le worker se termine
            if self.worker_thread.is_alive():
                self.worker_thread.join(timeout=5.0)

            # Fermer le handler cible
            self.target_handler.close()


class StructuredLogger:
    """
    Logger structuré pour l'analyse et le monitoring

    Facilite la création de logs structurés avec des métadonnées
    standardisées pour l'intégration avec des outils d'analyse.
    """

    def __init__(self, logger, service_name="vulnerability_agent"):
        self.logger = logger
        self.service_name = service_name
        self.session_id = self._generate_session_id()

    def _generate_session_id(self):
        """Génère un ID de session unique"""
        import uuid
        return str(uuid.uuid4())[:8]

    def log_scan_start(self, scan_id: str, target: str, scan_type: str):
        """Log structuré pour le début d'un scan"""
        self.logger.info(
            "Scan started",
            extra={
                "event_type": "scan_start",
                "scan_id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "service": self.service_name,
                "session_id": self.session_id
            }
        )

    def log_scan_complete(self, scan_id: str, duration: float, vulnerabilities_found: int):
        """Log structuré pour la fin d'un scan"""
        self.logger.info(
            "Scan completed",
            extra={
                "event_type": "scan_complete",
                "scan_id": scan_id,
                "duration": duration,
                "vulnerabilities_found": vulnerabilities_found,
                "service": self.service_name,
                "session_id": self.session_id
            }
        )

    def log_vulnerability_found(self, scan_id: str, vulnerability_id: str, severity: str, cvss_score: float = None):
        """Log structuré pour une vulnérabilité trouvée"""
        self.logger.warning(
            "Vulnerability detected",
            extra={
                "event_type": "vulnerability_found",
                "scan_id": scan_id,
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "service": self.service_name,
                "session_id": self.session_id
            }
        )

    def log_ai_analysis(self, analysis_id: str, model_used: str, processing_time: float, confidence: float):
        """Log structuré pour une analyse IA"""
        self.logger.info(
            "AI analysis completed",
            extra={
                "event_type": "ai_analysis",
                "analysis_id": analysis_id,
                "model_used": model_used,
                "processing_time": processing_time,
                "confidence": confidence,
                "service": self.service_name,
                "session_id": self.session_id
            }
        )

    def log_script_generated(self, script_id: str, vulnerability_id: str, risk_level: str, validation_status: str):
        """Log structuré pour la génération d'un script"""
        self.logger.info(
            "Remediation script generated",
            extra={
                "event_type": "script_generated",
                "script_id": script_id,
                "vulnerability_id": vulnerability_id,
                "risk_level": risk_level,
                "validation_status": validation_status,
                "service": self.service_name,
                "session_id": self.session_id
            }
        )

    def log_error(self, error_type: str, error_message: str, context: Dict[str, Any] = None):
        """Log structuré pour les erreurs"""
        extra_data = {
            "event_type": "error",
            "error_type": error_type,
            "service": self.service_name,
            "session_id": self.session_id
        }

        if context:
            extra_data.update(context)

        self.logger.error(
            error_message,
            extra=extra_data
        )


# === FONCTIONS PRINCIPALES ===

def setup_logger(name: str, level: str = "INFO", config: Dict[str, Any] = None) -> logging.Logger:
    """
    Configure et retourne un logger pour un module

    Args:
        name: Nom du logger (généralement __name__)
        level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        config: Configuration personnalisée

    Returns:
        logging.Logger: Logger configuré
    """
    # Créer le logger
    logger = logging.getLogger(name)

    # Éviter la duplication si déjà configuré
    if logger.handlers:
        return logger

    # Définir le niveau
    numeric_level = LOG_LEVELS.get(level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Ajouter les méthodes personnalisées
    def trace(self, message, *args, **kwargs):
        if self.isEnabledFor(TRACE_LEVEL):
            self._log(TRACE_LEVEL, message, args, **kwargs)

    def success(self, message, *args, **kwargs):
        if self.isEnabledFor(SUCCESS_LEVEL):
            self._log(SUCCESS_LEVEL, message, args, **kwargs)

    logger.trace = trace.__get__(logger, logging.Logger)
    logger.success = success.__get__(logger, logging.Logger)

    # Configuration par défaut si pas fournie
    if config is None:
        config = _get_default_config_for_logger(name)

    # Créer les répertoires de logs si nécessaire
    _ensure_log_directories()

    # Configurer selon la config
    _configure_logger_from_config(logger, config)

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Récupère un logger existant ou en crée un nouveau

    Args:
        name: Nom du logger

    Returns:
        logging.Logger: Logger existant ou nouveau
    """
    logger = logging.getLogger(name)

    # Si pas de handlers, le configurer avec les paramètres par défaut
    if not logger.handlers:
        return setup_logger(name)

    return logger


def configure_logging(config: Dict[str, Any] = None, config_file: str = None):
    """
    Configure le système de logging global

    Args:
        config: Configuration de logging (dict)
        config_file: Chemin vers fichier de configuration JSON/YAML
    """
    if config_file:
        config = _load_config_from_file(config_file)
    elif config is None:
        config = DEFAULT_LOGGING_CONFIG

    # S'assurer que les répertoires existent
    _ensure_log_directories()

    # Appliquer la configuration
    logging.config.dictConfig(config)


def create_contextual_logger(name: str, context: Dict[str, Any] = None) -> ContextualLogger:
    """
    Crée un logger contextuel avec des métadonnées automatiques

    Args:
        name: Nom du logger
        context: Contexte initial

    Returns:
        ContextualLogger: Logger avec contexte
    """
    base_logger = get_logger(name)
    return ContextualLogger(base_logger, context)


def create_structured_logger(name: str, service_name: str = "vulnerability_agent") -> StructuredLogger:
    """
    Crée un logger structuré pour l'analyse

    Args:
        name: Nom du logger
        service_name: Nom du service

    Returns:
        StructuredLogger: Logger structuré
    """
    base_logger = get_logger(name)
    return StructuredLogger(base_logger, service_name)


@contextmanager
def log_execution_time(logger, operation_name: str, level: int = logging.INFO):
    """
    Gestionnaire de contexte pour logger le temps d'exécution

    Args:
        logger: Logger à utiliser
        operation_name: Nom de l'opération
        level: Niveau de log

    Usage:
        with log_execution_time(logger, "scan_nmap"):
            # Opération à chronométrer
            result = some_long_operation()
    """
    start_time = time.time()
    logger.log(level, f"Starting {operation_name}")

    try:
        yield
        duration = time.time() - start_time
        logger.log(level, f"Completed {operation_name} in {duration:.3f}s")
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Failed {operation_name} after {duration:.3f}s: {e}")
        raise


def mask_sensitive_data(text: str, mask: str = "***MASKED***") -> str:
    """
    Masque les données sensibles dans un texte

    Args:
        text: Texte à analyser
        mask: Texte de remplacement

    Returns:
        str: Texte avec données masquées
    """
    import re

    result = text
    for pattern in SENSITIVE_PATTERNS:
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        result = compiled_pattern.sub(f'\\1{mask}', result)

    return result


# === FONCTIONS INTERNES ===

def _get_default_config_for_logger(name: str) -> Dict[str, Any]:
    """Génère une configuration par défaut pour un logger"""

    # Configuration spécialisée selon le module
    if "collector" in name:
        handlers = ["console", "file_scan"]
        level = "DEBUG"
    elif "analyzer" in name:
        handlers = ["console", "file_analysis"]
        level = "DEBUG"
    elif "generator" in name:
        handlers = ["console", "file_scripts"]
        level = "DEBUG"
    elif "api" in name:
        handlers = ["console", "file_api"]
        level = "INFO"
    else:
        handlers = ["console", "file_info"]
        level = "INFO"

    return {
        "level": level,
        "handlers": handlers,
        "formatters": {
            "console": "colored",
            "file": "detailed"
        }
    }


def _configure_logger_from_config(logger: logging.Logger, config: Dict[str, Any]):
    """Configure un logger selon une configuration"""

    # Handler console avec couleurs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter())
    console_handler.setLevel(logging.INFO)

    # Ajouter le filtre de données sensibles
    sensitive_filter = SensitiveDataFilter()
    console_handler.addFilter(sensitive_filter)

    logger.addHandler(console_handler)

    # Handler fichier détaillé
    log_file = Path("logs") / "app.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10485760,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(DETAILED_LOG_FORMAT))
    file_handler.setLevel(logging.DEBUG)
    file_handler.addFilter(sensitive_filter)

    logger.addHandler(file_handler)

    # Handler erreurs séparé
    error_file = Path("logs") / "error.log"
    error_handler = logging.handlers.RotatingFileHandler(
        error_file,
        maxBytes=10485760,
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setFormatter(logging.Formatter(DETAILED_LOG_FORMAT))
    error_handler.setLevel(logging.ERROR)

    logger.addHandler(error_handler)


def _ensure_log_directories():
    """S'assure que les répertoires de logs existent"""
    log_dirs = ["logs"]

    for log_dir in log_dirs:
        Path(log_dir).mkdir(exist_ok=True)


def _load_config_from_file(config_file: str) -> Dict[str, Any]:
    """Charge une configuration depuis un fichier"""
    config_path = Path(config_file)

    if not config_path.exists():
        raise FileNotFoundError(f"Fichier de configuration non trouvé: {config_file}")

    with open(config_path, 'r', encoding='utf-8') as f:
        if config_path.suffix.lower() == '.json':
            return json.load(f)
        elif config_path.suffix.lower() in ['.yml', '.yaml']:
            import yaml
            return yaml.safe_load(f)
        else:
            raise ValueError("Format de configuration non supporté (JSON ou YAML requis)")


# === DÉCORATEURS DE LOGGING ===

def log_function_call(logger=None, level=logging.DEBUG, include_args=True, include_result=False):
    """
    Décorateur pour logger automatiquement les appels de fonction

    Args:
        logger: Logger à utiliser (None = auto)
        level: Niveau de log
        include_args: Inclure les arguments
        include_result: Inclure le résultat
    """

    def decorator(func):
        import functools
        import inspect

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Obtenir le logger si pas fourni
            func_logger = logger or get_logger(func.__module__)

            # Construire le message
            func_name = f"{func.__module__}.{func.__name__}"

            if include_args:
                # Récupérer les noms des paramètres
                sig = inspect.signature(func)
                bound_args = sig.bind(*args, **kwargs)
                bound_args.apply_defaults()

                args_str = ", ".join(f"{k}={v}" for k, v in bound_args.arguments.items())
                message = f"Calling {func_name}({args_str})"
            else:
                message = f"Calling {func_name}"

            func_logger.log(level, message)

            try:
                result = func(*args, **kwargs)

                if include_result:
                    func_logger.log(level, f"{func_name} returned: {result}")
                else:
                    func_logger.log(level, f"{func_name} completed successfully")

                return result

            except Exception as e:
                func_logger.error(f"{func_name} failed with {type(e).__name__}: {e}")
                raise

        return wrapper

    return decorator


def log_exceptions(logger=None, level=logging.ERROR, reraise=True):
    """
    Décorateur pour logger automatiquement les exceptions

    Args:
        logger: Logger à utiliser
        level: Niveau de log
        reraise: Re-lancer l'exception après logging
    """

    def decorator(func):
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            func_logger = logger or get_logger(func.__module__)

            try:
                return func(*args, **kwargs)
            except Exception as e:
                func_logger.log(
                    level,
                    f"Exception in {func.__module__}.{func.__name__}: {type(e).__name__}: {e}",
                    exc_info=True
                )

                if reraise:
                    raise

                return None

        return wrapper

    return decorator


# === UTILITAIRES DE MONITORING ===

class LogMetrics:
    """
    Collecteur de métriques de logging pour monitoring

    Collecte des statistiques sur les logs pour surveiller
    la santé de l'application et détecter les anomalies.
    """

    def __init__(self):
        self.metrics = {
            "total_logs": 0,
            "logs_by_level": {level: 0 for level in LOG_LEVELS.keys()},
            "logs_by_module": {},
            "errors_count": 0,
            "warnings_count": 0,
            "last_error": None,
            "start_time": time.time()
        }
        self.lock = threading.Lock()

    def record_log(self, record: logging.LogRecord):
        """Enregistre une entrée de log dans les métriques"""
        with self.lock:
            self.metrics["total_logs"] += 1

            # Par niveau
            level_name = record.levelname
            if level_name in self.metrics["logs_by_level"]:
                self.metrics["logs_by_level"][level_name] += 1

            # Par module
            module = record.name
            self.metrics["logs_by_module"][module] = self.metrics["logs_by_module"].get(module, 0) + 1

            # Erreurs et warnings
            if record.levelno >= logging.ERROR:
                self.metrics["errors_count"] += 1
                self.metrics["last_error"] = {
                    "message": record.getMessage(),
                    "timestamp": record.created,
                    "module": record.name
                }
            elif record.levelno >= logging.WARNING:
                self.metrics["warnings_count"] += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques actuelles"""
        with self.lock:
            metrics = self.metrics.copy()
            metrics["uptime"] = time.time() - self.metrics["start_time"]

            # Calculer les taux
            if metrics["uptime"] > 0:
                metrics["logs_per_second"] = metrics["total_logs"] / metrics["uptime"]
                metrics["error_rate"] = metrics["errors_count"] / metrics["total_logs"] if metrics[
                                                                                               "total_logs"] > 0 else 0

            return metrics

    def reset_metrics(self):
        """Remet à zéro les métriques"""
        with self.lock:
            self.metrics = {
                "total_logs": 0,
                "logs_by_level": {level: 0 for level in LOG_LEVELS.keys()},
                "logs_by_module": {},
                "errors_count": 0,
                "warnings_count": 0,
                "last_error": None,
                "start_time": time.time()
            }


class MetricsHandler(logging.Handler):
    """Handler qui collecte les métriques de logging"""

    def __init__(self, metrics_collector: LogMetrics):
        super().__init__()
        self.metrics = metrics_collector

    def emit(self, record):
        self.metrics.record_log(record)


class AlertHandler(logging.Handler):
    """
    Handler qui déclenche des alertes basées sur les logs

    Peut envoyer des notifications en cas d'erreurs critiques
    ou de patterns suspects dans les logs.
    """

    def __init__(self, alert_config=None):
        super().__init__()
        self.alert_config = alert_config or {
            "error_threshold": 10,  # Nombre d'erreurs avant alerte
            "time_window": 300,  # Fenêtre de temps en secondes
            "alert_cooldown": 600  # Cooldown entre alertes
        }

        self.error_count = 0
        self.error_timestamps = []
        self.last_alert = 0
        self.lock = threading.Lock()

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            with self.lock:
                current_time = time.time()

                # Nettoyer les anciens timestamps
                self.error_timestamps = [
                    ts for ts in self.error_timestamps
                    if current_time - ts < self.alert_config["time_window"]
                ]

                # Ajouter le nouveau
                self.error_timestamps.append(current_time)

                # Vérifier si on doit déclencher une alerte
                if (len(self.error_timestamps) >= self.alert_config["error_threshold"] and
                        current_time - self.last_alert > self.alert_config["alert_cooldown"]):
                    self._send_alert(record, len(self.error_timestamps))
                    self.last_alert = current_time

    def _send_alert(self, record, error_count):
        """Envoie une alerte (à personnaliser selon les besoins)"""
        alert_message = f"ALERT: {error_count} erreurs détectées en {self.alert_config['time_window']}s"
        alert_message += f"\nDernière erreur: {record.getMessage()}"
        alert_message += f"\nModule: {record.name}"

        # Ici on pourrait envoyer un email, webhook, notification Slack, etc.
        print(f"\n🚨 {alert_message}\n", file=sys.stderr)


# === CONFIGURATION AVANCÉE ===

def setup_advanced_logging(
        service_name: str = "vulnerability_agent",
        log_level: str = "INFO",
        enable_json: bool = False,
        enable_metrics: bool = True,
        enable_alerts: bool = True,
        log_directory: str = "logs"
):
    """
    Configure un système de logging avancé avec toutes les fonctionnalités

    Args:
        service_name: Nom du service
        log_level: Niveau de log global
        enable_json: Activer le format JSON
        enable_metrics: Activer la collecte de métriques
        enable_alerts: Activer le système d'alertes
        log_directory: Répertoire des logs

    Returns:
        Dict contenant les objets de logging configurés
    """
    # Créer le répertoire de logs
    log_path = Path(log_directory)
    log_path.mkdir(exist_ok=True)

    # Configuration du logger principal
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVELS.get(log_level.upper(), logging.INFO))

    # Nettoyer les handlers existants
    root_logger.handlers.clear()

    handlers = []

    # Handler console
    console_handler = logging.StreamHandler(sys.stdout)
    if enable_json:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ColoredFormatter())
    console_handler.setLevel(logging.INFO)

    # Filtre de sécurité
    security_filter = SensitiveDataFilter()
    console_handler.addFilter(security_filter)
    handlers.append(console_handler)

    # Handler fichier principal
    main_log_file = log_path / f"{service_name}.log"
    file_handler = logging.handlers.RotatingFileHandler(
        main_log_file,
        maxBytes=20971520,  # 20MB
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(DETAILED_LOG_FORMAT) if not enable_json else JSONFormatter())
    file_handler.setLevel(logging.DEBUG)
    file_handler.addFilter(security_filter)
    handlers.append(file_handler)

    # Handler erreurs séparé
    error_log_file = log_path / f"{service_name}_errors.log"
    error_handler = logging.handlers.RotatingFileHandler(
        error_log_file,
        maxBytes=10485760,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setFormatter(logging.Formatter(DETAILED_LOG_FORMAT) if not enable_json else JSONFormatter())
    error_handler.setLevel(logging.ERROR)
    handlers.append(error_handler)

    # Collecteur de métriques
    metrics_collector = None
    if enable_metrics:
        metrics_collector = LogMetrics()
        metrics_handler = MetricsHandler(metrics_collector)
        handlers.append(metrics_handler)

    # Système d'alertes
    alert_handler = None
    if enable_alerts:
        alert_handler = AlertHandler()
        handlers.append(alert_handler)

    # Ajouter tous les handlers
    for handler in handlers:
        root_logger.addHandler(handler)

    # Configurer les loggers spécialisés
    specialized_loggers = {}

    modules = ['collector', 'analyzer', 'generator', 'supervisor', 'api']
    for module in modules:
        module_logger = logging.getLogger(f"src.core.{module}")
        module_logger.setLevel(logging.DEBUG)

        # Handler spécialisé pour chaque module
        module_log_file = log_path / f"{service_name}_{module}.log"
        module_handler = logging.handlers.RotatingFileHandler(
            module_log_file,
            maxBytes=10485760,
            backupCount=3,
            encoding='utf-8'
        )
        module_handler.setFormatter(logging.Formatter(DETAILED_LOG_FORMAT) if not enable_json else JSONFormatter())
        module_handler.setLevel(logging.DEBUG)
        module_handler.addFilter(security_filter)

        module_logger.addHandler(module_handler)
        specialized_loggers[module] = module_logger

    return {
        "root_logger": root_logger,
        "specialized_loggers": specialized_loggers,
        "metrics_collector": metrics_collector,
        "alert_handler": alert_handler,
        "handlers": handlers
    }


def configure_distributed_logging(
        service_name: str,
        node_id: str,
        central_log_server: Optional[str] = None,
        enable_syslog: bool = False
):
    """
    Configure le logging pour un environnement distribué

    Args:
        service_name: Nom du service
        node_id: Identifiant unique du nœud
        central_log_server: URL du serveur de logs central
        enable_syslog: Activer l'envoi vers syslog
    """
    logger = get_logger(__name__)

    # Contexte global pour tous les logs
    global_context = {
        "service": service_name,
        "node_id": node_id,
        "hostname": os.uname().nodename if hasattr(os, 'uname') else 'unknown'
    }

    # Handler pour serveur central (exemple avec HTTP)
    if central_log_server:
        try:
            import logging.handlers

            # Handler HTTP pour envoi vers serveur central
            http_handler = logging.handlers.HTTPHandler(
                central_log_server.replace('http://', '').replace('https://', ''),
                '/api/logs',
                method='POST'
            )

            # Formateur JSON avec contexte
            class DistributedJSONFormatter(JSONFormatter):
                def format(self, record):
                    log_entry = json.loads(super().format(record))
                    log_entry.update(global_context)
                    return json.dumps(log_entry, ensure_ascii=False, default=str)

            http_handler.setFormatter(DistributedJSONFormatter())
            http_handler.setLevel(logging.INFO)

            # Ajouter aux loggers principaux
            root_logger = logging.getLogger()
            root_logger.addHandler(http_handler)

            logger.info(f"Logging distribué configuré vers {central_log_server}")

        except Exception as e:
            logger.warning(f"Impossible de configurer le logging distribué: {e}")

    # Handler Syslog
    if enable_syslog:
        try:
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_formatter = logging.Formatter(
                f"{service_name}[%(process)d]: %(name)s - %(levelname)s - %(message)s"
            )
            syslog_handler.setFormatter(syslog_formatter)
            syslog_handler.setLevel(logging.INFO)

            root_logger = logging.getLogger()
            root_logger.addHandler(syslog_handler)

            logger.info("Handler Syslog configuré")

        except Exception as e:
            logger.warning(f"Impossible de configurer Syslog: {e}")


# === CLASSE DE BENCHMARK ===

class LoggingBenchmark:
    """
    Utilitaire pour benchmarker les performances du système de logging
    """

    @staticmethod
    def benchmark_formatters(num_records: int = 10000):
        """Benchmark des différents formatters"""
        import time

        # Créer un record de test
        logger = logging.getLogger("benchmark")
        record = logger.makeRecord(
            "test.module", logging.INFO, "test.py", 42, "Test message %s", ("arg",), None
        )

        formatters = {
            "Standard": logging.Formatter(DEFAULT_LOG_FORMAT),
            "Detailed": logging.Formatter(DETAILED_LOG_FORMAT),
            "JSON": JSONFormatter(),
            "Colored": ColoredFormatter()
        }

        results = {}

        for name, formatter in formatters.items():
            start_time = time.time()

            for _ in range(num_records):
                formatter.format(record)

            duration = time.time() - start_time
            results[name] = {
                "duration": duration,
                "records_per_second": num_records / duration
            }

        return results

    @staticmethod
    def benchmark_handlers(num_records: int = 1000):
        """Benchmark des différents handlers"""
        import tempfile
        import time

        # Handler console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))

        # Handler fichier
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            file_handler = logging.FileHandler(temp_file.name)
            file_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))

        # Handler rotatif
        with tempfile.NamedTemporaryFile(delete=False) as temp_file2:
            rotating_handler = logging.handlers.RotatingFileHandler(
                temp_file2.name, maxBytes=1024 * 1024, backupCount=3
            )
            rotating_handler.setFormatter(logging.Formatter(DEFAULT_LOG_FORMAT))

        handlers = {
            "Console": console_handler,
            "File": file_handler,
            "Rotating": rotating_handler
        }

        results = {}
        logger = logging.getLogger("benchmark")

        for name, handler in handlers.items():
            # Nettoyer les handlers précédents
            logger.handlers.clear()
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)

            start_time = time.time()

            for i in range(num_records):
                logger.info(f"Test message {i}")

            duration = time.time() - start_time
            results[name] = {
                "duration": duration,
                "records_per_second": num_records / duration
            }

        # Nettoyer
        logger.handlers.clear()

        return results


# === INITIALISATION GLOBALE ===

# Instance globale du collecteur de métriques
_global_metrics = LogMetrics()


def get_logging_metrics() -> LogMetrics:
    """Retourne l'instance globale des métriques de logging"""
    return _global_metrics


# === EXEMPLES ET TESTS ===

def demo_logging_features():
    """Démontre les fonctionnalités du système de logging"""
    print("=== Démonstration du système de logging ===\n")

    # Logger basique
    logger = setup_logger("demo.basic")
    logger.info("Message d'information basique")
    logger.warning("Message d'avertissement")
    logger.error("Message d'erreur")
    logger.success("Opération réussie!")
    logger.trace("Message de trace détaillé")

    # Logger contextuel
    ctx_logger = create_contextual_logger("demo.contextual", {"user_id": "admin", "session": "abc123"})
    ctx_logger.info("Message avec contexte automatique")

    # Logger structuré
    struct_logger = create_structured_logger("demo.structured")
    struct_logger.log_scan_start("scan_001", "192.168.1.100", "full")
    struct_logger.log_vulnerability_found("scan_001", "CVE-2024-1234", "HIGH", 8.5)
    struct_logger.log_scan_complete("scan_001", 120.5, 5)

    # Utilisation du décorateur
    @log_function_call(logger, include_args=True, include_result=True)
    def example_function(x, y):
        return x + y

    result = example_function(5, 3)

    # Logger avec gestion du temps
    with log_execution_time(logger, "operation_example"):
        time.sleep(0.1)  # Simulation d'une opération

    # Affichage des métriques
    metrics = _global_metrics.get_metrics()
    print(f"\nMétriques de logging:")
    print(f"- Total de logs: {metrics['total_logs']}")
    print(f"- Erreurs: {metrics['errors_count']}")
    print(f"- Warnings: {metrics['warnings_count']}")

    print("\n=== Démonstration terminée ===")


if __name__ == "__main__":
    # Tests et démonstration
    demo_logging_features()

    # Benchmark des performances
    print("\n=== Benchmark des formatters ===")
    formatter_results = LoggingBenchmark.benchmark_formatters(1000)
    for name, result in formatter_results.items():
        print(f"{name}: {result['records_per_second']:.0f} records/sec")

    print("\n=== Benchmark des handlers ===")
    handler_results = LoggingBenchmark.benchmark_handlers(100)
    for name, result in handler_results.items():
        print(f"{name}: {result['records_per_second']:.0f} records/sec")