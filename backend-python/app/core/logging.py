"""
Structured logging configuration.

The application logs as JSON in production (so log shippers such as Loki,
Fluent Bit or CloudWatch can parse it) and as coloured, human readable lines in
development. A single module level `logger` is shared across the codebase.
"""

import json
import logging
import logging.config
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.config import settings

# Attributes present on every LogRecord; anything else was attached by the
# caller via `logger.info(..., extra={...})` and belongs in the JSON payload.
_RESERVED_RECORD_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}

# Keys whose values are never written to the logs, wherever they appear.
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "session_token",
    "secret_key",
    "extension_secret",
    "anonymization_salt",
    "private_key",
}

_REDACTED = "***redacted***"


def _redact(value: Any, _depth: int = 0) -> Any:
    """Recursively strip sensitive values out of structured log payloads."""
    if _depth > 6:
        return "***max-depth***"

    if isinstance(value, dict):
        return {
            k: (
                _REDACTED if str(k).lower() in _SENSITIVE_KEYS else _redact(v, _depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_redact(v, _depth + 1) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """Render log records as single-line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": settings.APP_NAME,
            "version": settings.VERSION,
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        if record.levelno >= logging.WARNING:
            payload["source"] = f"{record.pathname}:{record.lineno}"

        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _RESERVED_RECORD_ATTRS and not key.startswith("_")
        }
        if extras:
            payload["context"] = _redact(extras)

        return json.dumps(payload, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Compact, colourised formatter for local development."""

    _COLOURS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;41m",
    }
    _RESET = "\033[0m"

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
            datefmt="%H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        if sys.stderr.isatty():
            colour = self._COLOURS.get(record.levelname, "")
            if colour:
                return f"{colour}{formatted}{self._RESET}"
        return formatted


def setup_logging(level: Optional[str] = None, force_json: Optional[bool] = None) -> None:
    """Configure the root logger.

    Args:
        level: Log level name. Defaults to ``settings.LOG_LEVEL``.
        force_json: Force JSON output on/off. Defaults to JSON whenever the
            application is not running in debug mode.
    """
    log_level = (level or settings.LOG_LEVEL).upper()
    use_json = (not settings.DEBUG) if force_json is None else force_json

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if use_json else ConsoleFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)

    # Third-party loggers are noisy at DEBUG; keep them one notch quieter.
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "asyncio", "urllib3", "httpx"):
        logging.getLogger(noisy).setLevel(
            max(logging.getLevelName(log_level), logging.WARNING)
            if noisy == "sqlalchemy.engine"
            else logging.INFO
        )

    logging.getLogger("uvicorn.error").propagate = True

    # With `echo=True` SQLAlchemy installs its own handler; letting the record
    # propagate as well prints every statement twice.
    logging.getLogger("sqlalchemy.engine").propagate = False


def get_logger(name: str = "infosec") -> logging.Logger:
    """Return a named logger sharing the application's handlers."""
    return logging.getLogger(name)


# Configure on import so modules imported before `setup_logging()` still log.
setup_logging()

# Shared application logger.
logger = get_logger("infosec")
