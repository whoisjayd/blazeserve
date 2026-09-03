"""Logging infrastructure with Rich and structured JSON formatters."""

from __future__ import annotations

import json
import logging
import sys
import time

from rich.console import Console
from rich.logging import RichHandler

_console: Console | None = None


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter for production log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(level: str = "WARNING", json_logs: bool = False) -> None:
    """Configure root logger with either Rich terminal or structured JSON handler."""
    global _console
    log_level = getattr(logging, level.upper(), logging.WARNING)

    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers.clear()

    if json_logs:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        root.addHandler(handler)
    else:
        _console = _console or Console()
        root.addHandler(RichHandler(console=_console, markup=True, rich_tracebacks=True))


def get_console() -> Console:
    """Obtain or initialize global Rich console instance."""
    global _console
    if _console is None:
        _console = Console()
    return _console
