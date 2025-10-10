import logging
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler

_console: Optional[Console] = None


def setup_logging(level: str = "WARNING") -> None:
    global _console
    _console = _console or Console()
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=_console, markup=True, rich_tracebacks=True)],
    )


def get_console() -> Console:
    global _console
    if _console is None:
        _console = Console()
    return _console
