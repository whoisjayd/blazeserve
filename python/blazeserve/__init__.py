"""BlazeServe: a fast HTTP file server for large static transfers.

Every command of the ``blaze`` program is available here without a second list to maintain.
``blazeserve.get(url, connections=8)`` runs ``blaze get --connections 8 URL``, and
``blazeserve.Server(path, max_upload_mb=100)`` takes any option of ``blaze serve``. The
options are checked against the program's own definition, so a new option or command works from
Python as soon as the program has it.
"""

import contextlib
import json
import os
import sys
from collections.abc import Callable, Iterator, Sequence
from typing import TYPE_CHECKING, Any

from ._native import (
    BlazeError,
    Server,
    __version__,
    command_line,
    commands as _commands,
    main as _main,
    run as _run,
    sha256,
    upgrade as _upgrade,
)

__all__ = [
    "BlazeError",
    "Server",
    "__version__",
    "command_line",
    "commands",
    "main",
    "run",
    "sha256",
    "upgrade",
]


@contextlib.contextmanager
def _interpreter() -> Iterator[None]:
    """Tell the native code which Python it runs in.

    ``upgrade`` uses it to run that interpreter's pip, and ``--background`` uses it to start
    the worker as ``python -m blazeserve``.
    """
    previous = os.environ.get("BLAZE_PYTHON")
    if sys.executable:
        os.environ["BLAZE_PYTHON"] = sys.executable
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("BLAZE_PYTHON", None)
        else:
            os.environ["BLAZE_PYTHON"] = previous


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``blaze`` command line and return its exit status.

    Ctrl+C raises ``KeyboardInterrupt`` and asks the command to stop cleanly: a download keeps
    its resume data and a server finishes what it is sending.
    """
    with _interpreter():
        return _main(list(sys.argv[1:] if argv is None else argv))


def run(command: str, *positional: Any, **options: Any) -> int:
    """Run one command and return its exit status.

    ``run("get", url, connections=8, extract=True)`` is ``blaze get --connections 8 --extract
    URL``. Options are keywords written with underscores. ``True`` and ``False`` are switches,
    a list repeats the option, ``None`` leaves it out, and paths and numbers are converted. An
    option the command does not have raises ``TypeError`` listing the ones it does.
    """
    with _interpreter():
        return _run(command, *positional, **options)


def commands() -> dict[str, str]:
    """The commands of ``blaze`` and what each one does."""
    return dict(_commands())


def upgrade(
    check: bool = True, *, version: str | None = None, yes: bool = False
) -> dict[str, Any]:
    """Check for a newer release, or install it with ``yes=True``.

    Returns the same fields as ``blaze upgrade --check --json`` plus ``status`` and
    ``message``. An upgrade never asks for confirmation here, so it needs ``yes=True``.
    """
    with _interpreter():
        return json.loads(_upgrade(check, version, yes))


def _wrapper(name: str, about: str) -> Callable[..., int]:
    def command(*positional: Any, **options: Any) -> int:
        return run(name, *positional, **options)

    command.__name__ = command.__qualname__ = name
    command.__doc__ = (
        f"{about}.\n\nRuns ``blaze {name}``. Positional values come first, options are "
        "keywords written with underscores, and the exit status is returned. See "
        "``blazeserve.run`` for how options are written."
    )
    return command


_wrappers: dict[str, Callable[..., int]] = {}


def __getattr__(name: str) -> Callable[..., int]:
    """``blazeserve.get``, ``blazeserve.put`` and so on, one for each command."""
    if not name.startswith("_"):
        if name not in _wrappers:
            about = dict(_commands()).get(name)
            if about is not None:
                _wrappers[name] = _wrapper(name, about)
        if name in _wrappers:
            return _wrappers[name]
    raise AttributeError(f"module 'blazeserve' has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({*globals(), *(name for name, _ in _commands())})


def _console_script() -> None:
    raise SystemExit(main())


if TYPE_CHECKING:
    # Written out so editors and type checkers know the commands. A test fails when a command
    # is added to the program without a line here.
    def serve(*positional: Any, **options: Any) -> int: ...
    def send(*positional: Any, **options: Any) -> int: ...
    def checksum(*positional: Any, **options: Any) -> int: ...
    def verify(*positional: Any, **options: Any) -> int: ...
    def version(*positional: Any, **options: Any) -> int: ...
    def doctor(*positional: Any, **options: Any) -> int: ...
    def benchmark(*positional: Any, **options: Any) -> int: ...
    def get(*positional: Any, **options: Any) -> int: ...
    def info(*positional: Any, **options: Any) -> int: ...
    def put(*positional: Any, **options: Any) -> int: ...
    def status(*positional: Any, **options: Any) -> int: ...
    def stop(*positional: Any, **options: Any) -> int: ...
    def attach(*positional: Any, **options: Any) -> int: ...
    def telemetry(*positional: Any, **options: Any) -> int: ...
    def bug(*positional: Any, **options: Any) -> int: ...
    def completions(*positional: Any, **options: Any) -> int: ...
    def man(*positional: Any, **options: Any) -> int: ...
