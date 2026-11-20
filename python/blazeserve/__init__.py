"""BlazeServe: a fast HTTP file server for large static transfers."""

import contextlib
import json
import os
import sys
from collections.abc import Iterator, Sequence
from typing import Any

from ._native import (
    BlazeError,
    Server,
    __version__,
    main as _main,
    sha256,
    upgrade as _upgrade,
)

__all__ = ["BlazeError", "Server", "__version__", "main", "sha256", "upgrade"]


@contextlib.contextmanager
def _interpreter() -> Iterator[None]:
    """Tell the native code which Python it runs in, so `upgrade` can use that pip."""
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
    """Run the ``blaze`` command line and return its exit status."""
    with _interpreter():
        return _main(list(sys.argv[1:] if argv is None else argv))


def upgrade(
    check: bool = True, *, version: str | None = None, yes: bool = False
) -> dict[str, Any]:
    """Check for a newer release, or install it with ``yes=True``.

    Returns the same fields as ``blaze upgrade --check --json`` plus ``status`` and
    ``message``. An upgrade never asks for confirmation here, so it needs ``yes=True``.
    """
    with _interpreter():
        return json.loads(_upgrade(check, version, yes))


def _console_script() -> None:
    raise SystemExit(main())
