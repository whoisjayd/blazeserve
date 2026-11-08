"""BlazeServe: a fast HTTP file server for large static transfers."""

import sys
from collections.abc import Sequence

from ._native import BlazeError, Server, __version__, main as _main, sha256

__all__ = ["BlazeError", "Server", "__version__", "main", "sha256"]


def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``blaze`` command line and return its exit status."""
    return _main(list(sys.argv[1:] if argv is None else argv))


def _console_script() -> None:
    raise SystemExit(main())
