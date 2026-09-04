"""Security headers, path traversal protection, and CORS policies."""

from __future__ import annotations

import os
import uuid
from typing import BinaryIO


class UnsafePathError(ValueError):
    """Raised when a filesystem operation would escape its configured root."""


def is_safe_path(base_dir: str, target_path: str) -> bool:
    """Return whether *target_path* resolves inside *base_dir*.

    ``realpath`` is required here: lexical ``abspath`` checks allow a symlink
    below the served root to redirect reads or writes outside that root.
    """
    real_base = os.path.realpath(base_dir)
    real_target = os.path.realpath(target_path)
    try:
        return os.path.commonpath((real_base, real_target)) == real_base
    except ValueError:
        return False


def create_upload_file(base_dir: str, target_path: str) -> BinaryIO:
    """Create a new upload destination without following a final symlink.

    Parent directories are created first and then resolved again so existing
    symlinked parents fail closed. ``O_EXCL`` prevents overwrite races and
    ``O_NOFOLLOW`` protects the final component where the platform supports it.
    """
    real_base = os.path.realpath(base_dir)
    absolute_target = os.path.abspath(target_path)
    if not is_safe_path(real_base, absolute_target):
        raise UnsafePathError("upload path escapes the configured root")

    parent = os.path.dirname(absolute_target)
    os.makedirs(parent, exist_ok=True)
    if not is_safe_path(real_base, parent):
        raise UnsafePathError("upload parent escapes the configured root")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute_target, flags, 0o600)
    except OSError as exc:
        if not is_safe_path(real_base, parent):
            raise UnsafePathError("upload parent changed during creation") from exc
        raise
    return os.fdopen(fd, "wb", buffering=0)


def generate_request_id(incoming: str | None = None) -> str:
    """Generate or sanitize correlation request ID.

    If an incoming valid alphanumeric ID is provided, preserve it for
    distributed tracing. Otherwise, generate a fresh 12-char hex UUID.
    """
    if incoming and 1 <= len(incoming) <= 64 and incoming.replace("-", "").isalnum():
        return incoming
    return uuid.uuid4().hex[:12]
