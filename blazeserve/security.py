"""Security headers, path traversal protection, and CORS policies."""

from __future__ import annotations

import os
import uuid


def is_safe_path(base_dir: str, target_path: str) -> bool:
    """Ensure target path is strictly contained within base directory.

    Guards against directory traversal attacks like ../../etc/passwd.
    """
    abs_base = os.path.abspath(base_dir)
    abs_target = os.path.abspath(target_path)
    return abs_target == abs_base or abs_target.startswith(abs_base + os.sep)


def generate_request_id(incoming: str | None = None) -> str:
    """Generate or sanitize correlation request ID.

    If an incoming valid alphanumeric ID is provided, preserve it for
    distributed tracing. Otherwise, generate a fresh 12-char hex UUID.
    """
    if incoming and 1 <= len(incoming) <= 64 and incoming.replace("-", "").isalnum():
        return incoming
    return uuid.uuid4().hex[:12]
