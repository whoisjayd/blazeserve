"""Common utility functions for hashing, size formatting, and auth parsing."""

from __future__ import annotations

import base64
import binascii
import hashlib

from blazeserve.limiter import TokenBucket


def human_size(n: int) -> str:
    """Format byte count into human-readable unit string."""
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    x = float(n)
    for u in units:
        if x < 1024.0:
            return f"{x:.2f}{u}"
        x /= 1024.0
    return f"{x:.2f}ZB"


def sha256_file(path: str, bufsize: int = 8 * 1024 * 1024) -> str:
    """Compute SHA-256 hex digest of file in chunked buffer reads."""
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    """Extract username and password from HTTP Basic Authorization header."""
    if not header or not header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        if ":" not in raw:
            return None
        u, p = raw.split(":", 1)
        return u, p
    except (binascii.Error, UnicodeDecodeError):
        return None


__all__ = ["TokenBucket", "human_size", "parse_basic_auth", "sha256_file"]
