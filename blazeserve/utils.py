import base64
import hashlib
import time
from typing import Optional, Tuple


def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"]
    x = float(n)
    for u in units:
        if x < 1024.0:
            return f"{x:.2f}{u}"
        x /= 1024.0
    return f"{x:.2f}ZB"


def sha256_file(path: str, bufsize: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def parse_basic_auth(header: Optional[str]) -> Optional[Tuple[str, str]]:
    if not header or not header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip()).decode("utf-8")
        if ":" not in raw:
            return None
        u, p = raw.split(":", 1)
        return u, p
    except Exception:
        return None


class TokenBucket:
    def __init__(self, rate_bps: float):
        self.capacity = max(rate_bps, 1.0)
        self.tokens = self.capacity
        self.rate = self.capacity
        self.timestamp = time.perf_counter()

    def consume(self, n: int) -> float:
        now = time.perf_counter()
        delta = now - self.timestamp
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        need = float(n)
        if self.tokens >= need:
            self.tokens -= need
            return 0.0
        short = need - self.tokens
        self.tokens = 0.0
        return short / self.rate
