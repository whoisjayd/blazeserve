"""Rate limiting primitives and per-IP client token buckets."""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Token bucket rate limiter with 2-second burst capacity and smooth replenishment."""

    def __init__(self, rate_bps: float | None) -> None:
        self.rate: float = float(rate_bps) if rate_bps and rate_bps > 0 else 0.0
        self.capacity: float = self.rate * 2.0 if self.rate > 0 else 0.0  # 2-second burst capacity
        self.tokens: float = self.capacity
        self.last: float = time.perf_counter()

    def consume(self, n: int) -> float:
        """Consume n tokens. Return seconds to sleep if not enough tokens."""
        if self.rate <= 0:
            return 0.0
        now = time.perf_counter()
        delta = now - self.last
        self.last = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        need = float(n)
        if self.tokens >= need:
            self.tokens -= need
            return 0.0
        short = need - self.tokens
        self.tokens = 0.0
        return short / self.rate

    def take(self, n: int) -> int:
        """Return how many bytes can be sent right now, sleeping if necessary."""
        if self.rate <= 0:
            return n

        now = time.perf_counter()
        elapsed = now - self.last
        self.last = now

        # Refill tokens based on elapsed time
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens < 1:
            wait_for = (1 - self.tokens) / self.rate
            if wait_for > 0:
                time.sleep(min(wait_for, 0.05))
            self.tokens = 1.0

        allowed = min(float(n), self.tokens)
        send = max(1, int(allowed))
        self.tokens -= send
        return send


class IPRateLimiterPool:
    """Thread-safe per-client-IP rate limiter registry with LRU-style eviction."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._lock = threading.Lock()
        self._limiters: dict[str, TokenBucket] = {}
        self._max: int = max_entries

    def get_limiter(self, ip: str, rate_bps: float) -> TokenBucket:
        """Fetch or create a rate limiter for client IP address."""
        with self._lock:
            if ip not in self._limiters:
                if len(self._limiters) >= self._max:
                    self._limiters.pop(next(iter(self._limiters)))
                self._limiters[ip] = TokenBucket(rate_bps)
            return self._limiters[ip]
