"""Rate limiting primitives and per-IP client token buckets."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict


class TokenBucket:
    """Thread-safe token bucket with 2-second burst capacity."""

    def __init__(self, rate_bps: float | None) -> None:
        self._lock = threading.Lock()
        self.rate: float = self._normalize_rate(rate_bps)
        self.capacity: float = max(1.0, self.rate * 2.0) if self.rate > 0 else 0.0
        self.tokens: float = self.capacity
        self.last: float = time.perf_counter()

    @staticmethod
    def _normalize_rate(rate_bps: float | None) -> float:
        return float(rate_bps) if rate_bps and rate_bps > 0 else 0.0

    def _refill_locked(self, now: float) -> None:
        elapsed = max(0.0, now - self.last)
        self.last = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    def update_rate(self, rate_bps: float | None) -> None:
        """Update throughput while preserving already accrued tokens."""
        new_rate = self._normalize_rate(rate_bps)
        with self._lock:
            if new_rate == self.rate:
                return
            self._refill_locked(time.perf_counter())
            was_unlimited = self.rate <= 0
            self.rate = new_rate
            self.capacity = max(1.0, new_rate * 2.0) if new_rate > 0 else 0.0
            if new_rate <= 0:
                self.tokens = 0.0
            elif was_unlimited:
                self.tokens = self.capacity
            else:
                self.tokens = min(self.tokens, self.capacity)

    def consume(self, n: int) -> float:
        """Reserve tokens and return the wait required for any deficit."""
        if n <= 0:
            return 0.0
        with self._lock:
            if self.rate <= 0:
                return 0.0
            self._refill_locked(time.perf_counter())
            need = float(n)
            if self.tokens >= need:
                self.tokens -= need
                return 0.0
            short = need - self.tokens
            self.tokens = 0.0
            return short / self.rate

    def take(self, n: int) -> int:
        """Return currently permitted bytes after at most one short sleep."""
        if n <= 0:
            return 0

        with self._lock:
            if self.rate <= 0:
                return n
            self._refill_locked(time.perf_counter())
            allowed = min(n, int(self.tokens))
            if allowed > 0:
                self.tokens -= allowed
                return allowed
            wait_for = (1.0 - self.tokens) / self.rate

        if wait_for > 0:
            time.sleep(min(wait_for, 0.05))

        with self._lock:
            if self.rate <= 0:
                return n
            self._refill_locked(time.perf_counter())
            allowed = min(n, int(self.tokens))
            if allowed > 0:
                self.tokens -= allowed
            return allowed


class IPRateLimiterPool:
    """Thread-safe bounded least-recently-used client limiter registry."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._lock = threading.Lock()
        self._limiters: OrderedDict[str, TokenBucket] = OrderedDict()
        self._max: int = max(0, int(max_entries))

    def get_limiter(self, ip: str, rate_bps: float | None) -> TokenBucket:
        """Fetch or create a rate limiter for a client IP address."""
        with self._lock:
            limiter = self._limiters.get(ip)
            if limiter is not None:
                limiter.update_rate(rate_bps)
                self._limiters.move_to_end(ip)
                return limiter

            limiter = TokenBucket(rate_bps)
            if self._max == 0:
                return limiter
            if len(self._limiters) >= self._max:
                self._limiters.popitem(last=False)
            self._limiters[ip] = limiter
            return limiter
