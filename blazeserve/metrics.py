"""Thread-safe telemetry and Prometheus OpenMetrics exporter."""

from __future__ import annotations

import threading
import time
from typing import Any


class ServerMetrics:
    """Thread-safe metrics tracking for server performance."""

    def __init__(self) -> None:
        self.start_time: float = time.time()
        self._lock = threading.Lock()
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._requests_total: int = 0
        self._requests_active: int = 0
        self._errors_total: int = 0

    @property
    def bytes_sent(self) -> int:
        with self._lock:
            return self._bytes_sent

    @bytes_sent.setter
    def bytes_sent(self, value: int) -> None:
        with self._lock:
            self._bytes_sent = value

    @property
    def bytes_received(self) -> int:
        with self._lock:
            return self._bytes_received

    @bytes_received.setter
    def bytes_received(self, value: int) -> None:
        with self._lock:
            self._bytes_received = value

    @property
    def requests_total(self) -> int:
        with self._lock:
            return self._requests_total

    @requests_total.setter
    def requests_total(self, value: int) -> None:
        with self._lock:
            self._requests_total = value

    @property
    def requests_active(self) -> int:
        with self._lock:
            return self._requests_active

    @requests_active.setter
    def requests_active(self, value: int) -> None:
        with self._lock:
            self._requests_active = value

    @property
    def errors_total(self) -> int:
        with self._lock:
            return self._errors_total

    @errors_total.setter
    def errors_total(self, value: int) -> None:
        with self._lock:
            self._errors_total = value

    def increment_bytes_sent(self, amount: int) -> None:
        """Atomically increment the number of bytes sent."""
        with self._lock:
            self._bytes_sent += amount

    def increment_bytes_received(self, amount: int) -> None:
        """Atomically increment the number of bytes received."""
        with self._lock:
            self._bytes_received += amount

    def increment_requests_total(self) -> None:
        """Atomically increment the total number of requests."""
        with self._lock:
            self._requests_total += 1

    def increment_requests_active(self) -> None:
        """Atomically increment the number of active requests."""
        with self._lock:
            self._requests_active += 1

    def decrement_requests_active(self) -> None:
        """Atomically decrement the number of active requests."""
        with self._lock:
            self._requests_active = max(0, self._requests_active - 1)

    def increment_errors_total(self) -> None:
        """Atomically increment the total number of errors."""
        with self._lock:
            self._errors_total += 1

    def get_stats(self) -> dict[str, Any]:
        """Get current server statistics in a thread-safe manner."""
        uptime = time.time() - self.start_time
        with self._lock:
            return {
                "uptime_seconds": int(uptime),
                "bytes_sent": self._bytes_sent,
                "bytes_received": self._bytes_received,
                "requests_total": self._requests_total,
                "requests_active": self._requests_active,
                "errors_total": self._errors_total,
                "bytes_per_second": (int(self._bytes_sent / uptime) if uptime > 0 else 0),
            }

    def to_prometheus(self) -> str:
        """Render metrics in Prometheus OpenMetrics text format."""
        uptime = time.time() - self.start_time
        with self._lock:
            lines = [
                "# HELP blazeserve_uptime_seconds Total server uptime in seconds",
                "# TYPE blazeserve_uptime_seconds gauge",
                f"blazeserve_uptime_seconds {int(uptime)}",
                "# HELP blazeserve_bytes_sent_total Total bytes sent to clients",
                "# TYPE blazeserve_bytes_sent_total counter",
                f"blazeserve_bytes_sent_total {self._bytes_sent}",
                "# HELP blazeserve_bytes_received_total Total bytes received via uploads",
                "# TYPE blazeserve_bytes_received_total counter",
                f"blazeserve_bytes_received_total {self._bytes_received}",
                "# HELP blazeserve_requests_total Total HTTP requests handled",
                "# TYPE blazeserve_requests_total counter",
                f"blazeserve_requests_total {self._requests_total}",
                "# HELP blazeserve_requests_active Current active in-flight HTTP requests",
                "# TYPE blazeserve_requests_active gauge",
                f"blazeserve_requests_active {self._requests_active}",
                "# HELP blazeserve_errors_total Total server errors encountered",
                "# TYPE blazeserve_errors_total counter",
                f"blazeserve_errors_total {self._errors_total}",
            ]
        return "\n".join(lines) + "\n"
