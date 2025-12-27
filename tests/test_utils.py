"""
Test suite for BlazeServe utility functions and classes.
"""

import threading
import time

from blazeserve.server import ServerMetrics, _RateLimiter
from blazeserve.utils import human_size, sha256_file


class TestHumanSize:
    """Test human-readable size formatting."""

    def test_bytes(self):
        """Test formatting of byte values."""
        assert human_size(100) == "100.00B"
        assert human_size(1023) == "1023.00B"

    def test_kilobytes(self):
        """Test formatting of KB values."""
        assert human_size(1024) == "1.00KB"
        assert human_size(2048) == "2.00KB"
        assert human_size(1536) == "1.50KB"

    def test_megabytes(self):
        """Test formatting of MB values."""
        assert human_size(1024 * 1024) == "1.00MB"
        assert human_size(5 * 1024 * 1024) == "5.00MB"

    def test_gigabytes(self):
        """Test formatting of GB values."""
        assert human_size(1024 * 1024 * 1024) == "1.00GB"
        assert human_size(10 * 1024 * 1024 * 1024) == "10.00GB"

    def test_zero(self):
        """Test formatting of zero."""
        assert human_size(0) == "0.00B"


class TestServerMetrics:
    """Test ServerMetrics class for thread safety and correctness."""

    def test_initialization(self):
        """Test metrics initialization."""
        metrics = ServerMetrics()
        assert metrics.bytes_sent == 0
        assert metrics.bytes_received == 0
        assert metrics.requests_total == 0
        assert metrics.requests_active == 0
        assert metrics.errors_total == 0

    def test_thread_safe_increment(self):
        """Test that atomic increment methods are thread-safe."""
        metrics = ServerMetrics()

        def increment_bytes():
            for _ in range(1000):
                metrics.increment_bytes_sent(1)

        threads = [threading.Thread(target=increment_bytes) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should be exactly 10000 with atomic increments
        assert metrics.bytes_sent == 10000

    def test_get_stats(self):
        """Test getting statistics."""
        metrics = ServerMetrics()
        metrics.bytes_sent = 1000000
        metrics.requests_total = 50

        stats = metrics.get_stats()
        assert stats["bytes_sent"] == 1000000
        assert stats["requests_total"] == 50
        assert "uptime_seconds" in stats
        assert "bytes_per_second" in stats

    def test_throughput_calculation(self):
        """Test bytes per second calculation."""
        metrics = ServerMetrics()
        time.sleep(0.1)  # Wait a bit for uptime
        metrics.bytes_sent = 1000

        stats = metrics.get_stats()
        assert stats["bytes_per_second"] > 0


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_no_rate_limit(self):
        """Test that limiter passes through when no rate set."""
        limiter = _RateLimiter(None)
        assert limiter.take(1000) == 1000
        assert limiter.take(5000) == 5000

    def test_rate_limiting_basic(self):
        """Test basic rate limiting."""
        # 1000 bytes per second
        limiter = _RateLimiter(1000.0)

        # Should allow at least 1 byte
        result = limiter.take(1000)
        assert result >= 1
        assert result <= 1000

    def test_burst_capacity(self):
        """Test burst capacity (2 second window)."""
        limiter = _RateLimiter(1000.0)

        # Fresh limiter should have full burst capacity
        # (2 * 1000 = 2000 bytes)
        result = limiter.take(2000)
        assert result > 1000  # Should allow burst

    def test_token_refill(self):
        """Test that tokens refill over time."""
        limiter = _RateLimiter(1000.0)

        # Drain tokens
        limiter.take(2000)

        # Wait for refill
        time.sleep(0.2)  # 200ms should add 200 tokens

        # Should have some tokens now
        result = limiter.take(1000)
        assert result >= 1


class TestSHA256:
    """Test SHA256 file hashing."""

    def test_sha256_file(self, tmp_path):
        """Test SHA256 hashing of a file."""
        import hashlib

        # Create test file
        test_file = tmp_path / "test.txt"
        content = b"Hello, World!"
        test_file.write_bytes(content)

        # Calculate expected hash
        expected = hashlib.sha256(content).hexdigest()

        # Test our function
        result = sha256_file(str(test_file))
        assert result == expected

    def test_sha256_large_file(self, tmp_path):
        """Test SHA256 hashing of a larger file."""
        import hashlib

        # Create larger test file
        test_file = tmp_path / "large.bin"
        content = b"X" * (10 * 1024 * 1024)  # 10MB
        test_file.write_bytes(content)

        # Calculate expected hash
        expected = hashlib.sha256(content).hexdigest()

        # Test our function
        result = sha256_file(str(test_file))
        assert result == expected

    def test_sha256_empty_file(self, tmp_path):
        """Test SHA256 hashing of an empty file."""
        import hashlib

        # Create empty file
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        # Calculate expected hash
        expected = hashlib.sha256(b"").hexdigest()

        # Test our function
        result = sha256_file(str(test_file))
        assert result == expected
