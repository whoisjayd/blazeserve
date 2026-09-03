"""
Test suite for BlazeServe server functionality.

This module contains comprehensive tests for the HTTP server,
including file serving, range requests, and special endpoints.
"""

import json
import tempfile
import threading
import time
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.fixture
def test_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_path = Path(tmpdir)
        (test_path / "test.txt").write_text("Hello, BlazeServe!")
        (test_path / "large.bin").write_bytes(b"X" * (1024 * 1024))  # 1MB

        # Create subdirectory
        subdir = test_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("Nested file")

        yield tmpdir


@pytest.fixture
def server(test_dir):
    """Start a test server instance with clean lifecycle teardown."""
    from blazeserve.server import create_server

    httpd = create_server(
        host="127.0.0.1",
        port=0,
        base=test_dir,
        single=None,
        listing=True,
        chunk_mb=256,
        sndbuf_mb=128,
        timeout=10,
        rate_mbps=None,
        auth=None,
        tls_cert=None,
        tls_key=None,
        cors=True,
        cors_origin="*",
        no_cache=False,
        index=None,
        backlog=8192,
        precompress=True,
        max_upload_mb=100,
        verbose=False,
    )
    actual_port = httpd.server_port
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.05)

    try:
        yield ("127.0.0.1", actual_port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        server_thread.join(timeout=2.0)


class TestBasicServing:
    """Test basic file serving functionality."""

    def test_serve_file(self, server):
        """Test serving a simple text file."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.read() == b"Hello, BlazeServe!"
        finally:
            conn.close()

    def test_serve_large_file(self, server):
        """Test serving a larger binary file."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/large.bin")
            resp = conn.getresponse()

            assert resp.status == 200
            data = resp.read()
            assert len(data) == 1024 * 1024
            assert data == b"X" * (1024 * 1024)
        finally:
            conn.close()

    def test_404_not_found(self, server):
        """Test 404 response for non-existent file."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/nonexistent.txt")
            resp = conn.getresponse()

            assert resp.status == 404
        finally:
            conn.close()

    def test_nested_file(self, server):
        """Test serving file from subdirectory."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/subdir/nested.txt")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.read() == b"Nested file"
        finally:
            conn.close()


class TestRangeRequests:
    """Test HTTP range request handling."""

    def test_single_range(self, server):
        """Test single byte range request."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt", headers={"Range": "bytes=0-4"})
            resp = conn.getresponse()

            assert resp.status == 206  # Partial Content
            assert resp.read() == b"Hello"
            assert "Content-Range" in resp.headers
        finally:
            conn.close()

    def test_range_suffix(self, server):
        """Test suffix byte range (last N bytes)."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            # "Hello, BlazeServe!" - last 7 bytes
            conn.request("GET", "/test.txt", headers={"Range": "bytes=-7"})
            resp = conn.getresponse()

            assert resp.status == 206
            data = resp.read()
            # Should end with "Serve!"
            assert data == b"Serve!" or data == b"eServe!"
        finally:
            conn.close()

    def test_full_range(self, server):
        """Test range covering entire file."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt", headers={"Range": "bytes=0-"})
            resp = conn.getresponse()

            assert resp.status == 206
            assert resp.read() == b"Hello, BlazeServe!"
        finally:
            conn.close()


class TestSpecialEndpoints:
    """Test special server endpoints."""

    def test_health_endpoint(self, server):
        """Test health check endpoint."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/__health__")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json"

            import json

            data = json.loads(resp.read())
            assert data["status"] == "ok"
        finally:
            conn.close()

    def test_stats_endpoint(self, server):
        """Test statistics endpoint."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/__stats__")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json"

            import json

            data = json.loads(resp.read())
            assert "bytes_sent" in data
        finally:
            conn.close()

    def test_perf_endpoint(self, server):
        """Test performance metrics endpoint."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/__perf__")
            resp = conn.getresponse()

            assert resp.status == 200
            assert resp.headers.get("Content-Type") == "application/json"

            import json

            data = json.loads(resp.read())
            assert "uptime_seconds" in data
            assert "bytes_sent" in data
            assert "requests_total" in data
            assert "config" in data
            assert data["config"]["chunk_size_mb"] == 256
            assert data["config"]["send_buffer_mb"] == 128
        finally:
            conn.close()


class TestCORS:
    """Test CORS header handling."""

    def test_cors_headers_present(self, server):
        """Test that CORS headers are present when enabled."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()

            assert "Access-Control-Allow-Origin" in resp.headers
            assert resp.headers["Access-Control-Allow-Origin"] == "*"
        finally:
            conn.close()

    def test_options_request(self, server):
        """Test OPTIONS preflight request."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("OPTIONS", "/test.txt")
            resp = conn.getresponse()

            assert resp.status == 204
            assert "Access-Control-Allow-Methods" in resp.headers
        finally:
            conn.close()


class TestHTTPHeaders:
    """Test HTTP header handling."""

    def test_etag_present(self, server):
        """Test that ETag header is present."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()

            assert "ETag" in resp.headers
            assert resp.headers["ETag"].startswith('"')
        finally:
            conn.close()

    def test_last_modified(self, server):
        """Test Last-Modified header."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()

            assert "Last-Modified" in resp.headers
        finally:
            conn.close()

    def test_content_type(self, server):
        """Test Content-Type header for text file."""
        host, port = server
        conn = HTTPConnection(host, port)

        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()

            assert "Content-Type" in resp.headers
            assert "text/plain" in resp.headers["Content-Type"]
        finally:
            conn.close()


class TestOperationalEndpoints:
    """Test k8s operational probes, version, and Prometheus metrics endpoints."""

    def test_live_endpoint(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/__live__")
            resp = conn.getresponse()
            assert resp.status == 200
            data = json.loads(resp.read())
            assert data["status"] == "alive"
        finally:
            conn.close()

    def test_ready_endpoint_success(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/__ready__")
            resp = conn.getresponse()
            assert resp.status == 200
            data = json.loads(resp.read())
            assert data["status"] == "ready"
        finally:
            conn.close()

    def test_version_endpoint(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/__version__")
            resp = conn.getresponse()
            assert resp.status == 200
            data = json.loads(resp.read())
            assert data["name"] == "blazeserve"
            assert data["version"] == "0.3.0"
            assert "python" in data
            assert "platform" in data
        finally:
            conn.close()

    def test_prometheus_metrics_endpoint(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/__metrics__")
            resp = conn.getresponse()
            assert resp.status == 200
            assert "text/plain" in resp.headers.get("Content-Type", "")
            body = resp.read().decode("utf-8")
            assert "# HELP blazeserve_uptime_seconds" in body
            assert "# TYPE blazeserve_uptime_seconds gauge" in body
            assert "blazeserve_requests_total" in body
            assert "blazeserve_bytes_sent_total" in body
        finally:
            conn.close()

    def test_operational_head_requests(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            for ep in ["/__live__", "/__ready__", "/__version__", "/__metrics__", "/metrics"]:
                conn.request("HEAD", ep)
                resp = conn.getresponse()
                assert resp.status == 200
                assert resp.read() == b""
        finally:
            conn.close()


class TestConditionalCaching:
    """Test RFC-7232 compliant conditional requests (If-None-Match, If-Modified-Since)."""

    def test_if_none_match_returns_304(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/test.txt")
            resp1 = conn.getresponse()
            assert resp1.status == 200
            etag = resp1.headers["ETag"]
            resp1.read()

            conn.request("GET", "/test.txt", headers={"If-None-Match": etag})
            resp2 = conn.getresponse()
            assert resp2.status == 304
            assert resp2.read() == b""
            assert resp2.headers.get("ETag") == etag
        finally:
            conn.close()

    def test_if_modified_since_returns_304(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/test.txt")
            resp1 = conn.getresponse()
            last_mod = resp1.headers["Last-Modified"]
            resp1.read()

            conn.request("GET", "/test.txt", headers={"If-Modified-Since": last_mod})
            resp2 = conn.getresponse()
            assert resp2.status == 304
            assert resp2.read() == b""
        finally:
            conn.close()


class TestSecurityHeaders:
    """Test standard defense-in-depth HTTP security headers."""

    def test_security_headers_present(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("GET", "/test.txt")
            resp = conn.getresponse()
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert resp.headers.get("X-Frame-Options") == "DENY"
            assert "X-Request-ID" in resp.headers
            assert "strict-origin" in resp.headers.get("Referrer-Policy", "")
        finally:
            conn.close()


class TestRateLimitingAndUpload:
    """Test rate limit headers and upload validation."""

    def test_upload_invalid_path(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            conn.request("PUT", "/invalid_upload/file.txt", body=b"test")
            resp = conn.getresponse()
            assert resp.status == 405
        finally:
            conn.close()

    def test_upload_valid_file(self, server):
        host, port = server
        conn = HTTPConnection(host, port)
        try:
            payload = b"Upload test content"
            conn.request(
                "PUT",
                "/__upload__/uploaded.txt",
                body=payload,
                headers={"Content-Length": str(len(payload))},
            )
            resp = conn.getresponse()
            assert resp.status in (200, 201)
            resp.read()

            # Read back uploaded file
            conn.request("GET", "/uploaded.txt")
            resp2 = conn.getresponse()
            assert resp2.status == 200
            assert resp2.read() == payload
        finally:
            conn.close()
