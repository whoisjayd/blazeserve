"""Integration tests for SRE operational endpoints, Kubernetes probes, and Prometheus metrics."""

import json
from http.client import HTTPConnection

import pytest


@pytest.mark.integration
def test_live_probe_endpoint(server: tuple[str, int]):
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


@pytest.mark.integration
def test_ready_probe_endpoint(server: tuple[str, int]):
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


@pytest.mark.integration
def test_version_endpoint(server: tuple[str, int]):
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


@pytest.mark.integration
def test_prometheus_metrics_endpoint(server: tuple[str, int]):
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


@pytest.mark.integration
def test_metrics_reports_only_current_request_as_active(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__live__")
        assert conn.getresponse().read()

        conn.request("GET", "/__metrics__")
        body = conn.getresponse().read().decode("utf-8")
        assert "blazeserve_requests_active 1" in body
    finally:
        conn.close()


@pytest.mark.integration
def test_perf_and_stats_endpoints(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__perf__")
        resp1 = conn.getresponse()
        assert resp1.status == 200
        perf_data = json.loads(resp1.read())
        assert "uptime_seconds" in perf_data
        assert "config" in perf_data

        conn.request("GET", "/__stats__")
        resp2 = conn.getresponse()
        assert resp2.status == 200
        stats_data = json.loads(resp2.read())
        assert "bytes_sent" in stats_data
    finally:
        conn.close()


@pytest.mark.integration
def test_stats_reports_actual_bytes_sent(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        response = conn.getresponse()
        response.read()

        conn.request("GET", "/__stats__")
        stats = conn.getresponse()
        assert stats.status == 200
        assert json.loads(stats.read())["bytes_sent"] >= len(b"Hello, BlazeServe!")
    finally:
        conn.close()


@pytest.mark.integration
def test_operational_head_matches_get_status_and_representation_headers(server: tuple[str, int]):
    host, port = server
    cases = [
        "/__live__",
        "/__ready__",
        "/__version__",
        "/__metrics__",
        "/metrics",
        "/__health__",
        "/__speed__?bytes=32",
        "/__zip__",
    ]
    conn = HTTPConnection(host, port)
    try:
        for endpoint in cases:
            conn.request("GET", endpoint)
            get_response = conn.getresponse()
            get_status = get_response.status
            get_headers = {
                name: get_response.headers.get(name)
                for name in ("Content-Type", "Content-Length", "Cache-Control")
            }
            get_response.read()

            conn.request("HEAD", endpoint)
            head_response = conn.getresponse()
            assert head_response.status == get_status
            stable_headers = ("Content-Type", "Cache-Control")
            assert {name: head_response.headers.get(name) for name in stable_headers} == {
                name: get_headers[name] for name in stable_headers
            }
            # Prometheus output changes as each request updates its counters.
            if endpoint not in ("/__metrics__", "/metrics"):
                assert head_response.headers.get("Content-Length") == get_headers["Content-Length"]
            assert head_response.read() == b""
    finally:
        conn.close()


@pytest.mark.integration
def test_metrics_count_keep_alive_http_requests(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        for _ in range(2):
            conn.request("GET", "/__live__")
            response = conn.getresponse()
            response.read()

        conn.request("GET", "/__metrics__")
        metrics = conn.getresponse()
        body = metrics.read().decode("utf-8")
        assert "blazeserve_requests_total 3" in body
        assert "blazeserve_requests_active 1" in body
    finally:
        conn.close()
