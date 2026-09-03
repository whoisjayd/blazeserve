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
def test_operational_head_probes(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        for ep in [
            "/__live__",
            "/__ready__",
            "/__version__",
            "/__metrics__",
            "/metrics",
            "/__health__",
        ]:
            conn.request("HEAD", ep)
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.read() == b""
    finally:
        conn.close()
