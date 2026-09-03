"""Unit tests for ServerMetrics telemetry and Prometheus exporter."""

import pytest

from blazeserve.metrics import ServerMetrics


@pytest.mark.unit
def test_server_metrics_properties_and_setters():
    sm = ServerMetrics()

    sm.bytes_sent = 500
    assert sm.bytes_sent == 500

    sm.bytes_received = 300
    assert sm.bytes_received == 300

    sm.requests_total = 10
    assert sm.requests_total == 10

    sm.requests_active = 5
    assert sm.requests_active == 5

    sm.errors_total = 2
    assert sm.errors_total == 2


@pytest.mark.unit
def test_server_metrics_decrement_active_bound():
    sm = ServerMetrics()
    assert sm.requests_active == 0
    sm.decrement_requests_active()
    assert sm.requests_active == 0

    sm.increment_requests_active()
    assert sm.requests_active == 1
    sm.decrement_requests_active()
    assert sm.requests_active == 0


@pytest.mark.unit
def test_server_metrics_get_stats():
    sm = ServerMetrics()
    sm.increment_bytes_sent(1024)
    sm.increment_bytes_received(512)
    sm.increment_requests_total()
    sm.increment_errors_total()

    stats = sm.get_stats()
    assert stats["bytes_sent"] == 1024
    assert stats["bytes_received"] == 512
    assert stats["requests_total"] == 1
    assert stats["errors_total"] == 1
    assert "uptime_seconds" in stats
    assert "bytes_per_second" in stats


@pytest.mark.unit
def test_server_metrics_to_prometheus():
    sm = ServerMetrics()
    sm.increment_bytes_sent(2048)
    sm.increment_bytes_received(1024)
    sm.increment_requests_total()
    sm.increment_requests_active()
    sm.increment_errors_total()

    prom = sm.to_prometheus()
    assert "# HELP blazeserve_uptime_seconds" in prom
    assert "# TYPE blazeserve_uptime_seconds gauge" in prom
    assert "blazeserve_bytes_sent_total 2048" in prom
    assert "blazeserve_bytes_received_total 1024" in prom
    assert "blazeserve_requests_total 1" in prom
    assert "blazeserve_requests_active 1" in prom
    assert "blazeserve_errors_total 1" in prom
