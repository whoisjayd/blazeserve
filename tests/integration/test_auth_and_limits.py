"""Integration tests for HTTP Basic Authentication and Rate Limiting."""

import base64
from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest

from blazeserve.server import create_server


@pytest.mark.integration
def test_create_server_invalid_auth_syntax(tmp_path: Path):
    with pytest.raises(SystemExit, match="Auth must be USER:PASS"):
        create_server(host="127.0.0.1", port=0, base=str(tmp_path), auth="no_colon_string")


@pytest.mark.integration
def test_basic_auth_valid(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    host, port = server_factory(base=str(test_dir), auth="admin:supersecret")
    conn = HTTPConnection(host, port)
    try:
        raw_token = base64.b64encode(b"admin:supersecret").decode("ascii")
        conn.request(
            "GET",
            "/test.txt",
            headers={"Authorization": f"Basic {raw_token}"},
        )
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"Hello, BlazeServe!"
    finally:
        conn.close()


@pytest.mark.integration
def test_basic_auth_missing_header(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    host, port = server_factory(base=str(test_dir), auth="admin:supersecret")
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 401
        assert "WWW-Authenticate" in resp.headers
        assert 'Basic realm="blazeserve"' in resp.headers["WWW-Authenticate"]
    finally:
        conn.close()


@pytest.mark.integration
def test_basic_auth_invalid_credentials(
    server_factory: Callable[..., tuple[str, int]], test_dir: Path
):
    host, port = server_factory(base=str(test_dir), auth="admin:supersecret")
    conn = HTTPConnection(host, port)
    try:
        wrong_token = base64.b64encode(b"admin:wrongpassword").decode("ascii")
        conn.request(
            "GET",
            "/test.txt",
            headers={"Authorization": f"Basic {wrong_token}"},
        )
        resp = conn.getresponse()
        assert resp.status == 401
    finally:
        conn.close()


@pytest.mark.integration
def test_rate_limit_headers(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    host, port = server_factory(base=str(test_dir), rate_mbps=50.0)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert int(resp.headers["X-RateLimit-Limit"]) == int(50.0 * 1024 * 1024)
    finally:
        conn.close()
