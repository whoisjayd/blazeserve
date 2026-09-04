"""Integration tests for RFC 7232 caching, security headers, and CORS."""

from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.mark.integration
def test_etag_and_last_modified_present(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "ETag" in resp.headers
        assert resp.headers["ETag"].startswith('"')
        assert "Last-Modified" in resp.headers
    finally:
        conn.close()


@pytest.mark.integration
def test_if_none_match_conditional_get_304(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp1 = conn.getresponse()
        etag = resp1.headers["ETag"]
        resp1.read()

        conn.request("GET", "/test.txt", headers={"If-None-Match": etag})
        resp2 = conn.getresponse()
        assert resp2.status == 304
        assert resp2.read() == b""
        assert resp2.headers.get("ETag") == etag
    finally:
        conn.close()


@pytest.mark.integration
def test_if_modified_since_conditional_get_304(server: tuple[str, int]):
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


@pytest.mark.integration
def test_if_none_match_weak_tag_returns_304(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        initial = conn.getresponse()
        etag = initial.headers["ETag"]
        initial.read()

        conn.request("GET", "/test.txt", headers={"If-None-Match": f"W/{etag}"})
        conditional = conn.getresponse()
        assert conditional.status == 304
        assert conditional.read() == b""
    finally:
        conn.close()


@pytest.mark.integration
def test_if_none_match_takes_precedence_over_if_modified_since(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        initial = conn.getresponse()
        last_modified = initial.headers["Last-Modified"]
        initial.read()

        conn.request(
            "GET",
            "/test.txt",
            headers={
                "If-None-Match": '"different"',
                "If-Modified-Since": last_modified,
            },
        )
        conditional = conn.getresponse()
        assert conditional.status == 200
        assert conditional.read() == b"Hello, BlazeServe!"
    finally:
        conn.close()


@pytest.mark.integration
def test_request_id_is_parsed_per_keep_alive_request(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__live__", headers={"X-Request-ID": "first-request"})
        first = conn.getresponse()
        assert first.headers.get("X-Request-ID") == "first-request"
        first.read()

        conn.request("GET", "/__live__", headers={"X-Request-ID": "second-request"})
        second = conn.getresponse()
        assert second.headers.get("X-Request-ID") == "second-request"
        second.read()
    finally:
        conn.close()


@pytest.mark.integration
def test_security_headers_present(server: tuple[str, int]):
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


@pytest.mark.integration
def test_cors_preflight_options(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("OPTIONS", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 204
        assert "Access-Control-Allow-Methods" in resp.headers
        assert "GET, HEAD, OPTIONS, PUT, POST" in resp.headers["Access-Control-Allow-Methods"]
    finally:
        conn.close()


@pytest.mark.integration
def test_no_cache_flag_behavior(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    host, port = server_factory(base=str(test_dir), no_cache=True)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "no-cache" in resp.headers.get("Cache-Control", "")
    finally:
        conn.close()
