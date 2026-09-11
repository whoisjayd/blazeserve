"""Integration tests for RFC 7232 caching, security headers, and CORS."""

import gzip
from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


def _header_token_set(headers, name: str, *, case_sensitive: bool) -> set[str]:
    """Return comma-separated header tokens without depending on their order."""
    tokens = {
        token.strip()
        for value in headers.get_all(name, [])
        for token in value.split(",")
        if token.strip()
    }
    return tokens if case_sensitive else {token.casefold() for token in tokens}


def _assert_cors_headers(response, origin: str) -> None:
    assert response.headers.get("Access-Control-Allow-Origin") == origin
    assert _header_token_set(
        response.headers, "Access-Control-Allow-Methods", case_sensitive=True
    ) == {"GET", "HEAD", "OPTIONS", "PUT", "POST"}
    assert _header_token_set(
        response.headers, "Access-Control-Allow-Headers", case_sensitive=False
    ) == {"range", "content-type", "authorization", "x-request-id"}
    assert _header_token_set(
        response.headers, "Access-Control-Expose-Headers", case_sensitive=False
    ) == {
        "accept-ranges",
        "content-length",
        "content-range",
        "etag",
        "last-modified",
        "x-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
    }


@pytest.fixture
def configured_cors_server(
    server_factory: Callable[..., tuple[str, int]], test_dir: Path
) -> tuple[str, int]:
    """Serve test files with a non-default CORS origin."""
    return server_factory(base=str(test_dir), cors=True, cors_origin="https://client.example.test")


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
def test_cors_preflight_options(configured_cors_server: tuple[str, int]):
    host, port = configured_cors_server
    conn = HTTPConnection(host, port)
    try:
        conn.request("OPTIONS", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 204
        assert resp.read() == b""
        _assert_cors_headers(resp, "https://client.example.test")
    finally:
        conn.close()


@pytest.mark.integration
def test_cors_get_and_head_vary_by_origin(configured_cors_server: tuple[str, int]):
    host, port = configured_cors_server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        get_response = conn.getresponse()
        assert get_response.status == 200
        assert get_response.read() == b"Hello, BlazeServe!"
        _assert_cors_headers(get_response, "https://client.example.test")
        assert _header_token_set(get_response.headers, "Vary", case_sensitive=False) == {"origin"}

        conn.request("HEAD", "/test.txt")
        head_response = conn.getresponse()
        assert head_response.status == 200
        assert head_response.read() == b""
        _assert_cors_headers(head_response, "https://client.example.test")
        assert _header_token_set(head_response.headers, "Vary", case_sensitive=False) == {"origin"}
    finally:
        conn.close()


@pytest.mark.integration
def test_cors_gzip_get_varies_by_origin_and_encoding(configured_cors_server: tuple[str, int]):
    host, port = configured_cors_server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Accept-Encoding": "gzip"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.headers.get("Content-Encoding") == "gzip"
        assert gzip.decompress(resp.read()) == b"Precompressed gzip content"
        _assert_cors_headers(resp, "https://client.example.test")
        assert _header_token_set(resp.headers, "Vary", case_sensitive=False) == {
            "origin",
            "accept-encoding",
        }
    finally:
        conn.close()


@pytest.mark.integration
def test_cors_disabled_omits_cors_headers_and_origin_vary(
    server_factory: Callable[..., tuple[str, int]], test_dir: Path
):
    host, port = server_factory(base=str(test_dir), cors=False)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"Hello, BlazeServe!"
        for name in (
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Expose-Headers",
        ):
            assert resp.headers.get(name) is None
        assert "origin" not in _header_token_set(resp.headers, "Vary", case_sensitive=False)
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
