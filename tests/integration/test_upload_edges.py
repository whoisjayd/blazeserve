"""Integration tests covering auth failure on upload and additional edge cases."""

from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.mark.integration
def test_upload_unauthorized(server_factory: Callable[..., tuple[str, int]], tmp_path: Path):
    host, port = server_factory(base=str(tmp_path), auth="admin:supersecret")
    conn = HTTPConnection(host, port)
    try:
        conn.request(
            "PUT",
            "/__upload__/test.txt",
            body=b"unauthorized payload",
            headers={"Content-Length": "20"},
        )
        resp = conn.getresponse()
        assert resp.status == 401
    finally:
        conn.close()


@pytest.mark.integration
def test_post_calls_put(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        payload = b"POST upload test"
        conn.request(
            "POST",
            "/__upload__/post_file.txt",
            body=payload,
            headers={"Content-Length": str(len(payload))},
        )
        resp = conn.getresponse()
        assert resp.status in (200, 201)
        resp.read()

        conn.request("GET", "/post_file.txt")
        resp2 = conn.getresponse()
        assert resp2.status == 200
        assert resp2.read() == payload
    finally:
        conn.close()
