"""Integration tests for HTTP/1.1 single and multipart byte-range downloads."""

from http.client import HTTPConnection

import pytest


@pytest.mark.integration
def test_single_byte_range(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Range": "bytes=0-4"})
        resp = conn.getresponse()
        assert resp.status == 206
        assert resp.read() == b"Hello"
        assert "bytes 0-4/" in resp.headers.get("Content-Range", "")
    finally:
        conn.close()


@pytest.mark.integration
def test_suffix_byte_range(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Range": "bytes=-5"})
        resp = conn.getresponse()
        assert resp.status == 206
        data = resp.read()
        assert data == b"erve!"
    finally:
        conn.close()


@pytest.mark.integration
def test_full_range_request(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Range": "bytes=0-"})
        resp = conn.getresponse()
        assert resp.status == 206
        assert resp.read() == b"Hello, BlazeServe!"
    finally:
        conn.close()


@pytest.mark.integration
def test_multipart_byteranges(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Range": "bytes=0-4,7-11"})
        resp = conn.getresponse()
        assert resp.status == 206
        assert "multipart/byteranges" in resp.headers.get("Content-Type", "")
        body = resp.read()
        assert b"Hello" in body
        assert b"Blaze" in body
    finally:
        conn.close()
