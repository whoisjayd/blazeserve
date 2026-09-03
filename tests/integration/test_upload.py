"""Integration tests for file upload handling, size limits, and security constraints."""

from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.mark.integration
def test_upload_success_and_readback(
    server_factory: Callable[..., tuple[str, int]], tmp_path: Path
):
    host, port = server_factory(base=str(tmp_path), max_upload_mb=10)
    conn = HTTPConnection(host, port)
    try:
        content = b"Uploaded file payload"
        conn.request(
            "PUT",
            "/__upload__/new_doc.txt",
            body=content,
            headers={"Content-Length": str(len(content))},
        )
        resp = conn.getresponse()
        assert resp.status == 201
        resp.read()

        # Read back newly uploaded file
        conn.request("GET", "/new_doc.txt")
        resp2 = conn.getresponse()
        assert resp2.status == 200
        assert resp2.read() == content
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_already_exists_conflict(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request(
            "PUT",
            "/__upload__/test.txt",
            body=b"overwrite",
            headers={"Content-Length": "9"},
        )
        resp = conn.getresponse()
        assert resp.status == 409
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_missing_content_length(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.putrequest("PUT", "/__upload__/no_len.txt")
        conn.endheaders()
        resp = conn.getresponse()
        assert resp.status == 411
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_invalid_content_length(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request(
            "PUT",
            "/__upload__/bad_len.txt",
            body=b"data",
            headers={"Content-Length": "not_an_int"},
        )
        resp = conn.getresponse()
        assert resp.status == 400
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_empty_filename(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("PUT", "/__upload__/", body=b"data", headers={"Content-Length": "4"})
        resp = conn.getresponse()
        assert resp.status == 400
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_exceeds_max_limit(server_factory: Callable[..., tuple[str, int]], tmp_path: Path):
    host, port = server_factory(base=str(tmp_path), max_upload_mb=1)
    conn = HTTPConnection(host, port)
    try:
        two_mb = 2 * 1024 * 1024
        conn.request(
            "PUT",
            "/__upload__/too_large.bin",
            headers={"Content-Length": str(two_mb)},
        )
        resp = conn.getresponse()
        assert resp.status == 413
    finally:
        conn.close()


@pytest.mark.integration
def test_upload_path_traversal_forbidden(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request(
            "PUT",
            "/__upload__/../../malicious.txt",
            body=b"evil",
            headers={"Content-Length": "4"},
        )
        resp = conn.getresponse()
        assert resp.status == 403
    finally:
        conn.close()
