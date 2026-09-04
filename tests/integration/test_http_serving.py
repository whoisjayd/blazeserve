"""Integration tests for static file serving, directory traversal, and single file mode."""

from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.mark.integration
def test_serve_file(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"Hello, BlazeServe!"
        assert "text/plain" in resp.headers.get("Content-Type", "")
    finally:
        conn.close()


@pytest.mark.integration
def test_serve_large_binary(server: tuple[str, int]):
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


@pytest.mark.integration
def test_404_not_found(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/nonexistent_file.txt")
        resp = conn.getresponse()
        assert resp.status == 404
    finally:
        conn.close()


@pytest.mark.integration
def test_nested_file_in_subdirectory(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/subdir/nested.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"Nested file"
    finally:
        conn.close()


@pytest.mark.integration
def test_single_file_mode(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    target = test_dir / "test.txt"
    host, port = server_factory(base=str(test_dir), single=str(target))
    conn = HTTPConnection(host, port)
    try:
        # Any request path serves the single target file
        conn.request("GET", "/any_arbitrary_url_path.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"Hello, BlazeServe!"
    finally:
        conn.close()


@pytest.mark.integration
def test_directory_listing_disabled(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    host, port = server_factory(base=str(test_dir), listing=False)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 403
    finally:
        conn.close()


@pytest.mark.integration
def test_directory_index_html_resolution(
    server_factory: Callable[..., tuple[str, int]], tmp_path: Path
):
    (tmp_path / "index.html").write_text("<h1>Welcome Home</h1>")
    host, port = server_factory(base=str(tmp_path), listing=True)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200
        assert b"Welcome Home" in resp.read()
    finally:
        conn.close()


@pytest.mark.integration
def test_static_file_symlink_cannot_escape_base(
    server_factory: Callable[..., tuple[str, int]], tmp_path: Path
):
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret")
    try:
        (base / "leak.txt").symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    host, port = server_factory(base=str(base))
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/leak.txt")
        resp = conn.getresponse()
        assert resp.status == 403
        assert b"secret" not in resp.read()
    finally:
        conn.close()
