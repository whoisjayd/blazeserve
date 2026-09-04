"""Integration tests for dynamic ZIP streaming, speed tests, and precompressed gzip assets."""

import gzip
from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path

import pytest


@pytest.mark.integration
def test_speed_benchmark_endpoint(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__speed__?bytes=4096")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/octet-stream"
        data = resp.read()
        assert len(data) == 4096
        assert data == b"\0" * 4096
    finally:
        conn.close()


@pytest.mark.integration
@pytest.mark.parametrize("value", ["not-a-number", "-1", "1048576001"])
def test_speed_benchmark_rejects_invalid_or_excessive_size(server: tuple[str, int], value: str):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", f"/__speed__?bytes={value}")
        resp = conn.getresponse()
        assert resp.status == 400
        resp.read()
    finally:
        conn.close()


@pytest.mark.integration
def test_precompressed_gzip_asset_serving(
    server_factory: Callable[..., tuple[str, int]], test_dir: Path
):
    host, port = server_factory(base=str(test_dir), precompress=True)
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/test.txt", headers={"Accept-Encoding": "gzip, deflate"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.headers.get("Content-Encoding") == "gzip"
        data = resp.read()
        assert gzip.decompress(data) == b"Precompressed gzip content"
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_directory_streaming(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__?path=subdir")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/zip"
        assert "subdir.zip" in resp.headers.get("Content-Disposition", "")
        data = resp.read()
        assert len(data) > 0
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_single_file_streaming(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__?path=test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "application/zip"
        assert len(resp.read()) > 0
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_missing_parameter(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__")
        resp = conn.getresponse()
        assert resp.status == 400
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_path_traversal_attack(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__?path=../../outside")
        resp = conn.getresponse()
        assert resp.status == 403
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_not_found(server: tuple[str, int]):
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__?path=nonexistent_folder")
        resp = conn.getresponse()
        assert resp.status == 404
    finally:
        conn.close()


@pytest.mark.integration
def test_zip_excludes_symlinked_file_outside_base(
    server_factory: Callable[..., tuple[str, int]], tmp_path: Path
):
    import io
    import zipfile

    base = tmp_path / "base"
    outside = tmp_path / "outside"
    archive_dir = base / "archive"
    archive_dir.mkdir(parents=True)
    outside.mkdir()
    (archive_dir / "inside.txt").write_text("inside")
    secret = outside / "secret.txt"
    secret.write_text("secret")
    try:
        (archive_dir / "leak.txt").symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    host, port = server_factory(base=str(base))
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/__zip__?path=archive")
        resp = conn.getresponse()
        assert resp.status == 200
        body = resp.read()
    finally:
        conn.close()

    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        assert archive.namelist() == ["inside.txt"]
