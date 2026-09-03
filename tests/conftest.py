"""Shared pytest fixtures, server factories, and test environment configuration."""

from __future__ import annotations

import gzip
import socket
import threading
import time
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

import pytest

from blazeserve.server import create_server


def wait_for_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Poll socket until server accepts connections."""
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.01)
    return False


@pytest.fixture
def test_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with test files and subdirectories."""
    (tmp_path / "test.txt").write_text("Hello, BlazeServe!")
    (tmp_path / "large.bin").write_bytes(b"X" * (1024 * 1024))  # 1MB
    (tmp_path / "empty.txt").write_text("")

    gz_content = gzip.compress(b"Precompressed gzip content")
    (tmp_path / "test.txt.gz").write_bytes(gz_content)

    subdir = tmp_path / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("Nested file")

    return tmp_path


@pytest.fixture
def server_factory() -> Generator[Callable[..., tuple[str, int]], None, None]:
    """Factory fixture to spawn parameterized test servers with clean lifecycle teardown."""
    running_servers = []

    def _spawn(**kwargs: Any) -> tuple[str, int]:
        host = kwargs.pop("host", "127.0.0.1")
        port = kwargs.pop("port", 0)
        httpd = create_server(host=host, port=port, **kwargs)
        actual_port = httpd.server_port

        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        if not wait_for_port(host, actual_port, timeout=3.0):
            httpd.shutdown()
            httpd.server_close()
            raise RuntimeError(f"Server failed to bind on port {actual_port}")

        running_servers.append((httpd, t))
        return (host, actual_port)

    yield _spawn

    for httpd, t in running_servers:
        httpd.shutdown()
        httpd.server_close()
        t.join(timeout=2.0)


@pytest.fixture
def server(server_factory: Callable[..., tuple[str, int]], test_dir: Path) -> tuple[str, int]:
    """Default test server instance serving test_dir."""
    return server_factory(base=str(test_dir), cors=True)
