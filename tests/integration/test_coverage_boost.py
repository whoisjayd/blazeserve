"""Integration tests specifically exercising directory listing, logging, and legacy dispatch."""

import logging
import sys
from collections.abc import Callable
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

import pytest

from blazeserve.cli import main
from blazeserve.logging import JsonFormatter, setup_logging


@pytest.mark.integration
def test_directory_listing_html_page(server: tuple[str, int]):
    """Exercise list_directory in BlazeHandler."""
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200
        assert "text/html" in resp.headers.get("Content-Type", "")
        body = resp.read().decode("utf-8")
        assert "Index of /" in body
        assert "test.txt" in body
        assert "subdir" in body
    finally:
        conn.close()


@pytest.mark.integration
def test_head_request_on_static_file(server: tuple[str, int]):
    """Exercise do_HEAD file path in BlazeHandler."""
    host, port = server
    conn = HTTPConnection(host, port)
    try:
        conn.request("HEAD", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b""
        assert resp.headers.get("Content-Length") == "18"
    finally:
        conn.close()


@pytest.mark.integration
def test_options_cors_disabled(server_factory: Callable[..., tuple[str, int]], test_dir: Path):
    """Exercise do_OPTIONS when CORS is False (405 Method Not Allowed)."""
    host, port = server_factory(base=str(test_dir), cors=False)
    conn = HTTPConnection(host, port)
    try:
        conn.request("OPTIONS", "/test.txt")
        resp = conn.getresponse()
        assert resp.status == 405
    finally:
        conn.close()


@pytest.mark.unit
def test_json_logging_infrastructure():
    """Exercise JsonFormatter and setup_logging with JSON handler."""
    setup_logging("INFO", json_logs=True)
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Structured message",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "Structured message" in formatted
    assert '"level": "INFO"' in formatted

    # With exception info
    try:
        raise ValueError("Sample error")
    except ValueError:
        record_exc = logging.LogRecord(
            name="test_logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=20,
            msg="Error message",
            args=(),
            exc_info=sys.exc_info(),
        )
        formatted_exc = formatter.format(record_exc)
        assert "Sample error" in formatted_exc

    # Restore default logging
    setup_logging("WARNING", json_logs=False)


@pytest.mark.unit
def test_main_legacy_send_dispatch(tmp_path: Path):
    f = tmp_path / "legacy.txt"
    f.write_text("data")
    with (
        patch.object(sys, "argv", ["blaze", "send", str(f), "-p", "8877"]),
        patch("blazeserve.cli.run_server") as mock_run,
    ):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0
        assert mock_run.called
        assert mock_run.call_args[1]["port"] == 8877


@pytest.mark.unit
def test_main_legacy_checksum_dispatch(tmp_path: Path):
    f = tmp_path / "check.txt"
    f.write_text("data")
    with patch.object(sys, "argv", ["blaze", "checksum", str(f)]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0


@pytest.mark.unit
def test_main_legacy_help_dispatch():
    with patch.object(sys, "argv", ["blaze", "-h"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
