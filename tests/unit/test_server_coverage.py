"""Unit tests for server IPv6, TLS creation, and error propagation."""

import contextlib
from unittest.mock import MagicMock, patch

import pytest

from blazeserve.handlers import BlazeHandler
from blazeserve.server import BlazeServer, create_server


@pytest.mark.unit
def test_create_server_ipv6_family(tmp_path):
    with contextlib.suppress(OSError):
        srv = create_server(host="::1", port=0, base=str(tmp_path))
        srv.server_close()


@pytest.mark.unit
def test_create_server_with_tls(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy cert")
    key.write_text("dummy key")

    with patch("ssl.SSLContext") as mock_ctx_cls:
        mock_ctx = MagicMock()
        mock_ctx_cls.return_value = mock_ctx
        server = create_server(
            host="127.0.0.1",
            port=0,
            base=str(tmp_path),
            tls_cert=str(cert),
            tls_key=str(key),
        )
        assert server is not None
        assert mock_ctx.load_cert_chain.called
        server.server_close()


@pytest.mark.unit
def test_server_handle_error_unexpected_exception():
    server = BlazeServer(("127.0.0.1", 0), MagicMock)
    mock_request = MagicMock()
    client_address = ("127.0.0.1", 12345)

    with patch("sys.exc_info") as mock_exc:
        # Generic non-network exception
        mock_exc.return_value = (RuntimeError, RuntimeError("Unexpected fatal error"), None)
        with (
            patch.object(BlazeServer, "handle_error", wraps=server.handle_error),
            contextlib.suppress(Exception),
        ):
            server.handle_error(mock_request, client_address)
    assert server.metrics is not None
    assert server.metrics.errors_total == 1
    server.server_close()


@pytest.mark.unit
def test_handler_log_message_json(capsys):
    handler = BlazeHandler.__new__(BlazeHandler)
    handler.LOG_JSON = True
    handler.request_id = "test-req-id"
    handler.client_address = ("127.0.0.1", 8000)

    handler.log_message("GET /test 200 -", "GET /test HTTP/1.1", "200", "123")
    captured = capsys.readouterr()
    assert '"request_id": "test-req-id"' in captured.out
    assert '"status": "200"' in captured.out


@pytest.mark.unit
def test_run_server_signals_mock(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")

    mock_httpd = MagicMock()
    with (
        patch("blazeserve.server.create_server", return_value=mock_httpd),
        patch("signal.signal") as mock_signal,
    ):
        from blazeserve.server import run_server

        mock_httpd.serve_forever.side_effect = KeyboardInterrupt
        with contextlib.suppress(KeyboardInterrupt):
            run_server(
                host="127.0.0.1",
                port=0,
                base=str(tmp_path),
                tls_cert=str(cert),
                tls_key=str(key),
            )
        assert mock_signal.called
        assert mock_httpd.server_close.called
