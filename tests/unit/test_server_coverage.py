"""Unit tests for server IPv6, TLS creation, and error propagation."""

import contextlib
import signal
import socket
import ssl
import threading
from http.server import HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from blazeserve.handlers import BlazeHandler
from blazeserve.server import (
    BlazeServer,
    _resolve_address_family,
    create_server,
    run_server,
)


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
def test_run_server_restores_signal_handlers_and_does_not_claim_tls_reload():
    mock_httpd = MagicMock()
    shutdown_signals = [signal.SIGINT]
    if hasattr(signal, "SIGTERM"):
        shutdown_signals.append(signal.SIGTERM)
    previous = {signum: object() for signum in shutdown_signals}

    with (
        patch("blazeserve.server.create_server", return_value=mock_httpd),
        patch("blazeserve.server.signal.getsignal", side_effect=previous.__getitem__),
        patch("blazeserve.server.signal.signal") as set_signal,
        patch("blazeserve.server.os.name", "posix"),
    ):
        run_server(
            host="127.0.0.1",
            port=0,
            tls_cert="cert.pem",
            tls_key="key.pem",
        )

    for signum in shutdown_signals:
        registrations = [
            call.args[1] for call in set_signal.call_args_list if call.args[0] == signum
        ]
        assert len(registrations) == 2
        assert callable(registrations[0])
        assert registrations[1] is previous[signum]
    if hasattr(signal, "SIGHUP"):
        assert all(call.args[0] != signal.SIGHUP for call in set_signal.call_args_list)
    mock_httpd.serve_forever.assert_called_once_with()
    mock_httpd.server_close.assert_called_once_with()


@pytest.mark.unit
def test_run_server_on_windows_preserves_keyboard_interrupt_and_closes_listener():
    mock_httpd = MagicMock()
    mock_httpd.serve_forever.side_effect = KeyboardInterrupt

    with (
        patch("blazeserve.server.create_server", return_value=mock_httpd),
        patch("blazeserve.server.os.name", "nt"),
        patch("blazeserve.server.signal.getsignal", return_value=signal.default_int_handler),
        patch("blazeserve.server.signal.signal") as set_signal,
        pytest.raises(KeyboardInterrupt),
    ):
        run_server(host="127.0.0.1", port=0)

    sigint_registrations = [
        call for call in set_signal.call_args_list if call.args[0] == signal.SIGINT
    ]
    assert sigint_registrations == []
    mock_httpd.server_close.assert_called_once_with()


@pytest.mark.unit
def test_posix_shutdown_signal_unwinds_the_server_and_closes_listener():
    mock_httpd = MagicMock()
    installed_handlers = {}

    def set_signal(signum, handler):
        installed_handlers.setdefault(signum, handler)

    def interrupt_server():
        installed_handlers[signal.SIGINT](signal.SIGINT, None)

    mock_httpd.serve_forever.side_effect = interrupt_server

    with (
        patch("blazeserve.server.create_server", return_value=mock_httpd),
        patch("blazeserve.server.os.name", "posix"),
        patch("blazeserve.server.signal.getsignal", return_value=signal.default_int_handler),
        patch("blazeserve.server.signal.signal", side_effect=set_signal),
        pytest.raises(KeyboardInterrupt),
    ):
        run_server(host="127.0.0.1", port=0)

    mock_httpd.server_close.assert_called_once_with()


@pytest.mark.unit
def test_run_server_calls_on_bound_before_serving_and_closes_on_callback_error():
    mock_httpd = MagicMock()
    callback = MagicMock(side_effect=RuntimeError("open failed"))

    with (
        patch("blazeserve.server.create_server", return_value=mock_httpd),
        pytest.raises(RuntimeError, match="open failed"),
    ):
        run_server(on_bound=callback)

    callback.assert_called_once_with(mock_httpd)
    mock_httpd.serve_forever.assert_not_called()
    mock_httpd.server_close.assert_called_once_with()


@pytest.mark.unit
def test_server_close_returns_promptly_with_an_idle_client(tmp_path):
    request_started = threading.Event()
    close_finished = threading.Event()
    original_process_request = BlazeServer.process_request_thread

    def tracked_process_request(server, request, client_address):
        request_started.set()
        original_process_request(server, request, client_address)

    with patch.object(BlazeServer, "process_request_thread", tracked_process_request):
        server = create_server(host="127.0.0.1", port=0, base=str(tmp_path), timeout=30)
        serve_thread = threading.Thread(target=server.serve_forever)
        serve_thread.start()
        idle_client = socket.create_connection(server.server_address, timeout=1.0)
        idle_client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        assert request_started.wait(1.0)
        server.shutdown()

        def close_server():
            server.server_close()
            close_finished.set()

        close_thread = threading.Thread(target=close_server)
        close_thread.start()
        try:
            assert close_finished.wait(1.0), "server_close waited for the idle request thread"
        finally:
            with contextlib.suppress(OSError):
                idle_client.shutdown(socket.SHUT_RDWR)
            idle_client.close()
            close_thread.join(timeout=2.0)
            serve_thread.join(timeout=2.0)


@pytest.mark.unit
def test_address_family_resolution_prefers_ipv4_for_dual_stack_hostname():
    addresses = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]
    with patch("blazeserve.server.socket.getaddrinfo", return_value=addresses):
        assert _resolve_address_family("localhost", 0) == socket.AF_INET


@pytest.mark.unit
def test_address_family_resolution_supports_ipv6_only_hostname():
    addresses = [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0))]
    with patch("blazeserve.server.socket.getaddrinfo", return_value=addresses):
        assert _resolve_address_family("ipv6-only.example", 0) == socket.AF_INET6


@pytest.mark.unit
def test_address_family_resolution_keeps_ipv4_fallback_on_lookup_failure():
    with patch("blazeserve.server.socket.getaddrinfo", side_effect=socket.gaierror):
        assert _resolve_address_family("unresolved.example", 0) == socket.AF_INET


@pytest.mark.unit
def test_create_server_isolates_handler_configuration(tmp_path):
    first_base = tmp_path / "first"
    second_base = tmp_path / "second"
    first_base.mkdir()
    second_base.mkdir()
    first = create_server(
        host="127.0.0.1", port=0, base=str(first_base), listing=False, rate_mbps=1.0
    )
    second = create_server(
        host="127.0.0.1", port=0, base=str(second_base), listing=True, rate_mbps=2.0
    )
    try:
        assert first.RequestHandlerClass is not second.RequestHandlerClass
        assert str(first_base.resolve()) == first.RequestHandlerClass.BASE
        assert str(second_base.resolve()) == second.RequestHandlerClass.BASE
        assert first.RequestHandlerClass.LISTING is False
        assert second.RequestHandlerClass.LISTING is True
        assert first.RequestHandlerClass.RATE_BPS == 1024 * 1024
        assert second.RequestHandlerClass.RATE_BPS == 2 * 1024 * 1024
    finally:
        first.server_close()
        second.server_close()


@pytest.mark.unit
def test_create_server_applies_socket_configuration_before_binding(tmp_path):
    observed = {}
    original_bind = BlazeServer.server_bind

    def recording_bind(server):
        observed["tcp_sendbuf"] = server.tcp_sendbuf
        observed["backlog"] = server.request_queue_size
        original_bind(server)

    with patch.object(BlazeServer, "server_bind", recording_bind):
        server = create_server(host="127.0.0.1", port=0, base=str(tmp_path), sndbuf_mb=1, backlog=7)
    try:
        assert observed == {"tcp_sendbuf": 1024 * 1024, "backlog": 7}
    finally:
        server.server_close()


@pytest.mark.unit
@pytest.mark.parametrize(("tls_cert", "tls_key"), [("cert.pem", None), (None, "key.pem")])
def test_create_server_rejects_incomplete_tls_before_binding(tmp_path, tls_cert, tls_key):
    with (
        patch.object(BlazeServer, "server_bind", side_effect=AssertionError("socket was bound")),
        pytest.raises(ValueError, match="TLS certificate and key must be provided together"),
    ):
        create_server(
            host="127.0.0.1",
            port=0,
            base=str(tmp_path),
            tls_cert=tls_cert,
            tls_key=tls_key,
        )


@pytest.mark.unit
def test_create_server_closes_listener_when_tls_setup_fails(tmp_path):
    context = MagicMock()
    context.load_cert_chain.side_effect = ssl.SSLError("invalid certificate")
    closed = []

    def recording_close(server):
        closed.append(server)
        HTTPServer.server_close(server)

    with (
        patch("blazeserve.server.ssl.SSLContext", return_value=context),
        patch.object(BlazeServer, "server_close", recording_close),
        pytest.raises(ssl.SSLError, match="invalid certificate"),
    ):
        create_server(
            host="127.0.0.1",
            port=0,
            base=str(tmp_path),
            tls_cert="cert.pem",
            tls_key="key.pem",
        )
    assert len(closed) == 1


@pytest.mark.unit
@pytest.mark.parametrize("rate_mbps", [0, -1])
def test_create_server_rejects_nonpositive_rate_limits_before_binding(tmp_path, rate_mbps):
    with (
        patch.object(BlazeServer, "server_bind", side_effect=AssertionError("socket was bound")),
        pytest.raises(ValueError, match="rate_mbps must be greater than zero"),
    ):
        create_server(host="127.0.0.1", port=0, base=str(tmp_path), rate_mbps=rate_mbps)
