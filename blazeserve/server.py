"""BlazeServer socket orchestration, platform TCP tuning, and lifecycle management."""

from __future__ import annotations

import argparse
import contextlib
import os
import signal
import socket
import ssl
import sys
import threading
from collections.abc import Callable
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from typing import Any

from blazeserve.handlers import (
    DEFAULT_CHUNK_MB,
    DEFAULT_SNDBUF_MB,
    BlazeHandler,
    _etag_for_stat,
    _http_date,
    _parse_range_header,
)
from blazeserve.limiter import IPRateLimiterPool, TokenBucket
from blazeserve.metrics import ServerMetrics

# Backwards compatibility aliases
_RateLimiter = TokenBucket
RECVBUF_MB = 64


class BlazeServer(ThreadingMixIn, HTTPServer):
    """Optimized multi-threaded HTTP server with draining shutdown semantics."""

    daemon_threads = False
    request_queue_size = 8192
    allow_reuse_address = True
    block_on_close = True
    tcp_sendbuf = DEFAULT_SNDBUF_MB * 1024 * 1024
    conn_timeout = 1800
    bytes_sent: int = 0
    metrics: ServerMetrics | None = None

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        if self.metrics is None:
            self.metrics = ServerMetrics()
        self.ip_limiters = IPRateLimiterPool()

    def server_bind(self) -> None:
        """Apply OS kernel-level socket and TCP buffer optimizations."""
        s = self.socket
        opts = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.SOL_SOCKET, socket.SO_SNDBUF, self.tcp_sendbuf),
            (socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_MB * 1024 * 1024),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]

        if hasattr(socket, "SO_REUSEPORT"):
            opts.append((socket.SOL_SOCKET, socket.SO_REUSEPORT, 1))

        if hasattr(socket, "TCP_NODELAY"):
            opts.append((socket.IPPROTO_TCP, socket.TCP_NODELAY, 1))

        if hasattr(socket, "TCP_QUICKACK") and sys.platform.startswith("linux"):
            opts.append((socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1))

        for lvl, opt, val in opts:
            with contextlib.suppress(OSError, AttributeError):
                s.setsockopt(lvl, opt, val)

        super().server_bind()

    def handle_error(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        """Track errors in metrics and suppress expected client disconnections."""
        e = sys.exc_info()[1]
        if hasattr(self, "metrics") and self.metrics:
            self.metrics.increment_errors_total()

        if isinstance(e, BrokenPipeError | ConnectionResetError | TimeoutError | OSError):
            return
        return super().handle_error(request, client_address)


def _resolve_address_family(host: str, port: int) -> socket.AddressFamily:
    """Resolve a bind host, preferring IPv4 when both families are available."""
    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            0,
            socket.AI_PASSIVE,
        )
    except socket.gaierror:
        return socket.AF_INET

    families = {address[0] for address in addresses}
    if socket.AF_INET in families:
        return socket.AF_INET
    if socket.AF_INET6 in families:
        return socket.AF_INET6
    return socket.AF_INET


def create_server(
    *,
    host: str = "0.0.0.0",
    port: int = 8000,
    base: str = ".",
    single: str | None = None,
    listing: bool = True,
    chunk_mb: int = DEFAULT_CHUNK_MB,
    sndbuf_mb: int = DEFAULT_SNDBUF_MB,
    timeout: int = 60,
    rate_mbps: float | None = None,
    auth: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    cors: bool = False,
    cors_origin: str = "*",
    no_cache: bool = False,
    index: list[str] | None = None,
    backlog: int = 4096,
    precompress: bool = True,
    max_upload_mb: int = 0,
    verbose: bool = False,
    log_json: bool = False,
) -> BlazeServer:
    """Instantiate and configure a high-performance BlazeServer."""
    if rate_mbps is not None and rate_mbps <= 0:
        raise ValueError("rate_mbps must be greater than zero when configured")
    if bool(tls_cert) != bool(tls_key):
        raise ValueError("TLS certificate and key must be provided together")

    class _Handler(BlazeHandler):
        pass

    _Handler.BASE = os.path.abspath(base)
    _Handler.WINDOW = max(4, int(chunk_mb)) * 1024 * 1024
    _Handler.SINGLE = single
    _Handler.LISTING = listing
    _Handler.RATE_BPS = (rate_mbps * 1024 * 1024) if rate_mbps else None
    _Handler.CORS = bool(cors)
    _Handler.CORS_ORIGIN = cors_origin or "*"
    _Handler.NOCACHE = bool(no_cache)
    _Handler.INDEX = list(index or [])
    _Handler.PRECOMPRESS = bool(precompress)
    _Handler.MAX_UPLOAD = max(0, int(max_upload_mb)) * 1024 * 1024
    _Handler.LOG_JSON = bool(log_json)

    if auth:
        if ":" not in auth:
            raise SystemExit("Auth must be USER:PASS")
        user, pw = auth.split(":", 1)
        _Handler.AUTH_PAIR = (user, pw)
    else:
        _Handler.AUTH_PAIR = None

    fam = _resolve_address_family(host, port)

    class _S(BlazeServer):
        tcp_sendbuf = max(256 * 1024, int(sndbuf_mb) * 1024 * 1024)
        request_queue_size = max(1, int(backlog))

    _S.address_family = fam
    httpd = _S((host, port), _Handler)
    httpd.conn_timeout = max(5, int(timeout))

    if tls_cert and tls_key:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.options |= ssl.OP_NO_COMPRESSION
            ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
            ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        except Exception:
            httpd.server_close()
            raise

    return httpd


def run_server(
    *,
    on_bound: Callable[[BlazeServer], None] | None = None,
    **kwargs: Any,
) -> None:
    """Run BlazeServer with restorable signal handling and request-thread draining."""
    httpd = create_server(**kwargs)
    previous_handlers: dict[int, Any] = {}

    def _shutdown_signal(signum: int, frame: Any) -> None:
        threading.Thread(target=httpd.shutdown, name="blazeserve-shutdown").start()

    def _install_shutdown_handler(signum: int) -> None:
        try:
            previous = signal.getsignal(signum)
            signal.signal(signum, _shutdown_signal)
        except (OSError, RuntimeError, ValueError):
            return
        previous_handlers[signum] = previous

    try:
        if on_bound is not None:
            on_bound(httpd)

        _install_shutdown_handler(signal.SIGINT)
        if hasattr(signal, "SIGTERM"):
            _install_shutdown_handler(signal.SIGTERM)

        httpd.serve_forever()
    finally:
        for signum, previous in previous_handlers.items():
            with contextlib.suppress(OSError, RuntimeError, ValueError):
                signal.signal(signum, previous)
        httpd.server_close()


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct argument parser for backwards-compatible legacy invocations."""
    p = argparse.ArgumentParser(add_help=True, prog="blaze (legacy)")
    sub = p.add_subparsers(dest="cmd")
    serve = sub.add_parser("serve", help="Serve path")
    serve.add_argument("path", nargs="?", default=".")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("-p", "--port", type=int, default=8000)
    serve.add_argument("--single")
    serve.add_argument("--no-listing", action="store_true")
    serve.add_argument("--chunk-mb", type=int, default=DEFAULT_CHUNK_MB)
    serve.add_argument("--sock-sndbuf-mb", type=int, default=DEFAULT_SNDBUF_MB)
    serve.add_argument("--timeout", type=int, default=1800)
    serve.add_argument("--rate-mbps", type=float, default=None)
    serve.add_argument("--auth", default=None)
    serve.add_argument("--tls-cert", default=None)
    serve.add_argument("--tls-key", default=None)
    send = sub.add_parser("send", help="Send single file")
    send.add_argument("file")
    send.add_argument("--host", default="0.0.0.0")
    send.add_argument("-p", "--port", type=int, default=8000)
    send.add_argument("--rate-mbps", type=float, default=None)
    send.add_argument("--auth", default=None)
    send.add_argument("--tls-cert", default=None)
    send.add_argument("--tls-key", default=None)
    chk = sub.add_parser("checksum", help="SHA256")
    chk.add_argument("files", nargs="+")
    return p


__all__ = [
    "BlazeHandler",
    "BlazeServer",
    "DEFAULT_CHUNK_MB",
    "DEFAULT_SNDBUF_MB",
    "RECVBUF_MB",
    "ServerMetrics",
    "TokenBucket",
    "_RateLimiter",
    "_etag_for_stat",
    "_http_date",
    "_parse_range_header",
    "create_server",
    "run_server",
    "build_arg_parser",
]
