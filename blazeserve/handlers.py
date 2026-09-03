"""HTTP request handler for BlazeServe with optimized I/O paths and operational endpoints."""

from __future__ import annotations

import contextlib
import email.utils
import hashlib
import io
import json
import mimetypes
import mmap
import os
import socket
import ssl
import sys
import time
import zipfile
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from typing import IO, Any, BinaryIO, cast
from urllib.parse import parse_qs, unquote, urlparse

from blazeserve import __version__
from blazeserve.limiter import TokenBucket
from blazeserve.security import generate_request_id, is_safe_path
from blazeserve.ui import render_directory_index

DEFAULT_CHUNK_MB = 256
DEFAULT_SNDBUF_MB = 128


def _etag_for_stat(st: os.stat_result) -> str:
    """Compute an ETag string based on mtime, size, and inode."""
    h = hashlib.sha1()
    h.update(f"{st.st_mtime}-{st.st_size}-{st.st_ino}".encode())
    return '"' + h.hexdigest()[:20] + '"'


def _http_date(ts: float) -> str:
    """Format timestamp as GMT HTTP date."""
    return email.utils.formatdate(ts, usegmt=True)


def _parse_range_header(rh: str | None, size: int) -> list[tuple[int, int]] | None:
    """Parse HTTP Range header per RFC 7233."""
    if not rh or not rh.startswith("bytes="):
        return None
    spec = rh[6:].strip()
    if not spec:
        return None
    out: list[tuple[int, int]] = []
    for part in spec.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" not in p:
            return None
        s_str, e_str = p.split("-", 1)
        if s_str == "":
            if e_str == "":
                return None
            try:
                n = int(e_str)
            except ValueError:
                return None
            if n <= 0:
                continue
            start = max(0, size - n)
            end = size - 1
        else:
            try:
                start = int(s_str)
            except ValueError:
                return None
            if e_str == "":
                end = size - 1
            else:
                try:
                    end = int(e_str)
                except ValueError:
                    return None
        if start < 0 or start >= size or end < start:
            continue
        end = min(end, size - 1)
        out.append((start, end))
    return out or None


class BlazeHandler(SimpleHTTPRequestHandler):
    """High-performance HTTP request handler."""

    protocol_version = "HTTP/1.1"
    BASE: str = "."
    WINDOW: int = DEFAULT_CHUNK_MB * 1024 * 1024
    SINGLE: str | None = None
    LISTING: bool = True
    AUTH_PAIR: tuple[str, str] | None = None
    RATE_BPS: float | None = None
    CORS: bool = False
    CORS_ORIGIN: str = "*"
    NOCACHE: bool = False
    INDEX: list[str] = []
    PRECOMPRESS: bool = True
    MAX_UPLOAD: int = 0
    LOG_JSON: bool = False
    ZIP_COMPRESSION: int = zipfile.ZIP_STORED
    _buf: bytearray | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=self.BASE, **kwargs)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Override logging to support structured JSON output when configured."""
        if self.LOG_JSON or os.environ.get("BLAZE_LOG_JSON") == "1":
            req_line = args[0] if args else "-"
            code = args[1] if len(args) > 1 else "-"
            size = args[2] if len(args) > 2 else "-"
            log_obj = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "INFO",
                "request_id": getattr(self, "request_id", "-"),
                "client_ip": self.client_address[0] if hasattr(self, "client_address") else "-",
                "request": req_line,
                "status": code,
                "size": size,
            }
            sys.stdout.write(json.dumps(log_obj) + "\n")
            sys.stdout.flush()

    def setup(self) -> None:
        """Setup connection with optimized socket parameters and correlation ID."""
        super().setup()
        s = self.connection
        self.request_id = generate_request_id(self.headers.get("X-Request-ID") if hasattr(self, "headers") else None)

        # Track active requests in metrics
        if hasattr(self.server, "metrics") and self.server.metrics:
            self.server.metrics.increment_requests_active()

        with contextlib.suppress(OSError, AttributeError):
            s.settimeout(getattr(self.server, "conn_timeout", 60))

        # Apply TCP socket optimizations
        opts = [
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_SNDBUF, getattr(self.server, "tcp_sendbuf", 128 * 1024 * 1024)),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        if hasattr(socket, "TCP_QUICKACK") and sys.platform.startswith("linux"):
            opts.append((socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1))
        for lvl, opt, val in opts:
            with contextlib.suppress(OSError, AttributeError):
                s.setsockopt(lvl, opt, val)

        if self._buf is None:
            self._buf = bytearray(self.WINDOW)

    def finish(self) -> None:
        """Clean up connection and update server telemetry."""
        try:
            if hasattr(self.server, "metrics") and self.server.metrics:
                self.server.metrics.increment_requests_total()
                self.server.metrics.decrement_requests_active()
        except Exception:
            pass

        with contextlib.suppress(BrokenPipeError, ConnectionResetError, OSError):
            super().finish()

    def do_OPTIONS(self) -> None:
        if not self.CORS:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:
        if not self._auth_ok():
            return
        parsed = urlparse(self.path)
        if parsed.path in (
            "/__stats__",
            "/__speed__",
            "/__zip__",
            "/__upload__",
            "/__health__",
            "/__perf__",
            "/__live__",
            "/__ready__",
            "/__version__",
            "/__metrics__",
            "/metrics",
        ):
            self.send_response(HTTPStatus.OK)
            self._cors_headers()
            self._send_security_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        f, extra = self._prepare(head_only=True)
        if f:
            with contextlib.suppress(Exception):
                f.close()

    def do_GET(self) -> None:
        if not self._auth_ok():
            return
        parsed = urlparse(self.path)
        p = parsed.path
        if p == "/__health__":
            return self._health()
        if p == "/__live__":
            return self._live()
        if p == "/__ready__":
            return self._ready()
        if p == "/__version__":
            return self._version()
        if p in ("/__metrics__", "/metrics"):
            return self._metrics()
        if p == "/__stats__":
            return self._stats()
        if p == "/__perf__":
            return self._perf()
        if p == "/__speed__":
            return self._speed(parsed)
        if p == "/__zip__":
            return self._zip(parsed)

        f, extra = self._prepare(head_only=False)
        if f is None:
            return
        try:
            mode = extra.get("mode", "range")
            if mode == "multipart":
                self._send_multipart(f, extra)
            elif mode == "passthrough":
                self.copyfile(f, self.wfile)
            else:
                self._send_range(f, extra["start"], extra["end"], extra.get("full", False))
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                f.close()

    def do_PUT(self) -> None:
        """Secure file upload handler."""
        if not self._auth_ok():
            return
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/__upload__/"):
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return

        fn = unquote(parsed.path[len("/__upload__/") :]).strip("/\\")
        if not fn:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        dst = os.path.abspath(os.path.join(self.BASE, fn))
        if not is_safe_path(self.BASE, dst):
            self.send_error(HTTPStatus.FORBIDDEN)
            return

        if os.path.exists(dst):
            self.send_error(HTTPStatus.CONFLICT)
            return

        cl_header = self.headers.get("Content-Length")
        if not cl_header:
            self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return

        try:
            length = int(cl_header)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        if self.MAX_UPLOAD > 0 and length > self.MAX_UPLOAD:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            with open(dst, "wb", buffering=0) as out:
                remain = length
                buf = self._buf or bytearray(self.WINDOW)
                mv = memoryview(buf)
                while remain > 0:
                    chunk_size = min(remain, len(buf))
                    n = self.rfile.readinto(mv[:chunk_size])
                    if not n:
                        break
                    out.write(mv[:n])
                    remain -= n
                    if hasattr(self.server, "metrics") and self.server.metrics:
                        self.server.metrics.increment_bytes_received(n)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(dst)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        self.send_response(HTTPStatus.CREATED)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        return self.do_PUT()

    def _send_security_headers(self) -> None:
        """Inject defense-in-depth security headers on all responses."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
        if hasattr(self.server, "socket") and isinstance(self.server.socket, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        req_id = getattr(self, "request_id", None)
        if req_id:
            self.send_header("X-Request-ID", req_id)
        if self.RATE_BPS:
            self.send_header("X-RateLimit-Limit", str(int(self.RATE_BPS)))

    def _cors_headers(self) -> None:
        if not self.CORS:
            return
        self.send_header("Access-Control-Allow-Origin", self.CORS_ORIGIN)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, PUT, POST")
        self.send_header("Access-Control-Allow-Headers", "Range, Content-Type, Authorization, X-Request-ID")
        self.send_header(
            "Access-Control-Expose-Headers",
            "Accept-Ranges, Content-Length, Content-Range, ETag, Last-Modified, X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining",
        )

    def _auth_ok(self) -> bool:
        if not self.AUTH_PAIR:
            return True
        hdr = self.headers.get("Authorization")
        if not hdr or not hdr.startswith("Basic "):
            self._auth_required()
            return False
        import base64
        try:
            userpass = base64.b64decode(hdr.split(" ", 1)[1]).decode("utf-8")
            user, pw = userpass.split(":", 1)
        except Exception:
            self._auth_required()
            return False
        if (user, pw) != self.AUTH_PAIR:
            self._auth_required()
            return False
        return True

    def _auth_required(self) -> None:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("WWW-Authenticate", 'Basic realm="blazeserve"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def list_directory(self, path: str | os.PathLike[str]) -> io.BytesIO | None:
        """Override directory listing to render modern responsive HTML5 index."""
        str_path = os.fspath(path)
        try:
            entries = list(os.scandir(str_path))
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None

        rel_path = os.path.relpath(str_path, self.BASE)
        if rel_path == ".":
            rel_path = ""
        encoded = render_directory_index(str_path, rel_path, entries, allow_upload=(self.MAX_UPLOAD > 0))
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        return f

    def _prepare(self, head_only: bool) -> tuple[BinaryIO | None, dict[str, Any]]:
        """Validate path, handle RFC conditional requests, and configure response."""
        if self.SINGLE:
            path = self.SINGLE
        else:
            urlp = urlparse(self.path)
            path = unquote(self.translate_path(urlp.path))
            if os.path.isdir(path):
                if not self.LISTING:
                    self.send_error(HTTPStatus.FORBIDDEN)
                    return None, {}
                for idx in ["index.html", "index.htm", *self.INDEX]:
                    idxp = os.path.join(path, idx)
                    if os.path.isfile(idxp):
                        path = idxp
                        break
                else:
                    listing = self.list_directory(path)
                    return cast(BinaryIO | None, listing), {"mode": "passthrough"}

        if not os.path.exists(path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return None, {}
        if not os.path.isfile(path):
            self.send_error(HTTPStatus.FORBIDDEN)
            return None, {}

        accept_enc = (self.headers.get("Accept-Encoding") or "").lower()
        wants_gzip = "gzip" in accept_enc
        use_gzip = False
        if self.PRECOMPRESS and wants_gzip:
            gz = path + ".gz"
            if os.path.isfile(gz) and not self.headers.get("Range"):
                path = gz
                use_gzip = True

        f = cast(BinaryIO, open(path, "rb", buffering=0))  # noqa: SIM115
        st = os.fstat(f.fileno())
        size = st.st_size
        ctype = (
            mimetypes.guess_type(path[:-3] if use_gzip else path)[0] or "application/octet-stream"
        )
        etag = _etag_for_stat(st)
        lastmod = _http_date(st.st_mtime)

        # RFC 7232: If-None-Match conditional check
        inm = self.headers.get("If-None-Match")
        if inm:
            tokens = [t.strip() for t in inm.split(",")]
            if "*" in tokens or etag in tokens or etag.strip('"') in tokens:
                self.send_response(HTTPStatus.NOT_MODIFIED)
                self._cors_headers()
                self._send_security_headers()
                self.send_header("ETag", etag)
                self.send_header("Last-Modified", lastmod)
                cache_hdr = "no-cache, no-store, must-revalidate" if self.NOCACHE else "public, max-age=3600"
                self.send_header("Cache-Control", cache_hdr)
                self.end_headers()
                f.close()
                return None, {}

        # RFC 7232: If-Modified-Since conditional check
        ims = self.headers.get("If-Modified-Since")
        if ims and not self.headers.get("Range"):
            try:
                ims_dt = email.utils.parsedate_to_datetime(ims)
                if int(st.st_mtime) <= int(ims_dt.timestamp()):
                    self.send_response(HTTPStatus.NOT_MODIFIED)
                    self._cors_headers()
                    self._send_security_headers()
                    self.send_header("ETag", etag)
                    self.send_header("Last-Modified", lastmod)
                    cache_hdr = "no-cache, no-store, must-revalidate" if self.NOCACHE else "public, max-age=3600"
                    self.send_header("Cache-Control", cache_hdr)
                    self.end_headers()
                    f.close()
                    return None, {}
            except Exception:
                pass

        ranges = _parse_range_header(self.headers.get("Range"), size)
        ifr = self.headers.get("If-Range")
        if ifr and ranges:
            ok = False
            if ifr.startswith("W/") or ifr.startswith('"'):
                ok = ifr == etag
            else:
                try:
                    ok = email.utils.parsedate_to_datetime(ifr).timestamp() == int(st.st_mtime)
                except Exception:
                    ok = False
            if not ok:
                ranges = None

        code = HTTPStatus.OK if not ranges else HTTPStatus.PARTIAL_CONTENT
        self.send_response(code)
        self._cors_headers()
        self._send_security_headers()
        cache_hdr = "no-cache, no-store, must-revalidate" if self.NOCACHE else "public, max-age=3600"
        self.send_header("Cache-Control", cache_hdr)
        self.send_header("Connection", "keep-alive")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Vary", "Origin, Accept-Encoding" if self.CORS else "Accept-Encoding")
        elif self.CORS:
            self.send_header("Vary", "Origin")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("ETag", etag)
        self.send_header("Last-Modified", lastmod)

        if not ranges:
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if head_only:
                f.close()
                return None, {}
            return f, {"mode": "range", "start": 0, "end": size - 1, "full": True}

        if len(ranges) == 1:
            start, end = ranges[0]
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(end - start + 1))
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if head_only:
                f.close()
                return None, {}
            return f, {
                "mode": "range",
                "start": start,
                "end": end,
                "full": (start == 0 and end == size - 1),
            }

        boundary = "RANGE_" + etag.strip('"')[:16]
        parts: list[tuple[bytes, int, int]] = []
        total_len = 0
        crlf = b"\r\n"
        b_boundary = ("--" + boundary + "\r\n").encode()
        b_close = ("--" + boundary + "--\r\n").encode()
        for start, end in ranges:
            h = (
                b_boundary
                + f"Content-Type: {ctype}\r\n".encode()
                + f"Content-Range: bytes {start}-{end}/{size}\r\n\r\n".encode()
            )
            parts.append((h, start, end))
            total_len += len(h) + (end - start + 1) + len(crlf)
        total_len += len(b_close)
        self.send_header("Content-Type", f"multipart/byteranges; boundary={boundary}")
        self.send_header("Content-Length", str(total_len))
        self.end_headers()
        if head_only:
            f.close()
            return None, {}
        return f, {"mode": "multipart", "parts": parts, "close": b_close}

    def _send_range(self, f: BinaryIO, start: int, end: int, full: bool) -> None:
        """Optimized range sender with zero-copy sendfile and memory-safe mmap."""
        s = self.connection
        total = end - start + 1
        limiter = TokenBucket(self.RATE_BPS) if self.RATE_BPS else None

        # Fast path 1: Zero-copy sendfile
        if full and start == 0 and hasattr(s, "sendfile"):
            try:
                offset = 0
                remaining = total
                if limiter:
                    while remaining > 0:
                        chunk_size = limiter.take(min(remaining, self.WINDOW))
                        sent = s.sendfile(f, offset=offset, count=chunk_size)
                        if sent is None or sent == 0:
                            break
                        offset += sent
                        remaining -= sent
                        if hasattr(self.server, "metrics") and self.server.metrics:
                            self.server.metrics.increment_bytes_sent(sent)
                else:
                    sent = s.sendfile(f, offset=0, count=total)
                    if sent is not None:
                        if hasattr(self.server, "metrics") and self.server.metrics:
                            self.server.metrics.increment_bytes_sent(sent)
                        if sent == total:
                            return
                        remaining = total - sent
                        offset = sent
                if remaining == 0:
                    return
            except (OSError, AttributeError):
                pass

        # Fast path 2: Safe memory-mapped I/O
        ag = getattr(mmap, "ALLOCATIONGRANULARITY", 4096)
        win = self.WINDOW
        size = os.fstat(f.fileno()).st_size
        pos = start
        rem = total

        try:
            while rem > 0:
                base = (pos // ag) * ag
                delta = pos - base
                mlen = min(win + delta, size - base)
                if mlen <= 0:
                    break

                mm = mmap.mmap(f.fileno(), length=mlen, access=mmap.ACCESS_READ, offset=base)
                try:
                    view = memoryview(mm)[delta : delta + min(rem, mlen - delta)]
                    try:
                        off = 0
                        while off < len(view):
                            to_send = limiter.take(len(view) - off) if limiter else (len(view) - off)
                            if to_send <= 0:
                                continue
                            try:
                                s.sendall(view[off : off + to_send])
                            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                                return
                            off += to_send
                            if hasattr(self.server, "metrics") and self.server.metrics:
                                self.server.metrics.increment_bytes_sent(to_send)
                        n = len(view)
                        pos += n
                        rem -= n
                    finally:
                        view.release()
                finally:
                    mm.close()
            if rem == 0:
                return
        except (OSError, ValueError, BufferError):
            pass

        # Fallback: Buffered I/O
        f.seek(start)
        rem = total
        buf = self._buf or bytearray(self.WINDOW)
        while rem > 0:
            chunk_size = min(len(buf), rem)
            try:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                to_send = limiter.take(len(chunk)) if limiter else len(chunk)
                s.sendall(chunk[:to_send])
                if hasattr(self.server, "metrics") and self.server.metrics:
                    self.server.metrics.increment_bytes_sent(to_send)
                rem -= len(chunk)
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                return

    def _send_multipart(self, f: BinaryIO, extra: dict[str, Any]) -> None:
        s = self.connection
        limiter = TokenBucket(self.RATE_BPS) if self.RATE_BPS else None
        for hdr, start, end in extra["parts"]:
            try:
                s.sendall(hdr)
            except Exception:
                return
            self._send_range(f, start, end, full=False)
            chunk = b"\r\n"
            off = 0
            while off < len(chunk):
                to_send = limiter.take(len(chunk) - off) if limiter else (len(chunk) - off)
                if to_send <= 0:
                    continue
                try:
                    s.sendall(chunk[off : off + to_send])
                except Exception:
                    return
                off += to_send
                if hasattr(self.server, "metrics") and self.server.metrics:
                    self.server.metrics.increment_bytes_sent(to_send)
        closing = extra["close"]
        try:
            s.sendall(closing)
            if hasattr(self.server, "metrics") and self.server.metrics:
                self.server.metrics.increment_bytes_sent(len(closing))
        except Exception:
            return

    def _send_json(self, code: HTTPStatus, data: dict[str, Any]) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with contextlib.suppress(Exception):
            self.wfile.write(body)

    def _health(self) -> None:
        uptime = int(time.time() - self.server.metrics.start_time) if hasattr(self.server, "metrics") and self.server.metrics else 0
        self._send_json(HTTPStatus.OK, {
            "status": "ok",
            "version": __version__,
            "uptime_seconds": uptime,
        })

    def _live(self) -> None:
        self._send_json(HTTPStatus.OK, {"status": "alive"})

    def _ready(self) -> None:
        ready = os.path.isdir(self.BASE) and os.access(self.BASE, os.R_OK)
        if ready:
            self._send_json(HTTPStatus.OK, {"status": "ready", "base": self.BASE})
        else:
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {
                "status": "not_ready",
                "reason": f"Base directory {self.BASE} is not accessible",
            })

    def _version(self) -> None:
        self._send_json(HTTPStatus.OK, {
            "name": "blazeserve",
            "version": __version__,
            "python": sys.version.split()[0],
            "platform": sys.platform,
        })

    def _metrics(self) -> None:
        metrics = getattr(self.server, "metrics", None)
        content = metrics.to_prometheus() if metrics else "# No metrics available\n"
        body = content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with contextlib.suppress(Exception):
            self.wfile.write(body)

    def _stats(self) -> None:
        self._send_json(HTTPStatus.OK, {
            "bytes_sent": getattr(self.server, "bytes_sent", 0)
        })

    def _perf(self) -> None:
        metrics = getattr(self.server, "metrics", None)
        stats = metrics.get_stats() if metrics else {"bytes_sent": 0, "uptime_seconds": 0}
        stats["config"] = {
            "chunk_size_mb": self.WINDOW // (1024 * 1024),
            "send_buffer_mb": getattr(self.server, "tcp_sendbuf", 0) // (1024 * 1024),
            "backlog": getattr(self.server, "request_queue_size", 4096),
            "timeout_seconds": getattr(self.server, "conn_timeout", 60),
            "rate_limit_mbps": self.RATE_BPS / (1024 * 1024) if self.RATE_BPS else None,
        }
        self._send_json(HTTPStatus.OK, stats)

    def _speed(self, parsed: Any) -> None:
        q = parse_qs(parsed.query or "")
        total = int(q.get("bytes", ["100000000"])[0])
        chunk = min(self.WINDOW, 8 * 1024 * 1024)
        zeros = b"\0" * chunk
        limiter = TokenBucket(self.RATE_BPS) if self.RATE_BPS else None
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        sent = 0
        try:
            while sent < total:
                n = min(chunk, total - sent)
                off = 0
                while off < n:
                    to_send = limiter.take(n - off) if limiter else (n - off)
                    if to_send <= 0:
                        continue
                    self.wfile.write(zeros[off : off + to_send])
                    off += to_send
                    sent += to_send
                    if hasattr(self.server, "metrics") and self.server.metrics:
                        self.server.metrics.increment_bytes_sent(to_send)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass

    def _zip(self, parsed: Any) -> None:
        q = parse_qs(parsed.query or "")
        raw = q.get("path", [""])[0]
        if not raw:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        path = os.path.abspath(os.path.join(self.BASE, raw))
        if not is_safe_path(self.BASE, path):
            self.send_error(HTTPStatus.FORBIDDEN)
            return
        if not os.path.exists(path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self._send_security_headers()
        self.send_header("Content-Type", "application/zip")
        name = os.path.basename(path.rstrip(os.sep)) or "archive"
        self.send_header("Content-Disposition", f'attachment; filename="{name}.zip"')
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        class _Stream(io.RawIOBase):
            def __init__(self, outer: BlazeHandler) -> None:
                self.outer = outer

            def writable(self) -> bool:
                return True

            def write(self, b: Any) -> int:
                chunk = bytes(b)
                try:
                    self.outer.wfile.write(chunk)
                    if hasattr(self.outer.server, "metrics") and self.outer.server.metrics:
                        self.outer.server.metrics.increment_bytes_sent(len(chunk))
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                return len(chunk)

        stream = _Stream(self)
        z = zipfile.ZipFile(cast(IO[bytes], stream), "w", compression=self.ZIP_COMPRESSION, allowZip64=True)
        try:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for fn in files:
                        ap = os.path.join(root, fn)
                        arc = os.path.relpath(ap, path)
                        with contextlib.suppress(OSError):
                            z.write(ap, arcname=arc)
            else:
                z.write(path, arcname=os.path.basename(path))
        finally:
            with contextlib.suppress(Exception):
                z.close()
