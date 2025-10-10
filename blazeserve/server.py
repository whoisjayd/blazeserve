from __future__ import annotations

import argparse
import email.utils
import hashlib
import io
import json
import mimetypes
import mmap
import os
import socket
import ssl
import time
import zipfile
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any, BinaryIO, Dict, IO, List, Optional, Tuple, cast
from urllib.parse import urlparse, unquote, parse_qs

DEFAULT_SNDBUF_MB = 64
DEFAULT_CHUNK_MB = 128
RECVBUF_MB = 32


def _etag_for_stat(st: os.stat_result) -> str:
    h = hashlib.sha1()
    h.update(str(st.st_size).encode())
    h.update(str(int(st.st_mtime)).encode())
    return '"' + h.hexdigest()[:20] + '"'


def _http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def _parse_range_header(
    rh: Optional[str], size: int
) -> Optional[List[Tuple[int, int]]]:
    if not rh or not rh.startswith("bytes="):
        return None
    out: List[Tuple[int, int]] = []
    for part in rh[6:].split(","):
        part = part.strip()
        if not part or "-" not in part:
            return None
        s, e = part.split("-", 1)
        if s == "":
            try:
                n = int(e)
            except Exception:
                return None
            if n <= 0:
                return None
            start = max(0, size - n)
            end = size - 1
        else:
            try:
                start = int(s)
                end = int(e) if e else size - 1
            except Exception:
                return None
            if start >= size:
                return None
            if end >= size:
                end = size - 1
            if end < start:
                return None
        out.append((start, end))
    return out or None


class _RateLimiter:
    def __init__(self, rate_bps: Optional[float]) -> None:
        self.rate = rate_bps or 0.0
        self.tokens = float(self.rate)
        self.last = time.perf_counter()

    def take(self, n: int) -> int:
        if self.rate <= 0:
            return n
        while True:
            now = time.perf_counter()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                wait_for = max(0.0, (1 - self.tokens) / self.rate)
                time.sleep(wait_for)
                continue
            allowed = min(float(n), self.tokens)
            send = min(n, max(1, int(allowed)))
            self.tokens = max(0.0, self.tokens - send)
            return send


class BlazeServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    request_queue_size = 4096
    allow_reuse_address = True
    block_on_close = False
    tcp_sendbuf = DEFAULT_SNDBUF_MB * 1024 * 1024
    conn_timeout = 1800
    bytes_sent: int = 0

    def server_bind(self) -> None:
        s = self.socket
        opts = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.SOL_SOCKET, socket.SO_SNDBUF, self.tcp_sendbuf),
            (socket.SOL_SOCKET, socket.SO_RCVBUF, RECVBUF_MB * 1024 * 1024),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        for lvl, opt, val in opts:
            try:
                s.setsockopt(lvl, opt, val)
            except Exception:
                pass
        super().server_bind()

    def handle_error(self, request, client_address) -> None:
        e = __import__("sys").exc_info()[1]
        if isinstance(
            e, (BrokenPipeError, ConnectionResetError, TimeoutError, OSError)
        ):
            return
        return super().handle_error(request, client_address)


class BlazeHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    BASE = "."
    WINDOW = DEFAULT_CHUNK_MB * 1024 * 1024
    SINGLE: Optional[str] = None
    LISTING = True
    AUTH_PAIR: Optional[Tuple[str, str]] = None
    RATE_BPS: Optional[float] = None
    CORS = False
    CORS_ORIGIN = "*"
    NOCACHE = False
    INDEX: List[str] = []
    PRECOMPRESS = True
    MAX_UPLOAD = 0
    _buf: Optional[bytearray] = None
    server: BlazeServer

    def __init__(self, *a, **k):
        super().__init__(*a, directory=self.BASE, **k)

    def log_message(self, *a, **k):
        pass

    def setup(self) -> None:
        super().setup()
        s = self.connection
        try:
            s.settimeout(self.server.conn_timeout)
        except Exception:
            pass
        for args in [
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_SNDBUF, self.server.tcp_sendbuf),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]:
            try:
                s.setsockopt(*args)
            except Exception:
                pass
        if self._buf is None:
            self._buf = bytearray(self.WINDOW)

    def do_OPTIONS(self):
        if not self.CORS:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        if not self._auth_ok():
            return
        parsed = urlparse(self.path)
        if parsed.path in (
            "/__stats__",
            "/__speed__",
            "/__zip__",
            "/__upload__",
            "/__health__",
        ):
            self.send_response(HTTPStatus.OK)
            self._cors_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        f, extra = self._prepare(head_only=True)
        if f:
            try:
                f.close()
            except Exception:
                pass

    def do_GET(self):
        if not self._auth_ok():
            return
        parsed = urlparse(self.path)
        p = parsed.path
        if p == "/__health__":
            return self._health()
        if p == "/__stats__":
            return self._stats()
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
                self._send_range(
                    f, extra["start"], extra["end"], extra.get("full", False)
                )
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass
        finally:
            try:
                f.close()
            except Exception:
                pass

    def do_PUT(self):
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
        if os.path.exists(dst):
            self.send_error(HTTPStatus.CONFLICT)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except Exception:
            self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return
        if self.MAX_UPLOAD > 0 and length > self.MAX_UPLOAD:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        try:
            with open(dst, "wb", buffering=0) as out:
                remain = length
                buf = self._buf or bytearray(self.WINDOW)
                mv = memoryview(buf)
                while remain > 0:
                    n = self.rfile.readinto(mv[: min(remain, len(buf))])
                    if not n:
                        break
                    out.write(mv[:n])
                    remain -= n
        except Exception:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self.send_response(HTTPStatus.CREATED)
        self._cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        return self.do_PUT()

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
        self.send_header("WWW-Authenticate", 'Basic realm="blazeserve"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _prepare(self, head_only: bool) -> Tuple[Optional[BinaryIO], Dict[str, Any]]:
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
                    listing = super().list_directory(path)
                    return cast(Optional[BinaryIO], listing), {"mode": "passthrough"}
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
        f = cast(BinaryIO, open(path, "rb", buffering=0))
        st = os.fstat(f.fileno())
        size = st.st_size
        ctype = (
            mimetypes.guess_type(path[:-3] if use_gzip else path)[0]
            or "application/octet-stream"
        )
        etag = _etag_for_stat(st)
        lastmod = _http_date(st.st_mtime)
        ranges = _parse_range_header(self.headers.get("Range"), size)
        ifr = self.headers.get("If-Range")
        if ifr and ranges:
            ok = False
            if ifr.startswith("W/") or ifr.startswith('"'):
                ok = ifr == etag
            else:
                try:
                    ok = email.utils.parsedate_to_datetime(ifr).timestamp() == int(
                        st.st_mtime
                    )
                except Exception:
                    ok = False
            if not ok:
                ranges = None
        code = HTTPStatus.OK if not ranges else HTTPStatus.PARTIAL_CONTENT
        self.send_response(code)
        self._cors_headers()
        cache_hdr = (
            "no-store" if self.NOCACHE else "public, max-age=31536000, immutable"
        )
        self.send_header("Cache-Control", cache_hdr)
        self.send_header("Connection", "keep-alive")
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
            self.send_header(
                "Vary", "Origin, Accept-Encoding" if self.CORS else "Accept-Encoding"
            )
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
        parts: List[Tuple[bytes, int, int]] = []
        total_len = 0
        CRLF = b"\r\n"
        b_boundary = ("--" + boundary + "\r\n").encode()
        b_close = ("--" + boundary + "--\r\n").encode()
        for start, end in ranges:
            h = (
                b_boundary
                + f"Content-Type: {ctype}\r\n".encode()
                + f"Content-Range: bytes {start}-{end}/{size}\r\n\r\n".encode()
            )
            parts.append((h, start, end))
            total_len += len(h) + (end - start + 1) + len(CRLF)
        total_len += len(b_close)
        self.send_header("Content-Type", f"multipart/byteranges; boundary={boundary}")
        self.send_header("Content-Length", str(total_len))
        self.end_headers()
        if head_only:
            f.close()
            return None, {}
        return f, {"mode": "multipart", "parts": parts, "close": b_close}

    def _cors_headers(self) -> None:
        if not self.CORS:
            return
        self.send_header("Access-Control-Allow-Origin", self.CORS_ORIGIN)
        self.send_header(
            "Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, PUT, POST"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Range, Content-Type, Authorization"
        )
        self.send_header(
            "Access-Control-Expose-Headers",
            "Accept-Ranges, Content-Length, Content-Range, ETag",
        )

    def _send_range(self, f, start: int, end: int, full: bool) -> None:
        s = self.connection
        total = end - start + 1
        limiter = _RateLimiter(self.RATE_BPS)
        if full and start == 0 and hasattr(s, "sendfile"):
            try:
                sent = s.sendfile(f, offset=0, count=total)
                if sent is None or sent == total:
                    try:
                        self.server.bytes_sent += total
                    except Exception:
                        pass
                    return
            except (OSError, AttributeError):
                pass
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
                with mmap.mmap(
                    f.fileno(), length=mlen, access=mmap.ACCESS_READ, offset=base
                ) as mm:
                    view = memoryview(mm)[delta : delta + min(rem, mlen - delta)]
                    off = 0
                    while off < len(view):
                        to_send = limiter.take(len(view) - off)
                        if to_send <= 0:
                            continue
                        try:
                            s.sendall(view[off : off + to_send])
                        except (
                            BrokenPipeError,
                            ConnectionResetError,
                            TimeoutError,
                            OSError,
                        ):
                            return
                        off += to_send
                        try:
                            self.server.bytes_sent += to_send
                        except Exception:
                            pass
                    n = len(view)
                    pos += n
                    rem -= n
            if rem == 0:
                return
        except Exception:
            pass
        buf = self._buf or bytearray(self.WINDOW)
        mv = memoryview(buf)
        f.seek(pos)
        while rem > 0:
            n = f.readinto(mv[: min(len(buf), rem)])
            if not n:
                break
            off = 0
            while off < n:
                to_send = limiter.take(n - off)
                if to_send <= 0:
                    continue
                try:
                    s.sendall(mv[off : off + to_send])
                except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                    return
                off += to_send
                try:
                    self.server.bytes_sent += to_send
                except Exception:
                    pass
            rem -= n

    def _send_multipart(self, f, extra: Dict) -> None:
        s = self.connection
        limiter = _RateLimiter(self.RATE_BPS)
        for hdr, start, end in extra["parts"]:
            try:
                s.sendall(hdr)
            except Exception:
                return
            self._send_range(f, start, end, full=False)
            chunk = b"\r\n"
            off = 0
            while off < len(chunk):
                to_send = limiter.take(len(chunk) - off)
                if to_send <= 0:
                    continue
                try:
                    s.sendall(chunk[off : off + to_send])
                except Exception:
                    return
                off += to_send
                try:
                    self.server.bytes_sent += to_send
                except Exception:
                    pass
        closing = extra["close"]
        off = 0
        while off < len(closing):
            to_send = limiter.take(len(closing) - off)
            if to_send <= 0:
                continue
            try:
                s.sendall(closing[off : off + to_send])
            except Exception:
                return
            off += to_send
            try:
                self.server.bytes_sent += to_send
            except Exception:
                pass

    def _health(self) -> None:
        body = json.dumps({"status": "ok"}).encode()
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _stats(self) -> None:
        body = json.dumps(
            {"bytes_sent": getattr(self.server, "bytes_sent", 0)}
        ).encode()
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _speed(self, parsed) -> None:
        q = parse_qs(parsed.query or "")
        total = int(q.get("bytes", ["100000000"])[0])
        chunk = min(self.WINDOW, 4 * 1024 * 1024)
        zeros = b"\0" * chunk
        limiter = _RateLimiter(self.RATE_BPS)
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(total))
        self.end_headers()
        sent = 0
        try:
            while sent < total:
                n = min(chunk, total - sent)
                off = 0
                while off < n:
                    to_send = limiter.take(n - off)
                    if to_send <= 0:
                        continue
                    self.wfile.write(zeros[off : off + to_send])
                    off += to_send
                    sent += to_send
                    try:
                        self.server.bytes_sent += to_send
                    except Exception:
                        pass
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            pass

    def _zip(self, parsed) -> None:
        q = parse_qs(parsed.query or "")
        raw = q.get("path", [""])[0]
        if not raw:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        path = os.path.abspath(os.path.join(self.BASE, raw))
        if not os.path.exists(path):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self._cors_headers()
        self.send_header("Content-Type", "application/zip")
        name = os.path.basename(path.rstrip(os.sep)) or "archive"
        self.send_header("Content-Disposition", f'attachment; filename="{name}.zip"')
        self.end_headers()

        class _Stream(io.RawIOBase):
            def __init__(self, outer: "BlazeHandler"):
                self.outer = outer

            def writable(self) -> bool:
                return True

            def write(self, b: Any) -> int:
                chunk = bytes(b)
                try:
                    self.outer.wfile.write(chunk)
                    self.outer.server.bytes_sent += len(chunk)
                except Exception:
                    pass
                return len(chunk)

            def close(self) -> None:  # pragma: no cover - nothing to close
                return

        stream = _Stream(self)
        z = zipfile.ZipFile(
            cast(IO[bytes], stream),
            "w",
            compression=zipfile.ZIP_STORED,
            allowZip64=True,
        )
        try:
            if os.path.isdir(path):
                base_dir = path
                for root, _, files in os.walk(path):
                    for fn in files:
                        ap = os.path.join(root, fn)
                        arc = os.path.relpath(ap, base_dir)
                        try:
                            z.write(ap, arcname=arc)
                        except Exception:
                            continue
            else:
                z.write(path, arcname=os.path.basename(path))
        finally:
            try:
                z.close()
            except Exception:
                pass


def build_arg_parser() -> argparse.ArgumentParser:
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


def run_server(
    *,
    host: str,
    port: int,
    base: str,
    single: Optional[str],
    listing: bool,
    chunk_mb: int,
    sndbuf_mb: int,
    timeout: int,
    rate_mbps: Optional[float],
    auth: Optional[str],
    tls_cert: Optional[str],
    tls_key: Optional[str],
    cors: bool = False,
    cors_origin: str = "*",
    no_cache: bool = False,
    index: Optional[List[str]] = None,
    backlog: int = 4096,
    precompress: bool = True,
    max_upload_mb: int = 0,
    verbose: bool = False,
) -> None:
    BlazeHandler.BASE = base
    BlazeHandler.WINDOW = max(4, int(chunk_mb)) * 1024 * 1024
    BlazeHandler.SINGLE = single
    BlazeHandler.LISTING = listing
    BlazeHandler.RATE_BPS = (rate_mbps * 1024 * 1024) if rate_mbps else None
    BlazeHandler.CORS = bool(cors)
    BlazeHandler.CORS_ORIGIN = cors_origin or "*"
    BlazeHandler.NOCACHE = bool(no_cache)
    BlazeHandler.INDEX = list(index or [])
    BlazeHandler.PRECOMPRESS = bool(precompress)
    BlazeHandler.MAX_UPLOAD = max(0, int(max_upload_mb)) * 1024 * 1024
    if auth:
        if ":" not in auth:
            raise SystemExit("Auth must be USER:PASS")
        user, pw = auth.split(":", 1)
        BlazeHandler.AUTH_PAIR = (user, pw)
    else:
        BlazeHandler.AUTH_PAIR = None
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET

    class _S(BlazeServer):
        pass

    _S.address_family = fam
    httpd = _S((host, port), BlazeHandler)
    httpd.tcp_sendbuf = max(256 * 1024, int(sndbuf_mb) * 1024 * 1024)
    httpd.conn_timeout = max(60, int(timeout))
    httpd.request_queue_size = max(1, int(backlog))
    if tls_cert and tls_key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()
