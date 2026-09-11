"""Run a deterministic, local BlazeServe contributor smoke flow.

Invoke from a checkout with ``uv run python scripts/contributor_smoke.py``.
The script intentionally exposes no persistent configuration, files, listeners, or
credentials: it creates all state below one temporary directory and binds only
loopback on an operating-system-selected port.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import secrets
import sys
import tempfile
import threading
import time
from http.client import HTTPConnection, HTTPResponse
from pathlib import Path
from typing import Any

from blazeserve.server import create_server

_HOST = "127.0.0.1"
_CLIENT_TIMEOUT_SECONDS = 2.0
_READY_TIMEOUT_SECONDS = 3.0
_POLL_INTERVAL_SECONDS = 0.02

# These payloads and names form the portable logical fixture manifest.  Do not
# add host metadata (timestamps, permissions, or absolute paths) to the result.
_FIXTURES = {
    "static/hello.txt": b"Hello from the BlazeServe contributor smoke fixture.\n",
    "static/nested/note.txt": b"Nested fixture for deterministic local serving.\n",
}
_UPLOAD_PATH = "uploads/contributor-upload.bin"
_UPLOAD_CONTENT = b"Authenticated contributor upload payload.\n"


class SmokeError(RuntimeError):
    """Raised when the smoke flow's observable HTTP contract is not met."""


def build_fixture(root: Path) -> dict[str, dict[str, object]]:
    """Create deterministic fixtures under *root* and return their logical manifest."""
    manifest: dict[str, dict[str, object]] = {}
    for relative_path, content in _FIXTURES.items():
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
        manifest[relative_path] = {
            "path": relative_path,
            "bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    return manifest


def _authorization_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {token}"


def _request(
    host: str,
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    """Make one bounded request and return only status plus response bytes."""
    connection = HTTPConnection(host, port, timeout=_CLIENT_TIMEOUT_SECONDS)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response: HTTPResponse = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _require(
    name: str,
    status: int,
    body: bytes,
    *,
    expected_status: int,
    expected_body: bytes | None = None,
) -> dict[str, object]:
    """Validate a response without retaining sensitive request metadata."""
    if status != expected_status:
        raise SmokeError(f"{name}: expected status {expected_status}, received {status}")
    if expected_body is not None and body != expected_body:
        raise SmokeError(f"{name}: response body did not match the deterministic fixture")
    return {"name": name, "status": status, "bytes": len(body)}


def _wait_until_ready(host: str, port: int, headers: dict[str, str]) -> None:
    """Poll authenticated readiness with a bounded clock deadline."""
    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            status, _ = _request(host, port, "GET", "/__ready__", headers=headers)
            if status == 200:
                return
            last_error = SmokeError(f"readiness probe returned status {status}")
        except (OSError, TimeoutError) as exc:
            last_error = exc
        time.sleep(_POLL_INTERVAL_SECONDS)
    if last_error is None:
        raise SmokeError("readiness probe timed out")
    raise SmokeError("server did not become ready before the bounded deadline") from last_error


def _clear_handler_credentials(server: Any) -> None:
    """Remove the credential tuple held on the generated request handler class."""
    handler = getattr(server, "RequestHandlerClass", None)
    if handler is not None:
        handler.AUTH_PAIR = None


def _sanitized_failure(exc: BaseException) -> dict[str, str]:
    """Return useful diagnostics without echoing dependency exception text."""
    if isinstance(exc, SmokeError):
        detail = str(exc)
    elif isinstance(exc, KeyboardInterrupt):
        detail = "interrupted"
    else:
        detail = f"unexpected {type(exc).__name__}"
    return {"error": "smoke failed", "detail": detail}


def run_smoke() -> dict[str, object]:
    """Run the complete ephemeral smoke flow and return sanitized logical evidence.

    Raises:
        SmokeError: A server startup, response, or body expectation failed.
    """
    server: Any | None = None
    worker: threading.Thread | None = None
    credential = bytearray(secrets.token_urlsafe(24).encode("ascii"))
    username = "contributor"
    result: dict[str, object] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="blazeserve-contributor-smoke-") as temporary_root:
            root = Path(temporary_root)
            manifest = build_fixture(root)
            password = credential.decode("ascii")
            try:
                server = create_server(
                    host=_HOST,
                    port=0,
                    base=str(root),
                    auth=f"{username}:{password}",
                    max_upload_mb=1,
                    timeout=5,
                    log_json=False,
                )
            finally:
                password = ""

            endpoint = f"http://{_HOST}:{server.server_port}"
            auth_headers = {
                "Authorization": _authorization_header(username, credential.decode("ascii"))
            }
            upload_headers: dict[str, str] = {}
            worker = threading.Thread(
                target=server.serve_forever,
                name="blazeserve-contributor-smoke",
                daemon=True,
            )
            worker.start()
            _wait_until_ready(_HOST, server.server_port, auth_headers)

            try:
                scenarios = []
                status, body = _request(
                    _HOST, server.server_port, "GET", "/static/hello.txt", headers=auth_headers
                )
                scenarios.append(
                    _require(
                        "static_get",
                        status,
                        body,
                        expected_status=200,
                        expected_body=_FIXTURES["static/hello.txt"],
                    )
                )

                status, body = _request(
                    _HOST,
                    server.server_port,
                    "GET",
                    "/static/hello.txt",
                    headers={**auth_headers, "Range": "bytes=0-4"},
                )
                scenarios.append(
                    _require(
                        "byte_range", status, body, expected_status=206, expected_body=b"Hello"
                    )
                )

                upload_headers = {**auth_headers, "Content-Length": str(len(_UPLOAD_CONTENT))}
                status, body = _request(
                    _HOST,
                    server.server_port,
                    "PUT",
                    f"/__upload__/{_UPLOAD_PATH}",
                    body=_UPLOAD_CONTENT,
                    headers=upload_headers,
                )
                scenarios.append(
                    _require("authenticated_upload", status, body, expected_status=201)
                )

                status, body = _request(
                    _HOST,
                    server.server_port,
                    "GET",
                    f"/{_UPLOAD_PATH}",
                    headers=auth_headers,
                )
                scenarios.append(
                    _require(
                        "authenticated_readback",
                        status,
                        body,
                        expected_status=200,
                        expected_body=_UPLOAD_CONTENT,
                    )
                )

                status, body = _request(
                    _HOST, server.server_port, "GET", "/__live__", headers=auth_headers
                )
                scenarios.append(_require("live", status, body, expected_status=200))

                status, body = _request(
                    _HOST, server.server_port, "GET", "/__ready__", headers=auth_headers
                )
                scenarios.append(_require("ready", status, body, expected_status=200))
            finally:
                auth_headers.clear()
                upload_headers.clear()
                if server is not None:
                    if worker is not None and worker.is_alive():
                        with contextlib.suppress(Exception):
                            server.shutdown()
                    _clear_handler_credentials(server)
                    with contextlib.suppress(Exception):
                        server.server_close()
                if worker is not None:
                    worker.join(timeout=_CLIENT_TIMEOUT_SECONDS)

            result = {"endpoint": endpoint, "manifest": manifest, "scenarios": scenarios}
    except KeyboardInterrupt:
        raise
    except SmokeError:
        raise
    except BaseException as exc:
        raise SmokeError(f"unexpected {type(exc).__name__}") from None
    finally:
        if server is not None:
            if worker is not None and worker.is_alive():
                with contextlib.suppress(Exception):
                    server.shutdown()
            _clear_handler_credentials(server)
            with contextlib.suppress(Exception):
                server.server_close()
        if worker is not None:
            worker.join(timeout=_CLIENT_TIMEOUT_SECONDS)
        credential.clear()

    if result is None:
        raise SmokeError("smoke flow did not produce a result")
    return result


def main() -> int:
    """Print one sanitized JSON report and return a process exit status."""
    try:
        result = run_smoke()
    except BaseException as exc:
        sys.stderr.write(f"{json.dumps(_sanitized_failure(exc), sort_keys=True)}\n")
        return 1
    sys.stdout.write(f"{json.dumps(result, sort_keys=True)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
