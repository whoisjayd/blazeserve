import base64
import hashlib
import http.server
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

import blazeserve


@pytest.fixture
def site(tmp_path):
    (tmp_path / "hello.txt").write_bytes(b"hello blaze")
    (tmp_path / "big.bin").write_bytes(bytes(range(256)) * 4096)
    return tmp_path


def fetch(url, headers=None):
    request = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.headers, response.read()


def test_serves_files_and_stops(site):
    with blazeserve.Server(site) as server:
        assert server.running
        assert server.port > 0
        status, _, body = fetch(server.url + "hello.txt")
        assert (status, body) == (200, b"hello blaze")
    assert not server.running
    with pytest.raises(urllib.error.URLError):
        fetch(server.url + "hello.txt")


def test_range_request(site):
    with blazeserve.Server(site) as server:
        status, headers, body = fetch(server.url + "big.bin", {"Range": "bytes=10-19"})
    assert status == 206
    assert headers["Content-Range"] == f"bytes 10-19/{4096 * 256}"
    assert body == bytes(range(10, 20))


def test_single_file(site):
    with blazeserve.Server(site / "hello.txt") as server:
        assert fetch(server.url)[2] == b"hello blaze"


def test_basic_auth(site):
    with blazeserve.Server(site, auth="ada:secret") as server:
        with pytest.raises(urllib.error.HTTPError) as denied:
            fetch(server.url + "hello.txt")
        assert denied.value.code == 401
        token = base64.b64encode(b"ada:secret").decode()
        status, _, body = fetch(server.url + "hello.txt", {"Authorization": f"Basic {token}"})
        assert (status, body) == (200, b"hello blaze")


def test_close_is_idempotent(site):
    server = blazeserve.Server(site)
    server.close()
    server.close()
    assert not server.running


def test_configuration_errors_are_blaze_errors(site, tmp_path):
    with pytest.raises(blazeserve.BlazeError):
        blazeserve.Server(tmp_path / "missing")
    with pytest.raises(blazeserve.BlazeError):
        blazeserve.Server(site, auth="no-colon")
    with pytest.raises(blazeserve.BlazeError):
        blazeserve.Server(site, tls_cert=site / "hello.txt")


def test_sha256_matches_hashlib(site):
    expected = hashlib.sha256((site / "big.bin").read_bytes()).hexdigest()
    assert blazeserve.sha256(site / "big.bin") == expected
    with pytest.raises(FileNotFoundError):
        blazeserve.sha256(site / "missing")


def test_main_runs_the_cli(capfd):
    assert blazeserve.main(["version", "--json"]) == 0
    assert json.loads(capfd.readouterr().out)["version"] == blazeserve.__version__
    assert blazeserve.main(["serve", "--port", "0"]) == 2


@pytest.fixture
def release_origin(monkeypatch):
    """A loopback stand-in for the release server that reports version 9.9.9."""
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/api/releases/latest":
                body = b'{"tag_name": "v9.9.9", "draft": false, "prerelease": false}'
                self.send_response(200)
            else:
                body = b"not found"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{origin.server_port}"
    monkeypatch.setenv("BLAZE_UPGRADE_API", base + "/api")
    monkeypatch.setenv("BLAZE_UPGRADE_DOWNLOADS", base + "/dl")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    try:
        yield requests
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join()


def test_upgrade_check_returns_a_report(release_origin):
    report = blazeserve.upgrade(check=True)
    assert report["current"] == blazeserve.__version__
    assert report["latest"] == "9.9.9"
    assert report["update_available"] is True
    assert report["channel"] == "pip"
    assert release_origin == ["/api/releases/latest"]


def test_upgrade_without_yes_is_refused_before_any_request(release_origin):
    with pytest.raises(blazeserve.BlazeError, match="--yes"):
        blazeserve.upgrade(check=False)
    assert release_origin == []


def test_upgrade_sets_the_interpreter_only_while_it_runs(release_origin, monkeypatch):
    monkeypatch.delenv("BLAZE_PYTHON", raising=False)
    blazeserve.upgrade(check=True)
    assert "BLAZE_PYTHON" not in os.environ


def test_blaze_upgrade_check_through_main_and_module(release_origin, capfd):
    assert blazeserve.main(["upgrade", "--check", "--json"]) == 0
    assert json.loads(capfd.readouterr().out)["update_available"] is True
    result = subprocess.run(
        [sys.executable, "-m", "blazeserve", "upgrade", "--check", "--json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["latest"] == "9.9.9"
