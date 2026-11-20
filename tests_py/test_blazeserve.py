import _thread
import base64
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
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


def test_every_command_is_reachable_and_typed():
    """Fails when a command is added to the program but not to the package's type stubs."""
    source = (pathlib.Path(blazeserve.__file__)).read_text(encoding="utf-8")
    names = blazeserve.commands()
    assert {"serve", "send", "get", "put", "status", "stop", "upgrade"} <= set(names)
    for name in names:
        assert callable(getattr(blazeserve, name)), name
        assert name in dir(blazeserve), name
        assert f"def {name}(" in source, f"add {name} to the TYPE_CHECKING block"
    with pytest.raises(AttributeError):
        blazeserve.no_such_command


def test_options_become_a_command_line():
    line = blazeserve.command_line(
        "get",
        "http://h/x",
        connections=8,
        extract=True,
        output=pathlib.Path("a b.bin"),
        resume=None,
    )
    assert line == ["get", "--connections", "8", "--extract", "--output", "a b.bin", "--", "http://h/x"]
    assert blazeserve.command_line("serve", hide=["*.env", ".git"], listing=False) == [
        "serve", "--hide", "*.env", "--hide", ".git", "--no-listing",
    ]


def test_mistaken_options_name_the_valid_ones():
    with pytest.raises(TypeError, match="connections"):
        blazeserve.command_line("get", "http://h/x", conections=8)
    with pytest.raises(TypeError, match="unknown command"):
        blazeserve.run("fetch")
    with pytest.raises(TypeError, match="switch"):
        blazeserve.command_line("get", "http://h/x", extract="yes")
    with pytest.raises(TypeError, match="expected a string"):
        blazeserve.command_line("get", "http://h/x", output=object())


def test_get_downloads_with_keyword_options(site, tmp_path):
    destination = tmp_path / "out.bin"
    with blazeserve.Server(site) as server:
        status = blazeserve.get(server.url + "big.bin", output=destination, connections=2)
    assert status == 0
    assert destination.read_bytes() == (site / "big.bin").read_bytes()


def test_a_failed_command_returns_its_exit_code(site, tmp_path):
    with blazeserve.Server(site, auth="ada:secret") as server:
        status = blazeserve.get(server.url + "hello.txt", output=tmp_path / "x")
    assert status == 5


def test_server_takes_every_serve_option(site):
    with blazeserve.Server(
        site, cors=True, cors_origin="https://example.com", hide=["*.bin"], listing=False
    ) as server:
        _, headers, _ = fetch(server.url + "hello.txt")
        assert headers["Access-Control-Allow-Origin"] == "https://example.com"
        with pytest.raises(urllib.error.HTTPError) as hidden:
            fetch(server.url + "big.bin")
        assert hidden.value.code == 404
        with pytest.raises(urllib.error.HTTPError) as listing:
            fetch(server.url)
        assert listing.value.code == 403
    with pytest.raises(TypeError, match="no option 'colour'"):
        blazeserve.Server(site, colour=True)


def test_background_get_works_from_python(site, tmp_path, monkeypatch, capfd):
    monkeypatch.setenv("BLAZE_STATE_DIR", str(tmp_path / "state"))
    destination = tmp_path / "bg.bin"
    with blazeserve.Server(site) as server:
        assert blazeserve.get(server.url + "big.bin", output=destination, background=True) == 0
        job = capfd.readouterr().out.strip()
        assert job
        deadline = time.monotonic() + 60
        report = {}
        while time.monotonic() < deadline:
            assert blazeserve.status(job, json=True) == 0
            report = json.loads(capfd.readouterr().out)
            if "finished" in json.dumps(report) or destination.exists():
                break
            time.sleep(0.2)
    assert destination.read_bytes() == (site / "big.bin").read_bytes()


def test_ctrl_c_stops_a_running_download_and_keeps_resume_data(site, tmp_path):
    destination = tmp_path / "slow.bin"
    with blazeserve.Server(site) as server:
        timer = threading.Timer(1.0, _thread.interrupt_main)
        timer.start()
        started = time.monotonic()
        try:
            with pytest.raises(KeyboardInterrupt):
                blazeserve.get(
                    server.url + "big.bin", output=destination, limit_rate="20K", connections=1
                )
        finally:
            timer.cancel()
        assert time.monotonic() - started < 20
    assert not destination.exists()
    assert (tmp_path / "slow.bin.part").exists()
