import base64
import hashlib
import json
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
