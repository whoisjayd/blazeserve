"""End-to-end tests for doctor, checksum, and CLI error handling."""

import json
import socket
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from click.testing import CliRunner

from blazeserve.cli import cli


@pytest.mark.e2e
def test_cli_doctor_valid_path(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path)])
    assert result.exit_code == 0
    assert "Diagnostics" in result.output or "OK" in result.output


@pytest.mark.e2e
def test_cli_doctor_json_reports_complete_machine_readable_diagnostics(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", str(tmp_path), "--port", "0", "--json"])

    assert result.exit_code == 0
    report = json.loads(result.output)
    assert report["path"] == str(tmp_path.resolve())
    assert report["port"] == 0
    assert report["success"] is True
    assert [check["id"] for check in report["checks"]] == [
        "base_path",
        "port_binding",
        "zero_copy_io",
        "sequential_read_ahead",
    ]
    assert all(set(check) == {"id", "outcome", "details"} for check in report["checks"])
    assert all(check["outcome"] in {"pass", "fail", "fallback"} for check in report["checks"])


@pytest.mark.e2e
def test_cli_doctor_json_reports_required_failures_before_exiting(tmp_path: Path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied_socket:
        occupied_socket.bind(("127.0.0.1", 0))
        port = occupied_socket.getsockname()[1]
        runner = CliRunner()
        result = runner.invoke(
            cli, ["doctor", str(tmp_path / "missing"), "--port", str(port), "--json"]
        )

    assert result.exit_code != 0
    report = json.loads(result.output)
    assert report["success"] is False
    assert report["path"] == str((tmp_path / "missing").resolve())
    assert report["port"] == port
    assert [check["outcome"] for check in report["checks"][:2]] == ["fail", "fail"]
    assert len(report["checks"]) == 4


@pytest.mark.e2e
def test_cli_doctor_invalid_path():
    runner = CliRunner()
    result = runner.invoke(cli, ["doctor", "/nonexistent_folder_xyz_12345"])
    assert result.exit_code != 0


@pytest.mark.e2e
def test_cli_checksum_single_file(tmp_path: Path):
    f = tmp_path / "test.txt"
    f.write_text("sample content")
    runner = CliRunner()
    result = runner.invoke(cli, ["checksum", str(f)])
    assert result.exit_code == 0


@pytest.mark.e2e
def test_cli_checksum_multiple_files(tmp_path: Path):
    f1 = tmp_path / "f1.txt"
    f2 = tmp_path / "f2.txt"
    f1.write_text("content 1")
    f2.write_text("content 2")

    runner = CliRunner()
    result = runner.invoke(cli, ["checksum", str(f1), str(f2)])
    assert result.exit_code == 0


@pytest.mark.e2e
def test_cli_checksum_no_files():
    runner = CliRunner()
    result = runner.invoke(cli, ["checksum"])
    assert result.exit_code != 0


@pytest.mark.e2e
def test_cli_serve_invalid_path():
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "/nonexistent_dir_random_12345"])
    assert result.exit_code != 0
    output = (result.output + result.stderr).lower()
    assert "invalid value" in output
    assert "exist" in output


@pytest.mark.e2e
def test_cli_serve_invalid_single():
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--single", "/nonexistent_file_random_12345.txt"])
    assert result.exit_code != 0
    output = (result.output + result.stderr).lower()
    assert "invalid value" in output
    assert "exist" in output


@pytest.mark.e2e
def test_cli_benchmark_starts_temporary_server():
    runner = CliRunner()
    result = runner.invoke(cli, ["benchmark", "--size-mb", "1"])
    assert result.exit_code == 0
    assert "Benchmark Complete" in result.output
    assert "1.00 MB" in result.output


@pytest.mark.e2e
def test_cli_benchmark_json_emits_only_one_typed_result(monkeypatch):
    monkeypatch.setenv("BLAZE_LOG_JSON", "1")
    runner = CliRunner()
    result = runner.invoke(cli, ["benchmark", "--size-mb", "1", "--json"])

    assert result.exit_code == 0
    output_lines = result.output.splitlines()
    assert len(output_lines) == 1
    report = json.loads(output_lines[0])
    assert set(report) == {
        "base_url",
        "requested_bytes",
        "downloaded_bytes",
        "elapsed_seconds",
        "throughput_mib_per_second",
    }
    assert isinstance(report["base_url"], str)
    assert report["requested_bytes"] == 1024 * 1024
    assert report["downloaded_bytes"] == 1024 * 1024
    assert isinstance(report["elapsed_seconds"], float)
    assert report["elapsed_seconds"] > 0
    assert isinstance(report["throughput_mib_per_second"], float)
    assert report["throughput_mib_per_second"] > 0


@pytest.mark.e2e
def test_cli_benchmark_temporary_server_does_not_serve_cwd(tmp_path: Path, monkeypatch):
    sentinel = tmp_path / "private-sentinel.txt"
    sentinel.write_text("must not be served")
    monkeypatch.chdir(tmp_path)

    real_urlopen = urllib.request.urlopen
    sentinel_status = None

    def probe_cwd_before_benchmark(url, *args, **kwargs):
        nonlocal sentinel_status
        target = str(url)
        if sentinel_status is None and "/__speed__?" in target:
            parsed = urlsplit(target)
            sentinel_url = f"{parsed.scheme}://{parsed.netloc}/{sentinel.name}"
            try:
                with real_urlopen(sentinel_url) as response:
                    sentinel_status = response.status
            except urllib.error.HTTPError as error:
                sentinel_status = error.code
                error.close()
        return real_urlopen(url, *args, **kwargs)

    monkeypatch.setattr(urllib.request, "urlopen", probe_cwd_before_benchmark)

    runner = CliRunner()
    result = runner.invoke(cli, ["benchmark", "--size-mb", "1"])

    assert result.exit_code == 0
    assert sentinel_status == 404
