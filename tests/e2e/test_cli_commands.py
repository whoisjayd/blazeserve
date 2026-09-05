"""End-to-end tests for doctor, checksum, and CLI error handling."""

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
