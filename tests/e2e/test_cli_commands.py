"""End-to-end tests for doctor, checksum, and CLI error handling."""

from pathlib import Path

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
    assert "does not exist" in result.output.lower() or "not found" in result.output.lower()


@pytest.mark.e2e
def test_cli_serve_invalid_single():
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--single", "/nonexistent_file_random_12345.txt"])
    assert result.exit_code != 0
    assert "does not exist" in result.output.lower() or "not found" in result.output.lower()
