"""End-to-end tests for CLI option parsing and basic commands."""

import json

import pytest
from click.testing import CliRunner

from blazeserve import __version__
from blazeserve.cli import cli


@pytest.mark.e2e
def test_cli_help_flag():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "serve" in result.output
    assert "send" in result.output
    assert "doctor" in result.output
    assert "benchmark" in result.output
    assert "checksum" in result.output
    assert "version" in result.output


@pytest.mark.e2e
def test_cli_version_human():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.e2e
def test_cli_version_json():
    runner = CliRunner()
    result = runner.invoke(cli, ["version", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["name"] == "blazeserve"
    assert data["version"] == __version__
    assert "python" in data
    assert "platform" in data


@pytest.mark.e2e
def test_cli_serve_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["serve", "--help"])
    assert result.exit_code == 0
    assert "--chunk-mb" in result.output
    assert "--sock-sndbuf-mb" in result.output
    assert "--rate-mbps" in result.output
    assert "--cors" in result.output
    assert "--log-json" in result.output


@pytest.mark.e2e
def test_cli_send_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["send", "--help"])
    assert result.exit_code == 0
    assert "--rate-mbps" in result.output
    assert "--tls-cert" in result.output
    assert "--log-json" in result.output


@pytest.mark.e2e
def test_cli_benchmark_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["benchmark", "--help"])
    assert result.exit_code == 0
    assert "--url" in result.output
    assert "--size-mb" in result.output
