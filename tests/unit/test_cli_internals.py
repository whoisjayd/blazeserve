"""Unit tests covering internal CLI functions, network IP discovery, and command execution."""

import sys
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import blazeserve.cli as cli_mod
from blazeserve.cli import _lan_ip, cli, main


@pytest.mark.unit
def test_lan_ip_resolution():
    ip = _lan_ip()
    assert isinstance(ip, str)
    assert len(ip.split(".")) == 4 or ip == "127.0.0.1"


@pytest.mark.unit
def test_lan_ip_exception_fallback():
    with patch("socket.socket") as mock_sock:
        mock_sock.side_effect = OSError("No network")
        assert _lan_ip() == "127.0.0.1"


@pytest.mark.unit
def test_serve_cmd_mock_run(tmp_path):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        # Mock run_server so CLI proceeds through all parameter setup
        mock_run.return_value = None
        result = runner.invoke(cli, ["serve", str(tmp_path), "--port", "9191", "--no-listing"])
        assert result.exit_code == 0
        assert mock_run.called
        kwargs = mock_run.call_args[1]
        assert kwargs["port"] == 9191
        assert kwargs["listing"] is False


@pytest.mark.unit
def test_send_cmd_mock_run(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("send content")

    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        mock_run.return_value = None
        result = runner.invoke(cli, ["send", str(f), "-p", "8888", "--rate-mbps", "10.0"])
        assert result.exit_code == 0
        assert mock_run.called
        kwargs = mock_run.call_args[1]
        assert kwargs["port"] == 8888
        assert kwargs["rate_mbps"] == 10.0


@pytest.mark.unit
def test_benchmark_cmd_execution():
    runner = CliRunner()
    mock_resp = MagicMock()
    mock_resp.read.side_effect = [b"A" * 1024, b""]  # 1KB download then EOF
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = runner.invoke(cli, ["benchmark", "--size-mb", "1"])
        assert result.exit_code == 0
        assert "Benchmark Complete" in result.output


@pytest.mark.unit
def test_main_subcommand_dispatch():
    with (
        patch.object(sys, "argv", ["blaze", "version", "--json"]),
        patch.object(cli_mod, "cli") as mock_cli,
    ):
        main()
        assert mock_cli.called


@pytest.mark.unit
def test_main_legacy_serve_dispatch(tmp_path):
    with (
        patch.object(sys, "argv", ["blaze", "serve", str(tmp_path), "--port", "9999"]),
        patch("blazeserve.cli.run_server") as mock_run,
    ):
        try:
            main()
        except SystemExit as e:
            assert e.code == 0
        assert mock_run.called
        assert mock_run.call_args[1]["port"] == 9999


@pytest.mark.unit
def test_serve_cmd_with_auth_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_AUTH_CRED", "user:pass")
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        mock_run.return_value = None
        result = runner.invoke(cli, ["serve", str(tmp_path), "--auth-env", "TEST_AUTH_CRED"])
        assert result.exit_code == 0
        assert mock_run.call_args[1]["auth"] == "user:pass"


@pytest.mark.unit
def test_serve_cmd_with_single_file(tmp_path):
    f = tmp_path / "single.txt"
    f.write_text("content")
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        mock_run.return_value = None
        result = runner.invoke(cli, ["serve", "--single", str(f)])
        assert result.exit_code == 0
        assert mock_run.call_args[1]["single"] == str(f)


@pytest.mark.unit
def test_serve_cmd_with_open_browser(tmp_path):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run, patch("webbrowser.open") as mock_browser:
        mock_run.return_value = None
        result = runner.invoke(cli, ["serve", str(tmp_path), "--open"])
        assert result.exit_code == 0
        assert mock_browser.called


@pytest.mark.unit
def test_send_cmd_with_auth_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_SEND_AUTH", "sender:pass123")
    f = tmp_path / "item.bin"
    f.write_bytes(b"data")
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        mock_run.return_value = None
        result = runner.invoke(cli, ["send", str(f), "--auth-env", "TEST_SEND_AUTH"])
        assert result.exit_code == 0
        assert mock_run.call_args[1]["auth"] == "sender:pass123"
