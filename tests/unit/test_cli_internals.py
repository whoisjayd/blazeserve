"""Unit tests covering internal CLI functions, network IP discovery, and command execution."""

import json
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

import blazeserve.cli as cli_mod
from blazeserve.cli import _lan_ip, cli, main
from blazeserve.logging import JsonFormatter, setup_logging


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
    mock_resp.read.side_effect = [b"A" * (1024 * 1024), b""]
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = runner.invoke(cli, ["benchmark", "--size-mb", "1"])
        assert result.exit_code == 0
        assert "Benchmark Complete" in result.output


@pytest.mark.unit
def test_benchmark_rejects_truncated_download():
    runner = CliRunner()
    mock_resp = MagicMock()
    mock_resp.read.side_effect = [b"A" * 1024, b""]
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = runner.invoke(cli, ["benchmark", "--size-mb", "1"])

    assert result.exit_code != 0
    assert "expected 1048576 bytes, received 1024" in result.output


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
def test_serve_opens_browser_only_from_bound_callback(tmp_path):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run, patch("webbrowser.open") as mock_browser:

        def bind_then_stop(**kwargs):
            mock_browser.assert_not_called()
            kwargs["on_bound"](MagicMock())

        mock_run.side_effect = bind_then_stop
        result = runner.invoke(cli, ["serve", str(tmp_path), "--open"])
    assert result.exit_code == 0
    mock_browser.assert_called_once()


@pytest.mark.unit
def test_serve_bind_failure_does_not_open_browser_or_report_success(tmp_path):
    runner = CliRunner()
    with (
        patch("blazeserve.cli.run_server", side_effect=OSError("address in use")),
        patch("webbrowser.open") as mock_browser,
    ):
        result = runner.invoke(cli, ["serve", str(tmp_path), "--open"])

    assert result.exit_code != 0
    mock_browser.assert_not_called()
    assert "Serving" not in result.output


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


@pytest.mark.unit
def test_serve_file_path_enables_single_file_mode(tmp_path):
    file_path = tmp_path / "only-this.txt"
    file_path.write_text("private")
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(cli, ["serve", str(file_path)])
    assert result.exit_code == 0
    assert mock_run.call_args.kwargs["single"] == str(file_path.resolve())


@pytest.mark.unit
@pytest.mark.parametrize("port", ["0", "-1", "65536"])
def test_serve_rejects_invalid_tcp_ports(tmp_path, port):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(cli, ["serve", str(tmp_path), "--port", port])
    assert result.exit_code == 2
    mock_run.assert_not_called()


@pytest.mark.unit
def test_send_rejects_invalid_tcp_port(tmp_path):
    file_path = tmp_path / "share.txt"
    file_path.write_text("content")
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(cli, ["send", str(file_path), "--port", "65536"])
    assert result.exit_code == 2
    mock_run.assert_not_called()


@pytest.mark.unit
def test_serve_fails_closed_when_auth_environment_variable_is_missing(tmp_path):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(
            cli,
            ["serve", str(tmp_path), "--auth-env", "BLAZE_MISSING_TEST_AUTH"],
            env={"BLAZE_MISSING_TEST_AUTH": None},
        )
    assert result.exit_code != 0
    assert "BLAZE_MISSING_TEST_AUTH" in result.output
    mock_run.assert_not_called()


@pytest.mark.unit
def test_serve_rejects_malformed_auth_before_startup(tmp_path):
    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(cli, ["serve", str(tmp_path), "--auth", "missing-colon"])
    assert result.exit_code != 0
    assert "USER:PASS" in result.output
    mock_run.assert_not_called()


@pytest.mark.unit
def test_serve_rejects_incomplete_tls_configuration(tmp_path):
    cert = tmp_path / "cert.pem"
    cert.write_text("invalid but present")

    runner = CliRunner()
    with patch("blazeserve.cli.run_server") as mock_run:
        result = runner.invoke(
            cli,
            ["serve", str(tmp_path), "--tls-cert", str(cert)],
            standalone_mode=False,
        )
    assert result.exit_code != 0
    assert isinstance(result.exception, cli_mod.click.ClickException)
    assert str(result.exception) == "--tls-cert and --tls-key must be provided together."
    mock_run.assert_not_called()


@pytest.mark.unit
def test_json_log_mode_keeps_human_status_out_of_stdout(tmp_path):
    def log_once(**kwargs):
        kwargs["on_bound"](MagicMock())
        logging.getLogger("blazeserve.audit").warning('line one\n{"forged": true}')

    runner = CliRunner()
    with patch("blazeserve.cli.run_server", side_effect=log_once):
        result = runner.invoke(cli, ["serve", str(tmp_path), "--log-json"])
    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["message"] == 'line one\n{"forged": true}'
    assert "Serving" in result.stderr


@pytest.mark.unit
def test_benchmark_rejects_url_with_query_before_network_access():
    runner = CliRunner()
    with patch("urllib.request.urlopen") as mock_open:
        result = runner.invoke(cli, ["benchmark", "--url", "http://localhost:8000?token=x"])
    assert result.exit_code != 0
    assert "query" in result.output.lower()
    mock_open.assert_not_called()


@pytest.mark.unit
def test_benchmark_rejects_url_credentials_without_echoing_them():
    runner = CliRunner()
    secret = "do-not-print-this"
    with patch("urllib.request.urlopen") as mock_open:
        result = runner.invoke(
            cli,
            ["benchmark", "--url", f"http://operator:{secret}@localhost:8000"],
        )
    assert result.exit_code != 0
    assert secret not in result.output
    mock_open.assert_not_called()


@pytest.mark.unit
def test_json_formatter_redacts_credentials_from_messages_and_exceptions():
    secret = "do-not-log-this"
    try:
        raise RuntimeError(f"failed to fetch https://operator:{secret}@example.test")
    except RuntimeError:
        exc_info = sys.exc_info()
    record = logging.LogRecord(
        name="blazeserve.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg=f"Authorization: Bearer {secret}",
        args=(),
        exc_info=exc_info,
    )

    formatted = JsonFormatter().format(record)

    assert secret not in formatted
    assert "[REDACTED]" in formatted


@pytest.mark.unit
def test_json_logging_setup_is_idempotent():
    root = logging.getLogger()
    original_handlers = root.handlers[:]
    original_level = root.level
    try:
        setup_logging("INFO", json_logs=True)
        setup_logging("INFO", json_logs=True)

        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
    finally:
        root.handlers[:] = original_handlers
        root.setLevel(original_level)
