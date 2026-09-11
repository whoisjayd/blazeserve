"""Consumer-observable checks for the contributor smoke environment."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

_SMOKE_PATH = Path(__file__).parents[2] / "scripts" / "contributor_smoke.py"
_SPEC = importlib.util.spec_from_file_location("contributor_smoke", _SMOKE_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load contributor smoke script")
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)


@pytest.mark.unit
def test_build_fixture_returns_stable_logical_manifest(tmp_path: Path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()

    first = smoke.build_fixture(first_root)
    second = smoke.build_fixture(second_root)

    assert first == second
    assert first
    assert all(isinstance(path, str) for path in first)

    for logical_name, entry in first.items():
        assert set(entry) == {"path", "bytes", "sha256"}
        relative_path = Path(entry["path"])
        assert logical_name == entry["path"]
        assert not relative_path.is_absolute()
        assert ".." not in relative_path.parts
        assert isinstance(entry["bytes"], int)
        assert entry["bytes"] >= 0
        assert isinstance(entry["sha256"], str)
        assert len(entry["sha256"]) == 64

        content = (first_root / relative_path).read_bytes()
        assert entry["bytes"] == len(content)
        assert entry["sha256"] == hashlib.sha256(content).hexdigest()


def _assert_sanitized(value: object, forbidden: tuple[str, ...]) -> None:
    rendered = json.dumps(value, sort_keys=True)
    for secret in forbidden:
        assert secret not in rendered
    assert "authorization" not in rendered.lower()
    assert "basic " not in rendered.lower()


def _assert_completed_result(result: dict[str, object]) -> None:
    assert set(result) >= {"endpoint", "manifest", "scenarios"}

    endpoint = result["endpoint"]
    assert isinstance(endpoint, str)
    parsed = urlparse(endpoint)
    assert parsed.scheme == "http"
    assert parsed.hostname == "127.0.0.1"
    assert parsed.port is not None
    assert 0 < parsed.port <= 65535

    manifest = result["manifest"]
    assert isinstance(manifest, dict)
    assert manifest
    for entry in manifest.values():
        assert isinstance(entry, dict)
        assert set(entry) == {"path", "bytes", "sha256"}
        assert not Path(entry["path"]).is_absolute()

    scenarios = result["scenarios"]
    assert [scenario["name"] for scenario in scenarios] == [
        "static_get",
        "byte_range",
        "authenticated_upload",
        "authenticated_readback",
        "live",
        "ready",
    ]
    for scenario in scenarios:
        assert isinstance(scenario, dict)
        assert set(scenario) == {"name", "status", "bytes"}
        assert isinstance(scenario["status"], int)
        assert 200 <= scenario["status"] < 300
        assert isinstance(scenario["bytes"], int)
        assert scenario["bytes"] >= 0


@pytest.mark.unit
def test_run_smoke_returns_completed_sanitized_result():
    result = smoke.run_smoke()

    _assert_completed_result(result)
    _assert_sanitized(result, (str(Path.cwd()),))


@pytest.mark.unit
def test_main_emits_one_completed_json_result_with_inherited_json_logging(monkeypatch, capsys):
    monkeypatch.setenv("BLAZE_LOG_JSON", "1")
    assert smoke.main() == 0

    captured = capsys.readouterr()
    assert captured.err == ""
    lines = captured.out.splitlines()
    assert len(lines) == 1
    result = json.loads(lines[0])
    assert isinstance(result, dict)
    _assert_completed_result(result)
    _assert_sanitized(result, (str(Path.cwd()),))


@pytest.mark.unit
def test_main_sanitizes_server_creation_failure_and_recovers(monkeypatch, capsys, tmp_path: Path):
    username = "contributor-smoke-test-user"
    password = "contributor-smoke-test-password"
    raw_path = tmp_path / "sensitive-fixture-root"

    def fail_server_creation(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(f"cannot bind {username}:{password} in {raw_path}")

    original_create_server = smoke.create_server
    monkeypatch.setattr(smoke, "create_server", fail_server_creation)

    assert smoke.main() != 0
    failed = capsys.readouterr()
    assert failed.out == ""
    lines = failed.err.splitlines()
    assert len(lines) == 1
    report = json.loads(lines[0])
    assert isinstance(report, dict)
    _assert_sanitized(report, (username, password, str(raw_path), str(tmp_path)))

    monkeypatch.setattr(smoke, "create_server", original_create_server)
    result = smoke.run_smoke()
    _assert_completed_result(result)
