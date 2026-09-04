"""Unit tests for utility functions in blazeserve.utils."""

from pathlib import Path

import pytest

from blazeserve.utils import human_size, parse_basic_auth, sha256_file


@pytest.mark.unit
def test_human_size_formatting():
    assert human_size(100) == "100.00B"
    assert human_size(1024) == "1.00KB"
    assert human_size(1536) == "1.50KB"
    assert human_size(1024 * 1024) == "1.00MB"
    assert human_size(1024 * 1024 * 1024) == "1.00GB"
    assert human_size(0) == "0.00B"


@pytest.mark.unit
def test_sha256_file(tmp_path: Path):
    f = tmp_path / "sample.txt"
    f.write_text("hello world")
    digest = sha256_file(str(f))
    # SHA256 of "hello world"
    assert digest == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


@pytest.mark.unit
def test_parse_basic_auth_valid():
    import base64

    raw = base64.b64encode(b"admin:pass123").decode("ascii")
    user, pw = parse_basic_auth(f"Basic {raw}")
    assert user == "admin"
    assert pw == "pass123"


@pytest.mark.unit
def test_parse_basic_auth_invalid():
    assert parse_basic_auth(None) is None
    assert parse_basic_auth("Bearer token") is None
    assert parse_basic_auth("Basic !!!invalid-base64") is None

    assert parse_basic_auth("Basic YWRtaW46cHc=!") is None
    # Valid base64 but missing colon
    import base64

    no_colon = base64.b64encode(b"adminpass").decode("ascii")
    assert parse_basic_auth(f"Basic {no_colon}") is None
