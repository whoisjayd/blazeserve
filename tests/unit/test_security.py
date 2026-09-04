"""Unit tests for security utilities and path traversal protections."""

import os
from pathlib import Path

import pytest

from blazeserve.security import (
    UnsafePathError,
    create_upload_file,
    generate_request_id,
    is_safe_path,
)


@pytest.mark.unit
def test_is_safe_path_valid_subpath(tmp_path: Path):
    sub = tmp_path / "subdir" / "file.txt"
    assert is_safe_path(str(tmp_path), str(sub))


@pytest.mark.unit
def test_is_safe_path_exact_match(tmp_path: Path):
    assert is_safe_path(str(tmp_path), str(tmp_path))


@pytest.mark.unit
def test_is_safe_path_traversal_attack(tmp_path: Path):
    evil = tmp_path / ".." / "outside.txt"
    assert not is_safe_path(str(tmp_path), str(evil))


@pytest.mark.unit
def test_is_safe_path_sibling_prefix_attack(tmp_path: Path):
    base = os.path.join(str(tmp_path), "data")
    sibling = os.path.join(str(tmp_path), "data_leak", "file.txt")
    assert not is_safe_path(base, sibling)


@pytest.mark.unit
def test_is_safe_path_rejects_symlink_escape(tmp_path: Path):
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    link = base / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    assert not is_safe_path(str(base), str(link / "secret.txt"))


@pytest.mark.unit
def test_create_upload_file_rejects_symlink_parent(tmp_path: Path):
    base = tmp_path / "base"
    outside = tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    link = base / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        create_upload_file(str(base), str(link / "escaped.txt"))
    assert not (outside / "escaped.txt").exists()


@pytest.mark.unit
def test_generate_request_id_valid_incoming():
    req_id = generate_request_id("trace-12345-abc")
    assert req_id == "trace-12345-abc"


@pytest.mark.unit
def test_generate_request_id_invalid_incoming():
    req_id = generate_request_id("invalid!@#$%" * 10)
    assert len(req_id) == 12
    assert req_id.isalnum()


@pytest.mark.unit
def test_generate_request_id_none():
    req_id = generate_request_id(None)
    assert len(req_id) == 12
    assert req_id.isalnum()
