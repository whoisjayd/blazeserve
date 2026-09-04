"""Unit tests for HTML5 responsive directory UI."""

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from blazeserve.ui import render_directory_index


@pytest.mark.unit
def test_render_directory_index_root(tmp_path: Path):
    (tmp_path / "file1.txt").write_text("content")
    (tmp_path / "sub").mkdir()

    entries = list(os.scandir(tmp_path))
    html_bytes = render_directory_index(str(tmp_path), "", entries, allow_upload=False)
    html_str = html_bytes.decode("utf-8")

    assert "<title>Index of / — BlazeServe</title>" in html_str
    assert "file1.txt" in html_str
    assert "sub" in html_str
    assert "dropzone" not in html_str


@pytest.mark.unit
def test_render_directory_index_subfolder_with_parent_link(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested")

    entries = list(os.scandir(sub))
    html_bytes = render_directory_index(str(sub), "sub", entries, allow_upload=False)
    html_str = html_bytes.decode("utf-8")

    assert "Index of /sub" in html_str
    assert "nested.txt" in html_str
    assert "Parent Directory" in html_str


@pytest.mark.unit
def test_render_directory_index_quotes_url_paths_and_special_names(tmp_path: Path):
    nested = tmp_path / "folder" / "child"
    nested.mkdir(parents=True)
    # '?' is invalid in Windows filenames; '#' and '%' still exercise URL quoting.
    (nested / "report #1%.txt").write_text("content")

    entries = list(os.scandir(nested))
    html_str = render_directory_index(
        str(nested),
        r"folder\child",
        entries,
        allow_upload=False,
    ).decode("utf-8")

    assert 'href="/folder/"' in html_str
    assert 'href="/folder/child/report%20%231%25.txt"' in html_str
    assert r'href="folder\child"' not in html_str


@pytest.mark.unit
def test_render_directory_index_with_upload_dropzone(tmp_path: Path):
    entries = list(os.scandir(tmp_path))
    html_bytes = render_directory_index(str(tmp_path), "", entries, allow_upload=True)
    html_str = html_bytes.decode("utf-8")

    assert 'id="dropzone"' in html_str
    assert "Drag & drop files here" in html_str


@pytest.mark.unit
def test_render_directory_index_oserror_entry(tmp_path: Path):
    mock_entry = MagicMock(spec=os.DirEntry)
    mock_entry.stat.side_effect = OSError("Access denied")
    mock_entry.name = "broken.bin"
    mock_entry.is_dir.return_value = False

    html_bytes = render_directory_index(str(tmp_path), "", [mock_entry], allow_upload=False)
    assert isinstance(html_bytes, bytes)
    assert "broken.bin" not in html_bytes.decode("utf-8")
