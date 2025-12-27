"""
Shared pytest fixtures and configuration.
"""

import pytest


@pytest.fixture(scope="session")
def test_files_dir(tmp_path_factory):
    """Create a session-scoped directory with test files."""
    tmpdir = tmp_path_factory.mktemp("test_files")

    # Create various test files
    (tmpdir / "empty.txt").write_text("")
    (tmpdir / "small.txt").write_text("Small file content")
    (tmpdir / "medium.txt").write_text("M" * 1000)
    (tmpdir / "large.bin").write_bytes(b"L" * (1024 * 1024))

    # Create subdirectories
    subdir = tmpdir / "subdir"
    subdir.mkdir()
    (subdir / "nested.txt").write_text("Nested content")

    return tmpdir


# Configure pytest
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
