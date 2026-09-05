"""Unit tests for package version."""

import pytest

import blazeserve
from blazeserve import __version__


@pytest.mark.unit
def test_version_string():
    assert __version__ == "0.3.1"
    assert blazeserve.__version__ == "0.3.1"
