from blazeserve import __version__


def test_version_format() -> None:
    assert isinstance(__version__, str)
    assert "." in __version__
