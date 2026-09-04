"""Unit tests for low-level handler helpers and HTTP Range parser edge cases."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from blazeserve.handlers import (
    BlazeHandler,
    _ClientDisconnectedError,
    _etag_for_stat,
    _http_date,
    _if_none_match_matches,
    _parse_range_header,
    _ZipStream,
)
from blazeserve.server import build_arg_parser


@pytest.mark.unit
def test_parse_range_header_all_branches():
    # Empty or non-bytes
    assert _parse_range_header(None, 100) is None
    assert _parse_range_header("", 100) is None
    assert _parse_range_header("chars=0-10", 100) is None
    assert _parse_range_header("bytes=", 100) is None
    assert _parse_range_header("bytes=   ", 100) is None

    # Missing dash
    assert _parse_range_header("bytes=100", 100) is None

    # Empty start and end
    assert _parse_range_header("bytes=-", 100) is None

    # Suffix ranges: "-N"
    assert _parse_range_header("bytes=-10", 100) == [(90, 99)]
    assert _parse_range_header("bytes=-0", 100) == []  # valid but unsatisfiable
    assert _parse_range_header("bytes=-bad", 100) is None  # non-int
    assert _parse_range_header("bytes=-200", 100) == [(0, 99)]  # suffix > size

    # Prefix ranges: "N-"
    assert _parse_range_header("bytes=10-", 100) == [(10, 99)]
    assert _parse_range_header("bytes=bad-", 100) is None
    assert _parse_range_header("bytes=200-", 100) == []  # valid but unsatisfiable

    # Full ranges: "N-M"
    assert _parse_range_header("bytes=10-20", 100) == [(10, 20)]
    assert _parse_range_header("bytes=10-bad", 100) is None
    assert _parse_range_header("bytes=20-10", 100) == []  # valid but unsatisfiable
    assert _parse_range_header("bytes=10-200", 100) == [(10, 99)]  # end clamped

    # Multiple ranges and whitespace
    assert _parse_range_header("bytes=0-9, , 20-29", 100) == [(0, 9), (20, 29)]


@pytest.mark.unit
def test_if_none_match_uses_weak_entity_tag_comparison():
    assert _if_none_match_matches('W/"current"', '"current"')
    assert _if_none_match_matches('"other", W/"current"', '"current"')
    assert not _if_none_match_matches('"other"', '"current"')
    assert not _if_none_match_matches("current", '"current"')


@pytest.mark.unit
def test_auth_compares_both_basic_credentials_in_constant_time(monkeypatch):
    handler = object.__new__(BlazeHandler)
    handler.AUTH_PAIR = ("admin", "secret")
    handler.headers = {"Authorization": "Basic YWRtaW46d3Jvbmc="}
    handler._auth_required = Mock()
    comparisons = []

    def compare_digest(actual, expected):
        comparisons.append((actual, expected))
        return actual == expected

    monkeypatch.setattr("blazeserve.handlers.hmac.compare_digest", compare_digest)

    assert not handler._auth_ok()
    assert comparisons == [("admin", "admin"), ("wrong", "secret")]
    handler._auth_required.assert_called_once_with()


@pytest.mark.unit
def test_zip_stream_propagates_client_disconnect():
    writer = Mock()
    writer.write.side_effect = BrokenPipeError
    outer = SimpleNamespace(wfile=writer, server=SimpleNamespace(metrics=None))

    with pytest.raises(_ClientDisconnectedError):
        _ZipStream(outer).write(b"archive data")


@pytest.mark.unit
def test_http_date_formatter():
    # Known timestamp: 1700000000 -> Tue, 14 Nov 2023 22:13:20 GMT
    formatted = _http_date(1700000000.0)
    assert "GMT" in formatted
    assert "Nov 2023" in formatted


@pytest.mark.unit
def test_etag_formatter(tmp_path):
    f = tmp_path / "etag.txt"
    f.write_text("content")
    st = f.stat()
    etag = _etag_for_stat(st)
    assert etag.startswith('"')
    assert etag.endswith('"')
    assert len(etag) == 22


@pytest.mark.unit
def test_build_arg_parser_checksum_execution(tmp_path):
    parser = build_arg_parser()
    f = tmp_path / "f.txt"
    f.write_text("data")
    args = parser.parse_args(["checksum", str(f)])
    assert args.cmd == "checksum"
    assert args.files == [str(f)]
