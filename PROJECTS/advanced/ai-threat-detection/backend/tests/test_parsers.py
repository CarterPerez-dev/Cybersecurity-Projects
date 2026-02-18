"""
©AngelaMos | 2026
test_parsers.py
"""

from datetime import datetime, UTC

from app.core.ingestion.parsers import ParsedLogEntry, parse_combined


def test_parse_standard_combined_line() -> None:
    """
    Parse a standard nginx combined log line into all fields.
    """
    line = (
        "93.184.216.34 - - [11/Feb/2026:14:30:00 +0000] "
        '"GET /api/users?page=1 HTTP/1.1" 200 1234 '
        '"https://example.com" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    result = parse_combined(line)

    assert result is not None
    assert isinstance(result, ParsedLogEntry)
    assert result.ip == "93.184.216.34"
    assert result.timestamp == datetime(2026, 2, 11, 14, 30, 0, tzinfo=UTC)
    assert result.method == "GET"
    assert result.path == "/api/users"
    assert result.query_string == "page=1"
    assert result.status_code == 200
    assert result.response_size == 1234
    assert result.referer == "https://example.com"
    assert result.user_agent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert result.raw_line == line


def test_parse_ipv6_address() -> None:
    """
    Parse a line with an IPv6 source address.
    """
    line = '::1 - - [11/Feb/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 612 "-" "curl/8.0"'
    result = parse_combined(line)

    assert result is not None
    assert result.ip == "::1"
    assert result.method == "GET"
    assert result.path == "/"
    assert result.query_string == ""


def test_parse_missing_referer() -> None:
    """
    A dash referer is normalized to an empty string.
    """
    line = (
        "10.0.0.1 - - [11/Feb/2026:08:15:42 +0000] "
        '"POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0"'
    )
    result = parse_combined(line)

    assert result is not None
    assert result.referer == ""
    assert result.method == "POST"
    assert result.status_code == 302


def test_parse_complex_query_string() -> None:
    """
    Query strings with multiple parameters and special characters.
    """
    line = (
        "93.184.216.34 - - [11/Feb/2026:14:30:00 +0000] "
        '"GET /search?q=hello+world&lang=en&page=2&sort=relevance HTTP/1.1" '
        '200 5678 "https://example.com/search" "Mozilla/5.0"'
    )
    result = parse_combined(line)

    assert result is not None
    assert result.path == "/search"
    assert result.query_string == "q=hello+world&lang=en&page=2&sort=relevance"


def test_parse_malformed_line_returns_none() -> None:
    """
    Malformed lines return None instead of raising.
    """
    assert parse_combined("this is not a valid log line") is None


def test_parse_empty_line_returns_none() -> None:
    """
    Empty input returns None.
    """
    assert parse_combined("") is None


def test_parse_dash_response_size() -> None:
    """
    A dash response size (e.g. HEAD 304) is normalized to zero.
    """
    line = '1.2.3.4 - - [11/Feb/2026:10:00:00 +0000] "HEAD / HTTP/1.1" 304 - "-" "Mozilla/5.0"'
    result = parse_combined(line)

    assert result is not None
    assert result.response_size == 0
    assert result.status_code == 304


def test_parse_full_ipv6_address() -> None:
    """
    Parse a line with a full-length IPv6 address.
    """
    line = (
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - "
        '[11/Feb/2026:14:30:00 +0000] "GET /api/v1/health HTTP/2.0" '
        '200 256 "-" "python-httpx/0.28"'
    )
    result = parse_combined(line)

    assert result is not None
    assert result.ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert result.path == "/api/v1/health"
