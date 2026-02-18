"""
©AngelaMos | 2026
parsers.py
"""

import re
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class ParsedLogEntry:
    """
    Structured representation of a single nginx access log line.
    """

    ip: str
    timestamp: datetime
    method: str
    path: str
    query_string: str
    status_code: int
    response_size: int
    referer: str
    user_agent: str
    raw_line: str


_TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"

_COMBINED_RE = re.compile(
    r"(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<timestamp>[^\]]+)\] "
    r'"(?P<request>[^"]*)" '
    r"(?P<status>\d{3}) "
    r"(?P<size>\S+) "
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)


def parse_combined(line: str) -> ParsedLogEntry | None:
    """
    Parse an nginx combined-format log line using string-split primary
    with compiled regex fallback.
    """
    if not line:
        return None

    result = _parse_split(line)
    if result is not None:
        return result

    return _parse_regex(line)


def _parse_split(line: str) -> ParsedLogEntry | None:
    """
    Fast string-split parser for well-formed nginx combined lines.
    """
    try:
        parts = line.split('"')
        if len(parts) < 6:
            return None

        prefix = parts[0]
        request_line = parts[1]
        status_size = parts[2]
        referer_raw = parts[3]
        user_agent = parts[5]

        bracket_open = prefix.index("[")
        bracket_close = prefix.index("]")
        ip = prefix[:bracket_open].split()[0]
        timestamp = datetime.strptime(prefix[bracket_open + 1 : bracket_close], _TIMESTAMP_FMT)

        request_parts = request_line.split(" ", 2)
        method = request_parts[0]
        full_uri = request_parts[1] if len(request_parts) > 1 else ""

        if "?" in full_uri:
            path, query_string = full_uri.split("?", 1)
        else:
            path = full_uri
            query_string = ""

        tokens = status_size.strip().split()
        status_code = int(tokens[0])
        response_size = int(tokens[1]) if tokens[1] != "-" else 0

        referer = "" if referer_raw == "-" else referer_raw

        return ParsedLogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            path=path,
            query_string=query_string,
            status_code=status_code,
            response_size=response_size,
            referer=referer,
            user_agent=user_agent,
            raw_line=line,
        )
    except (ValueError, IndexError):
        return None


def _parse_regex(line: str) -> ParsedLogEntry | None:
    """
    Regex fallback for non-standard or edge-case log lines.
    """
    match = _COMBINED_RE.match(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match["timestamp"], _TIMESTAMP_FMT)

        request_line = match["request"]
        request_parts = request_line.split(" ", 2)
        method = request_parts[0]
        full_uri = request_parts[1] if len(request_parts) > 1 else ""

        if "?" in full_uri:
            path, query_string = full_uri.split("?", 1)
        else:
            path = full_uri
            query_string = ""

        size_raw = match["size"]
        response_size = int(size_raw) if size_raw != "-" else 0

        referer_raw = match["referer"]
        referer = "" if referer_raw == "-" else referer_raw

        return ParsedLogEntry(
            ip=match["ip"],
            timestamp=timestamp,
            method=method,
            path=path,
            query_string=query_string,
            status_code=int(match["status"]),
            response_size=response_size,
            referer=referer,
            user_agent=match["user_agent"],
            raw_line=line,
        )
    except (ValueError, IndexError):
        return None
