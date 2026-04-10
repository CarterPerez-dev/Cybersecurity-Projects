"""
©AngelaMos | 2026
protocols.py
"""


import socket
from dataclasses import dataclass, field

import structlog


log = structlog.get_logger()

HTTP_METHODS: frozenset[bytes] = frozenset(
    {
        b"GET",
        b"POST",
        b"PUT",
        b"DELETE",
        b"HEAD",
        b"OPTIONS",
        b"PATCH",
    }
)

HTTP_RESPONSE_PREFIX: bytes = b"HTTP/"
TLS_RECORD_PREFIX: bytes = b"\x16\x03"
SSH_PREFIX: bytes = b"SSH-"
SMTP_BANNER_PREFIX: bytes = b"220 "
DNS_PORT: int = 53

DNS_QTYPES: dict[int,
                 str] = {
                     1: "A",
                     2: "NS",
                     5: "CNAME",
                     6: "SOA",
                     12: "PTR",
                     15: "MX",
                     16: "TXT",
                     28: "AAAA",
                     33: "SRV",
                     255: "ANY",
                 }


@dataclass(frozen = True, slots = True)
class HttpMessage:
    """
    Parsed HTTP request or response
    """

    method: str
    uri: str
    version: str
    headers: dict[str, str]
    body: str
    is_request: bool


@dataclass(frozen = True, slots = True)
class DnsQuery:
    """
    A single DNS query entry
    """

    name: str
    query_type: str
    query_class: str


@dataclass(frozen = True, slots = True)
class DnsRecord:
    """
    Parsed DNS message with queries and answers
    """

    queries: list[DnsQuery] = field(default_factory = list)
    answers: list[str] = field(default_factory = list)
    is_response: bool = False
    transaction_id: int = 0


def parse_http(
    payload: bytes,
) -> HttpMessage | None:
    """
    Parse HTTP request or response from raw payload
    """
    import dpkt

    try:
        if _is_http_request(payload):
            req = dpkt.http.Request(payload)
            headers = dict(req.headers)
            body = _decode_body(req.body)
            return HttpMessage(
                method = req.method,
                uri = req.uri,
                version = req.version,
                headers = headers,
                body = body,
                is_request = True,
            )

        if payload.startswith(HTTP_RESPONSE_PREFIX):
            resp = dpkt.http.Response(payload)
            headers = dict(resp.headers)
            body = _decode_body(resp.body)
            return HttpMessage(
                method = "",
                uri = "",
                version = resp.version,
                headers = headers,
                body = body,
                is_request = False,
            )
    except (dpkt.NeedData, dpkt.UnpackError):
        return None

    return None


def parse_dns(
    payload: bytes,
) -> DnsRecord | None:
    """
    Parse DNS message from raw UDP payload
    """
    import dpkt

    try:
        dns = dpkt.dns.DNS(payload)
    except (dpkt.NeedData, dpkt.UnpackError):
        return None

    queries: list[DnsQuery] = []
    for qd in dns.qd:
        qtype = DNS_QTYPES.get(qd.type, str(qd.type))
        queries.append(
            DnsQuery(
                name = qd.name,
                query_type = qtype,
                query_class = str(qd.cls),
            )
        )

    answers: list[str] = []
    for an in dns.an:
        _parse_answer(an, answers)

    return DnsRecord(
        queries = queries,
        answers = answers,
        is_response = bool(dns.qr),
        transaction_id = dns.id,
    )


def identify_protocol(
    payload: bytes,
) -> str:
    """
    Identify application-layer protocol via DPI
    """
    if not payload:
        return "unknown"

    if _is_http_request(payload):
        return "http"

    if payload.startswith(HTTP_RESPONSE_PREFIX):
        return "http"

    if (len(payload) > 2 and payload[: 2] == TLS_RECORD_PREFIX):
        return "tls"

    if payload.startswith(SSH_PREFIX):
        return "ssh"

    if payload.startswith(SMTP_BANNER_PREFIX):
        return "smtp"

    return "unknown"


def _is_http_request(payload: bytes) -> bool:
    """
    Check if payload starts with an HTTP method
    """
    first_space = payload.find(b" ")
    if first_space < 3 or first_space > 7:
        return False
    return payload[: first_space] in HTTP_METHODS


def _decode_body(body: bytes | str) -> str:
    """
    Decode HTTP body bytes to string
    """
    if isinstance(body, str):
        return body
    if not body:
        return ""
    try:
        return body.decode("utf-8", errors = "replace")
    except Exception:
        return ""


def _parse_answer(
    an: object,
    answers: list[str],
) -> None:
    """
    Parse a single DNS answer record
    """
    try:
        an_type = getattr(an, "type", 0)
        rdata = getattr(an, "rdata", b"")

        if an_type == 1 and len(rdata) == 4:
            answers.append(socket.inet_ntoa(rdata))
        elif an_type == 16 and rdata:
            answers.append(_parse_txt_rdata(rdata))
        elif hasattr(an, "cname") and an.cname:
            answers.append(an.cname)
        elif hasattr(an, "name") and an.name:
            answers.append(an.name)
    except Exception:
        pass


def _parse_txt_rdata(rdata: bytes) -> str:
    """
    Parse TXT record rdata (length-prefixed strings)
    """
    parts: list[str] = []
    i = 0
    while i < len(rdata):
        length = rdata[i]
        i += 1
        if i + length <= len(rdata):
            chunk = rdata[i : i + length]
            parts.append(chunk.decode("utf-8", errors = "replace"))
            i += length
        else:
            break
    return " ".join(parts)
