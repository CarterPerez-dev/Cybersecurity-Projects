"""
©AngelaMos | 2026
test_protocols.py
"""


from dlp_scanner.network.protocols import (
    _is_http_request,
    _parse_txt_rdata,
    identify_protocol,
    parse_dns,
    parse_http,
)


class TestIdentifyProtocol:
    def test_http_get_request(self) -> None:
        payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        assert identify_protocol(payload) == "http"

    def test_http_post_request(self) -> None:
        payload = b"POST /api HTTP/1.1\r\n\r\n"
        assert identify_protocol(payload) == "http"

    def test_http_response(self) -> None:
        payload = b"HTTP/1.1 200 OK\r\n\r\n"
        assert identify_protocol(payload) == "http"

    def test_tls_handshake(self) -> None:
        payload = b"\x16\x03\x01\x00\x05hello"
        assert identify_protocol(payload) == "tls"

    def test_ssh_banner(self) -> None:
        payload = b"SSH-2.0-OpenSSH_8.9\r\n"
        assert identify_protocol(payload) == "ssh"

    def test_smtp_banner(self) -> None:
        payload = b"220 mail.example.com ESMTP"
        assert identify_protocol(payload) == "smtp"

    def test_unknown_protocol(self) -> None:
        payload = b"\x00\x01\x02\x03"
        assert identify_protocol(payload) == "unknown"

    def test_empty_payload(self) -> None:
        assert identify_protocol(b"") == "unknown"


class TestIsHttpRequest:
    def test_get_is_http(self) -> None:
        assert _is_http_request(b"GET /path HTTP/1.1")

    def test_delete_is_http(self) -> None:
        assert _is_http_request(b"DELETE /resource HTTP/1.1")

    def test_random_bytes_not_http(self) -> None:
        assert not _is_http_request(b"\x00\x01\x02")

    def test_short_payload_not_http(self) -> None:
        assert not _is_http_request(b"HI")


class TestParseHttp:
    def test_parse_get_request(self) -> None:
        raw = (
            b"GET /index.html HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"\r\n"
        )
        result = parse_http(raw)
        assert result is not None
        assert result.method == "GET"
        assert result.uri == "/index.html"
        assert result.is_request is True
        assert "host" in result.headers

    def test_parse_post_with_body(self) -> None:
        body = b"key=value"
        raw = (
            b"POST /api HTTP/1.1\r\n"
            b"Content-Length: 9\r\n"
            b"\r\n" + body
        )
        result = parse_http(raw)
        assert result is not None
        assert result.method == "POST"
        assert result.body == "key=value"

    def test_parse_response(self) -> None:
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 5\r\n"
            b"\r\nhello"
        )
        result = parse_http(raw)
        assert result is not None
        assert result.is_request is False
        assert result.body == "hello"

    def test_invalid_data_returns_none(self) -> None:
        assert parse_http(b"\x00\x01") is None


class TestParseDns:
    def test_parse_dns_query(self) -> None:
        import dpkt

        dns = dpkt.dns.DNS()
        dns.id = 1234
        dns.qr = dpkt.dns.DNS_Q
        dns.opcode = dpkt.dns.DNS_QUERY
        q = dpkt.dns.DNS.Q()
        q.name = "example.com"
        q.type = dpkt.dns.DNS_A
        q.cls = dpkt.dns.DNS_IN
        dns.qd = [q]

        result = parse_dns(bytes(dns))
        assert result is not None
        assert len(result.queries) == 1
        assert result.queries[0].name == "example.com"
        assert result.queries[0].query_type == "A"
        assert result.is_response is False
        assert result.transaction_id == 1234

    def test_parse_txt_query(self) -> None:
        import dpkt

        dns = dpkt.dns.DNS()
        dns.id = 5678
        dns.qr = dpkt.dns.DNS_Q
        q = dpkt.dns.DNS.Q()
        q.name = "data.evil.com"
        q.type = dpkt.dns.DNS_TXT
        q.cls = dpkt.dns.DNS_IN
        dns.qd = [q]

        result = parse_dns(bytes(dns))
        assert result is not None
        assert result.queries[0].query_type == "TXT"
        assert (result.queries[0].name == "data.evil.com")

    def test_invalid_data_returns_none(self) -> None:
        assert parse_dns(b"\x00\x01") is None


class TestParseTxtRdata:
    def test_single_string(self) -> None:
        rdata = b"\x05hello"
        assert _parse_txt_rdata(rdata) == "hello"

    def test_multiple_strings(self) -> None:
        rdata = b"\x02hi\x05world"
        assert _parse_txt_rdata(rdata) == "hi world"

    def test_empty_rdata(self) -> None:
        assert _parse_txt_rdata(b"") == ""
