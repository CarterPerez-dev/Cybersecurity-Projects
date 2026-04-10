"""
©AngelaMos | 2026
test_exfiltration.py
"""


from dlp_scanner.network.exfiltration import (
    DnsExfilDetector,
    _extract_base_domain,
    detect_base64_payload,
)
from dlp_scanner.network.protocols import DnsQuery


class TestExtractBaseDomain:
    def test_simple_domain(self) -> None:
        assert (_extract_base_domain("www.example.com") == "example.com")

    def test_deep_subdomain(self) -> None:
        result = _extract_base_domain("a.b.c.example.com")
        assert result == "example.com"

    def test_trailing_dot(self) -> None:
        result = _extract_base_domain("www.example.com.")
        assert result == "example.com"

    def test_single_label(self) -> None:
        assert _extract_base_domain("localhost") == ("localhost")

    def test_two_labels(self) -> None:
        assert (_extract_base_domain("example.com") == "example.com")


class TestDnsExfilDetector:
    def test_normal_query_no_indicator(self) -> None:
        detector = DnsExfilDetector()
        query = DnsQuery(
            name = "www.google.com",
            query_type = "A",
            query_class = "1",
        )
        result = detector.analyze_query(query, "10.0.0.1", "8.8.8.8")
        assert result is None

    def test_long_label_detected(self) -> None:
        detector = DnsExfilDetector()
        long_label = "a" * 55
        query = DnsQuery(
            name = f"{long_label}.evil.com",
            query_type = "A",
            query_class = "1",
        )
        result = detector.analyze_query(query, "10.0.0.1", "1.2.3.4")
        assert result is not None
        assert (result.indicator_type == "dns_long_label")

    def test_high_entropy_subdomain(self) -> None:
        detector = DnsExfilDetector(entropy_threshold = 3.5)
        encoded = "aGVsbG8gd29ybGQgdGhpcw"
        query = DnsQuery(
            name = f"{encoded}.evil.com",
            query_type = "A",
            query_class = "1",
        )
        result = detector.analyze_query(query, "10.0.0.1", "1.2.3.4")
        assert result is not None
        assert (result.indicator_type == "dns_high_entropy")

    def test_long_qname_detected(self) -> None:
        detector = DnsExfilDetector()
        parts = ["abc"] * 40
        name = ".".join(parts) + ".evil.com"
        query = DnsQuery(
            name = name,
            query_type = "A",
            query_class = "1",
        )
        result = detector.analyze_query(query, "10.0.0.1", "1.2.3.4")
        assert result is not None

    def test_txt_volume_detection(self) -> None:
        detector = DnsExfilDetector()
        for _ in range(10):
            detector.analyze_query(
                DnsQuery(
                    name = "data.evil.com",
                    query_type = "TXT",
                    query_class = "1",
                ),
                "10.0.0.1",
                "1.2.3.4",
            )

        indicators = detector.check_txt_volume()
        assert len(indicators) > 0
        assert (indicators[0].indicator_type == "dns_txt_volume")

    def test_get_indicators_accumulates(
        self,
    ) -> None:
        detector = DnsExfilDetector()
        long_label = "x" * 55
        query = DnsQuery(
            name = f"{long_label}.evil.com",
            query_type = "A",
            query_class = "1",
        )
        detector.analyze_query(query, "10.0.0.1", "1.2.3.4")
        detector.analyze_query(query, "10.0.0.1", "1.2.3.4")

        indicators = detector.get_indicators()
        assert len(indicators) == 2

    def test_short_subdomain_no_entropy_check(
        self,
    ) -> None:
        detector = DnsExfilDetector(entropy_threshold = 3.0)
        query = DnsQuery(
            name = "example.com",
            query_type = "A",
            query_class = "1",
        )
        result = detector.analyze_query(query, "10.0.0.1", "8.8.8.8")
        assert result is None


class TestDetectBase64Payload:
    def test_base64_detected(self) -> None:
        payload = (b"data=" + b"A" * 50 + b"== end")
        indicators = detect_base64_payload(payload)
        assert len(indicators) > 0
        assert (indicators[0].indicator_type == "base64_payload")

    def test_hex_detected(self) -> None:
        payload = b"0x" + b"aabbccdd" * 10
        indicators = detect_base64_payload(payload)
        assert len(indicators) > 0
        types = {i.indicator_type for i in indicators}
        assert "hex_payload" in types

    def test_normal_text_no_detection(self) -> None:
        payload = b"Hello, this is normal text."
        indicators = detect_base64_payload(payload)
        assert len(indicators) == 0

    def test_short_base64_not_detected(self) -> None:
        payload = b"dGVzdA=="
        indicators = detect_base64_payload(payload)
        assert len(indicators) == 0

    def test_source_ip_preserved(self) -> None:
        payload = b"A" * 50
        indicators = detect_base64_payload(
            payload,
            src_ip = "10.0.0.1",
            dst_ip = "1.2.3.4",
        )
        assert len(indicators) > 0
        assert indicators[0].source_ip == "10.0.0.1"
        assert indicators[0].dest_ip == "1.2.3.4"
