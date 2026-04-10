"""
©AngelaMos | 2026
network_scanner.py
"""


from datetime import datetime, UTC
from pathlib import Path

import structlog

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.base import DetectorMatch
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.models import (
    Finding,
    Location,
    ScanResult,
)
from dlp_scanner.network.exfiltration import (
    DnsExfilDetector,
    ExfilIndicator,
    detect_base64_payload,
)
from dlp_scanner.network.flow_tracker import (
    FlowTracker,
    make_flow_key,
)
from dlp_scanner.network.pcap import read_pcap
from dlp_scanner.network.protocols import (
    DNS_PORT,
    identify_protocol,
    parse_dns,
    parse_http,
)
from dlp_scanner.scoring import match_to_finding


log = structlog.get_logger()

EXFIL_RULE_MAP: dict[str, tuple[str, str]] = {
    "dns_long_label": (
        "NET_DNS_EXFIL_LONG_LABEL",
        "DNS Exfiltration: Long Label",
    ),
    "dns_high_entropy": (
        "NET_DNS_EXFIL_HIGH_ENTROPY",
        "DNS Exfiltration: High Entropy Subdomain",
    ),
    "dns_long_qname": (
        "NET_DNS_EXFIL_LONG_QNAME",
        "DNS Exfiltration: Long QNAME",
    ),
    "dns_txt_volume": (
        "NET_DNS_EXFIL_TXT_VOLUME",
        "DNS Exfiltration: High TXT Volume",
    ),
    "base64_payload": (
        "NET_ENCODED_BASE64",
        "Encoded Payload: Base64",
    ),
    "hex_payload": (
        "NET_ENCODED_HEX",
        "Encoded Payload: Hex",
    ),
}


class NetworkScanner:
    """
    Scans network capture files for sensitive data in transit
    """
    def __init__(
        self,
        config: ScanConfig,
        registry: DetectorRegistry,
    ) -> None:
        self._net_config = config.network
        self._detection_config = config.detection
        self._redaction_style = config.output.redaction_style
        self._registry = registry

    def scan(self, target: str) -> ScanResult:
        """
        Scan a PCAP file for sensitive data in payloads
        """
        result = ScanResult()
        target_path = Path(target)

        if not target_path.exists():
            result.errors.append(f"PCAP file not found: {target}")
            result.scan_completed_at = datetime.now(UTC)
            return result

        try:
            self._scan_pcap(target_path, result)
        except Exception as exc:
            log.warning(
                "pcap_scan_failed",
                path = str(target_path),
                error = str(exc),
            )
            result.errors.append(f"PCAP scan failed: {exc}")

        result.scan_completed_at = datetime.now(UTC)
        return result

    def _scan_pcap(
        self,
        path: Path,
        result: ScanResult,
    ) -> None:
        """
        Read packets, reassemble flows, and run detection
        """
        tracker = FlowTracker()
        dns_detector = DnsExfilDetector(
            entropy_threshold = (
                self._net_config.dns_label_entropy_threshold
            ),
        )
        packet_count = 0

        for packet in read_pcap(
            path,
            max_packets = self._net_config.max_packets,
        ):
            packet_count += 1
            tracker.add_packet(packet)

            if (
                packet.protocol == "udp"
                and (
                    packet.src_port == DNS_PORT
                    or packet.dst_port == DNS_PORT
                )
            ):
                self._process_dns_packet(
                    packet.payload,
                    packet.src_ip,
                    packet.dst_ip,
                    path,
                    packet_count,
                    dns_detector,
                    result,
                )

            if packet.payload:
                exfil_indicators = detect_base64_payload(
                    packet.payload,
                    src_ip = packet.src_ip,
                    dst_ip = packet.dst_ip,
                )
                for indicator in exfil_indicators:
                    finding = _indicator_to_finding(
                        indicator,
                        str(path),
                        packet_count,
                    )
                    result.findings.append(finding)

        txt_indicators = dns_detector.check_txt_volume()
        for indicator in txt_indicators:
            finding = _indicator_to_finding(
                indicator,
                str(path),
                packet_count,
            )
            result.findings.append(finding)

        self._scan_reassembled_flows(tracker, path, result)

        result.targets_scanned = packet_count

    def _process_dns_packet(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        path: Path,
        packet_num: int,
        dns_detector: DnsExfilDetector,
        result: ScanResult,
    ) -> None:
        """
        Parse DNS and check for exfiltration patterns
        """
        dns_record = parse_dns(payload)
        if dns_record is None:
            return

        for query in dns_record.queries:
            indicator = dns_detector.analyze_query(
                query,
                src_ip,
                dst_ip,
            )
            if indicator is not None:
                finding = _indicator_to_finding(
                    indicator,
                    str(path),
                    packet_num,
                )
                result.findings.append(finding)

    def _scan_reassembled_flows(
        self,
        tracker: FlowTracker,
        path: Path,
        result: ScanResult,
    ) -> None:
        """
        Reassemble TCP streams and scan for sensitive data
        """
        min_confidence = self._detection_config.min_confidence

        for flow in tracker.get_flows():
            key = (
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                flow.dst_port,
            )
            stream = tracker.reassemble_stream(key)
            if not stream:
                continue

            protocol = identify_protocol(stream)
            text = self._extract_scannable_text(
                stream,
                protocol,
            )

            if not text or not text.strip():
                continue

            matches = self._registry.detect(text)

            location = Location(
                source_type = "network",
                uri = str(path),
            )

            for match in matches:
                if match.score < min_confidence:
                    continue

                finding = match_to_finding(
                    match,
                    text,
                    location,
                    self._redaction_style,
                )
                result.findings.append(finding)

    def _extract_scannable_text(
        self,
        stream: bytes,
        protocol: str,
    ) -> str:
        """
        Extract text content from a reassembled stream
        """
        if protocol == "http":
            return self._extract_http_text(stream)

        if protocol in ("tls", "ssh"):
            return ""

        try:
            return stream.decode("utf-8", errors = "replace")
        except Exception:
            return ""

    def _extract_http_text(
        self,
        stream: bytes,
    ) -> str:
        """
        Extract scannable text from HTTP messages
        """
        http_msg = parse_http(stream)
        if http_msg is None:
            try:
                return stream.decode(
                    "utf-8",
                    errors = "replace",
                )
            except Exception:
                return ""

        parts: list[str] = []

        if http_msg.is_request and http_msg.uri:
            parts.append(http_msg.uri)

        for header_name in ("cookie", "authorization", "set-cookie"):
            val = http_msg.headers.get(header_name, "")
            if val:
                parts.append(val)

        if http_msg.body:
            parts.append(http_msg.body)

        return "\n".join(parts)


def _indicator_to_finding(
    indicator: ExfilIndicator,
    uri: str,
    packet_num: int,
) -> Finding:
    """
    Convert an exfiltration indicator to a Finding
    """
    rule_id, rule_name = EXFIL_RULE_MAP.get(
        indicator.indicator_type,
        ("NET_EXFIL_UNKNOWN", "Network Exfiltration Indicator"),
    )

    severity = "high" if indicator.confidence >= 0.70 else "medium"

    location = Location(
        source_type = "network",
        uri = uri,
        byte_offset = packet_num,
    )

    return Finding(
        rule_id = rule_id,
        rule_name = rule_name,
        severity = severity,
        confidence = indicator.confidence,
        location = location,
        redacted_snippet = indicator.evidence[:120],
        compliance_frameworks = [],
        remediation = indicator.description,
    )
