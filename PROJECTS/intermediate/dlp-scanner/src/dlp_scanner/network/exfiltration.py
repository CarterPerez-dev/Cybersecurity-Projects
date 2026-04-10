"""
©AngelaMos | 2026
exfiltration.py
"""


import re
from collections import defaultdict
from dataclasses import dataclass

import structlog

from dlp_scanner.constants import (
    DEFAULT_DNS_ENTROPY_THRESHOLD,
)
from dlp_scanner.detectors.entropy import (
    shannon_entropy_str,
)
from dlp_scanner.network.protocols import DnsQuery


log = structlog.get_logger()

DNS_LABEL_MAX_NORMAL: int = 50
DNS_QNAME_MAX_NORMAL: int = 100
TXT_VOLUME_THRESHOLD: float = 0.05

BASE64_PATTERN = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
HEX_PATTERN = re.compile(rb"[0-9A-Fa-f]{64,}")


@dataclass(frozen = True, slots = True)
class ExfilIndicator:
    """
    An indicator of potential data exfiltration
    """

    indicator_type: str
    description: str
    confidence: float
    source_ip: str
    dest_ip: str
    evidence: str


class DnsExfilDetector:
    """
    Detects DNS-based data exfiltration patterns
    """
    def __init__(
        self,
        entropy_threshold: float = (DEFAULT_DNS_ENTROPY_THRESHOLD),
    ) -> None:
        self._entropy_threshold = entropy_threshold
        self._indicators: list[ExfilIndicator] = []
        self._domain_txt_counts: dict[str, int] = defaultdict(int)
        self._domain_total_counts: dict[str, int] = defaultdict(int)

    def analyze_query(
        self,
        query: DnsQuery,
        src_ip: str,
        dst_ip: str,
    ) -> ExfilIndicator | None:
        """
        Analyze a single DNS query for exfiltration
        """
        name = query.name
        domain = _extract_base_domain(name)

        self._domain_total_counts[domain] += 1
        if query.query_type == "TXT":
            self._domain_txt_counts[domain] += 1

        indicator = self._check_label_length(name, src_ip, dst_ip)
        if indicator is not None:
            self._indicators.append(indicator)
            return indicator

        indicator = self._check_subdomain_entropy(name, src_ip, dst_ip)
        if indicator is not None:
            self._indicators.append(indicator)
            return indicator

        indicator = self._check_qname_length(name, src_ip, dst_ip)
        if indicator is not None:
            self._indicators.append(indicator)
            return indicator

        return None

    def check_txt_volume(
        self,
    ) -> list[ExfilIndicator]:
        """
        Check for suspicious TXT query volume ratios
        """
        indicators: list[ExfilIndicator] = []

        for domain, txt_count in (self._domain_txt_counts.items()):
            total = self._domain_total_counts.get(domain, 0)
            if total == 0:
                continue

            ratio = txt_count / total
            if ratio > TXT_VOLUME_THRESHOLD:
                indicator = ExfilIndicator(
                    indicator_type = "dns_txt_volume",
                    description = (
                        f"High TXT query ratio "
                        f"({ratio:.1%}) for "
                        f"{domain}"
                    ),
                    confidence = min(0.90,
                                     0.50 + ratio),
                    source_ip = "",
                    dest_ip = "",
                    evidence = (f"{txt_count} TXT / "
                                f"{total} total"),
                )
                indicators.append(indicator)

        self._indicators.extend(indicators)
        return indicators

    def get_indicators(
        self,
    ) -> list[ExfilIndicator]:
        """
        Return all collected exfiltration indicators
        """
        return list(self._indicators)

    def _check_label_length(
        self,
        name: str,
        src_ip: str,
        dst_ip: str,
    ) -> ExfilIndicator | None:
        """
        Flag suspiciously long DNS labels
        """
        for label in name.split("."):
            if len(label) > DNS_LABEL_MAX_NORMAL:
                return ExfilIndicator(
                    indicator_type = ("dns_long_label"),
                    description = (
                        f"DNS label length "
                        f"{len(label)} exceeds "
                        f"normal threshold"
                    ),
                    confidence = 0.75,
                    source_ip = src_ip,
                    dest_ip = dst_ip,
                    evidence = name,
                )
        return None

    def _check_subdomain_entropy(
        self,
        name: str,
        src_ip: str,
        dst_ip: str,
    ) -> ExfilIndicator | None:
        """
        Flag high-entropy subdomains suggesting tunneling
        """
        parts = name.split(".")
        if len(parts) < 3:
            return None

        subdomain = ".".join(parts[:-2])
        if not subdomain:
            return None

        entropy = shannon_entropy_str(subdomain)
        if entropy > self._entropy_threshold:
            return ExfilIndicator(
                indicator_type = ("dns_high_entropy"),
                description = (
                    f"High subdomain entropy "
                    f"({entropy:.2f}) suggesting "
                    f"DNS tunneling"
                ),
                confidence = min(
                    0.95,
                    0.50 + (entropy - 3.0) * 0.15,
                ),
                source_ip = src_ip,
                dest_ip = dst_ip,
                evidence = name,
            )
        return None

    def _check_qname_length(
        self,
        name: str,
        src_ip: str,
        dst_ip: str,
    ) -> ExfilIndicator | None:
        """
        Flag excessively long QNAMEs
        """
        if len(name) > DNS_QNAME_MAX_NORMAL:
            return ExfilIndicator(
                indicator_type = "dns_long_qname",
                description = (
                    f"QNAME length {len(name)} "
                    f"exceeds normal threshold"
                ),
                confidence = 0.65,
                source_ip = src_ip,
                dest_ip = dst_ip,
                evidence = name,
            )
        return None


def detect_base64_payload(
    data: bytes,
    src_ip: str = "",
    dst_ip: str = "",
) -> list[ExfilIndicator]:
    """
    Detect base64 or hex-encoded data in payloads
    """
    indicators: list[ExfilIndicator] = []

    for m in BASE64_PATTERN.finditer(data):
        matched = m.group()
        indicators.append(
            ExfilIndicator(
                indicator_type = "base64_payload",
                description = (
                    f"Base64-encoded data "
                    f"({len(matched)} bytes) "
                    f"in network payload"
                ),
                confidence = 0.55,
                source_ip = src_ip,
                dest_ip = dst_ip,
                evidence = matched[: 80].decode(
                    "ascii",
                    errors = "replace"
                ),
            )
        )

    for m in HEX_PATTERN.finditer(data):
        matched = m.group()
        indicators.append(
            ExfilIndicator(
                indicator_type = "hex_payload",
                description = (
                    f"Hex-encoded data "
                    f"({len(matched)} bytes) "
                    f"in network payload"
                ),
                confidence = 0.45,
                source_ip = src_ip,
                dest_ip = dst_ip,
                evidence = matched[: 80].decode(
                    "ascii",
                    errors = "replace"
                ),
            )
        )

    return indicators


def _extract_base_domain(name: str) -> str:
    """
    Extract the registerable domain from a QNAME
    """
    parts = name.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2 :])
    return name
