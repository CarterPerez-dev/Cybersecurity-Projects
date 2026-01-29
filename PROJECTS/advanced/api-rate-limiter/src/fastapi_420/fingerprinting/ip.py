"""
ⒸAngelaMos | 2025
ip.py
"""

from __future__ import annotations

from ipaddress import (
    IPv6Address,
    ip_address,
    ip_network,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


class IPExtractor:
    """
    Extract and normalize client IP addresses

    Handles IPv6 /64 prefix normalization since users control
    entire /64 prefixes (~18 quintillion addresses), making
    per-IP limits trivially bypassable without normalization.
    """
    def __init__(
        self,
        ipv6_prefix_length: int = 64,
        trusted_proxies: list[str] | None = None,
        trust_x_forwarded_for: bool = False,
    ) -> None:
        self.ipv6_prefix_length = ipv6_prefix_length
        self.trusted_proxies = set(trusted_proxies or [])
        self.trust_x_forwarded_for = trust_x_forwarded_for

    def extract(self, request: Request) -> tuple[str, str]:
        """
        Extract raw IP and normalized IP from request

        Returns tuple of (raw_ip, normalized_ip)
        """
        raw_ip = self._get_client_ip(request)
        normalized_ip = self._normalize_ip(raw_ip)
        return raw_ip, normalized_ip

    def _get_client_ip(self, request: Request) -> str:
        """
        Get client IP address, handling proxy headers if configured
        """
        if self.trust_x_forwarded_for:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                return self._parse_x_forwarded_for(forwarded_for, request)

        x_real_ip = request.headers.get("X-Real-IP")
        if x_real_ip and self._is_trusted_proxy(
                request.client.host if request.client else ""):
            return x_real_ip.strip()

        if request.client:
            return request.client.host

        return "0.0.0.0"

    def _parse_x_forwarded_for(self, header: str, request: Request) -> str:
        """
        Parse X-Forwarded-For header safely

        Uses rightmost-trusted approach: walk backwards through
        the chain and return the first IP not in trusted proxies
        """
        ips = [ip.strip() for ip in header.split(",")]

        if not self.trusted_proxies:
            return ips[0]

        for ip in reversed(ips):
            if ip not in self.trusted_proxies:
                return ip

        return ips[0] if ips else (
            request.client.host if request.client else "0.0.0.0"
        )

    def _is_trusted_proxy(self, ip: str) -> bool:
        """
        Check if IP is in trusted proxies list
        """
        return ip in self.trusted_proxies

    def _normalize_ip(self, ip_str: str) -> str:
        """
        Normalize IP address for rate limiting

        IPv6 addresses are normalized to their /64 network prefix
        since users typically control entire /64 blocks.
        """
        try:
            addr = ip_address(ip_str)
        except ValueError:
            return ip_str

        if isinstance(addr, IPv6Address):
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)

            network = ip_network(
                f"{ip_str}/{self.ipv6_prefix_length}",
                strict = False,
            )
            return str(network.network_address)

        return str(addr)

    def is_ipv6(self, ip_str: str) -> bool:
        """
        Check if IP string is IPv6
        """
        try:
            addr = ip_address(ip_str)
            return isinstance(addr, IPv6Address)
        except ValueError:
            return False

    def is_private(self, ip_str: str) -> bool:
        """
        Check if IP is a private/internal address
        """
        try:
            addr = ip_address(ip_str)
            return addr.is_private
        except ValueError:
            return False
