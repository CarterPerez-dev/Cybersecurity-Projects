"""
ⒸAngelaMos | 2026
test_filters.py

Basic happy path tests for BPF filter builder
"""

import pytest

from netanal.models import Protocol
from netanal.exceptions import ValidationError
from netanal.filters import FilterBuilder, combine_filters


class TestFilterBuilder:
    """
    Tests for the FilterBuilder class
    """
    def test_empty_filter(self):
        """
        Verify empty builder returns None
        """
        builder = FilterBuilder()
        assert builder.build() is None

    def test_single_protocol(self):
        """
        Verify single protocol filter
        """
        result = FilterBuilder().protocol(Protocol.TCP).build()
        assert result == "(tcp)"

    def test_single_port(self):
        """
        Verify single port filter
        """
        result = FilterBuilder().port(80).build()
        assert result == "port 80"

    def test_src_port(self):
        """
        Verify source port filter
        """
        result = FilterBuilder().src_port(443).build()
        assert result == "src port 443"

    def test_dst_port(self):
        """
        Verify destination port filter
        """
        result = FilterBuilder().dst_port(8080).build()
        assert result == "dst port 8080"

    def test_host_filter(self):
        """
        Verify host IP filter
        """
        result = FilterBuilder().host("192.168.1.1").build()
        assert result == "host 192.168.1.1"

    def test_src_host(self):
        """
        Verify source host filter
        """
        result = FilterBuilder().src_host("10.0.0.1").build()
        assert result == "src host 10.0.0.1"

    def test_dst_host(self):
        """
        Verify destination host filter
        """
        result = FilterBuilder().dst_host("10.0.0.2").build()
        assert result == "dst host 10.0.0.2"

    def test_network_filter(self):
        """
        Verify network CIDR filter
        """
        result = FilterBuilder().net("192.168.0.0/24").build()
        assert result == "net 192.168.0.0/24"

    def test_chained_filters_and(self):
        """
        Verify multiple filters combine with AND by default
        """
        result = (FilterBuilder().protocol(Protocol.TCP).port(80).build())
        assert result == "(tcp) and port 80"

    def test_chained_filters_or(self):
        """
        Verify OR operator joins expressions
        """
        result = (
            FilterBuilder().port(80).port(443).build(operator = "or")
        )
        assert result == "port 80 or port 443"

    def test_complex_filter(self):
        """
        Verify complex filter chain builds correctly
        """
        result = (
            FilterBuilder().protocol(
                Protocol.TCP
            ).host("192.168.1.100").port(443).build()
        )
        assert "(tcp)" in result
        assert "host 192.168.1.100" in result
        assert "port 443" in result

    def test_reset(self):
        """
        Verify reset clears all expressions
        """
        builder = FilterBuilder().port(80).port(443)
        builder.reset()
        assert builder.build() is None


class TestCombineFilters:
    """
    Tests for the combine_filters helper function
    """
    def test_combine_empty(self):
        """
        Verify empty list returns None
        """
        assert combine_filters([]) is None

    def test_combine_single(self):
        """
        Verify single filter returns as-is
        """
        assert combine_filters(["tcp port 80"]) == "tcp port 80"

    def test_combine_multiple_and(self):
        """
        Verify multiple filters combine with AND
        """
        result = combine_filters(["tcp", "port 80"], operator = "and")
        assert result == "(tcp) and (port 80)"

    def test_combine_multiple_or(self):
        """
        Verify multiple filters combine with OR
        """
        result = combine_filters(["port 80", "port 443"], operator = "or")
        assert result == "(port 80) or (port 443)"


class TestFilterValidation:
    """
    Tests for filter input validation
    """
    def test_invalid_port_too_high(self):
        """
        Verify port > 65535 raises ValidationError
        """
        with pytest.raises(ValidationError):
            FilterBuilder().port(70000)

    def test_invalid_port_negative(self):
        """
        Verify negative port raises ValidationError
        """
        with pytest.raises(ValidationError):
            FilterBuilder().port(-1)

    def test_invalid_ip_address(self):
        """
        Verify malformed IP raises ValidationError
        """
        with pytest.raises(ValidationError):
            FilterBuilder().host("not.an.ip")

    def test_invalid_network(self):
        """
        Verify malformed CIDR raises ValidationError
        """
        with pytest.raises(ValidationError):
            FilterBuilder().net("invalid/network")

    def test_valid_port_boundaries(self):
        """
        Verify port 0 and 65535 are valid
        """
        FilterBuilder().port(0)
        FilterBuilder().port(65535)

    def test_valid_ipv6(self):
        """
        Verify IPv6 addresses are accepted
        """
        FilterBuilder().host("::1")
        FilterBuilder().host("2001:db8::1")
