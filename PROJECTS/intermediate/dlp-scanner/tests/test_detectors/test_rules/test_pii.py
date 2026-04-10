"""
©AngelaMos | 2026
test_pii.py
"""


import pytest

from dlp_scanner.detectors.rules.pii import (
    SSN_PATTERN,
    EMAIL_PATTERN,
    PHONE_US_PATTERN,
    IPV4_PATTERN,
    _validate_ssn,
)


class TestSSNPattern:
    @pytest.mark.parametrize(
        "text",
        [
            "234-56-7890",
            "567-89-0123",
            "001-01-0001",
            "899-99-9999",
        ],
    )
    def test_valid_ssns_match(self, text: str) -> None:
        assert SSN_PATTERN.search(text) is not None

    @pytest.mark.parametrize(
        "text",
        [
            "000-45-6789",
            "666-45-6789",
            "900-45-6789",
            "999-45-6789",
            "123-00-6789",
            "123-45-0000",
        ],
    )
    def test_invalid_ssns_rejected(self, text: str) -> None:
        match = SSN_PATTERN.search(text)
        if match is not None:
            assert not _validate_ssn(match.group())


class TestSSNValidation:
    def test_valid_ssn(self) -> None:
        assert _validate_ssn("234-56-7890") is True

    def test_invalid_area_000(self) -> None:
        assert _validate_ssn("000-45-6789") is False

    def test_invalid_area_666(self) -> None:
        assert _validate_ssn("666-45-6789") is False

    def test_invalid_area_900_plus(self) -> None:
        assert _validate_ssn("950-45-6789") is False

    def test_invalid_group_00(self) -> None:
        assert _validate_ssn("123-00-6789") is False

    def test_invalid_serial_0000(self) -> None:
        assert _validate_ssn("123-45-0000") is False

    def test_bare_format(self) -> None:
        assert _validate_ssn("234567890") is True

    def test_non_numeric(self) -> None:
        assert _validate_ssn("abc-de-fghi") is False


class TestEmailPattern:
    @pytest.mark.parametrize(
        "text",
        [
            "user@example.com",
            "first.last@company.org",
            "user+tag@domain.co.uk",
            "test_email@test.museum",
        ],
    )
    def test_valid_emails_match(self, text: str) -> None:
        assert EMAIL_PATTERN.search(text) is not None

    @pytest.mark.parametrize(
        "text",
        [
            "not-an-email",
            "@nodomain",
            "user@",
            "user@.com",
        ],
    )
    def test_invalid_emails_rejected(self, text: str) -> None:
        assert EMAIL_PATTERN.search(text) is None


class TestPhoneUSPattern:
    @pytest.mark.parametrize(
        "text",
        [
            "(555) 234-5678",
            "555-234-5678",
            "555.234.5678",
            "+1 555-234-5678",
            "1-555-234-5678",
        ],
    )
    def test_valid_phones_match(self, text: str) -> None:
        assert PHONE_US_PATTERN.search(text) is not None


class TestIPv4Pattern:
    @pytest.mark.parametrize(
        "text",
        [
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "172.16.0.1",
        ],
    )
    def test_valid_ips_match(self, text: str) -> None:
        assert IPV4_PATTERN.search(text) is not None

    @pytest.mark.parametrize(
        "text",
        [
            "256.1.1.1",
            "1.1.1.256",
            "999.999.999.999",
        ],
    )
    def test_invalid_ips_rejected(self, text: str) -> None:
        assert IPV4_PATTERN.search(text) is None
