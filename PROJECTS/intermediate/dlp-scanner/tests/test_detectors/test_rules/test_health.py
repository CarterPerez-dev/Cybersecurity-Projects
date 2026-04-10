"""
©AngelaMos | 2026
test_health.py
"""


import pytest

from dlp_scanner.detectors.rules.health import (
    MEDICAL_RECORD_PATTERN,
    DEA_NUMBER_PATTERN,
    NPI_PATTERN,
    _validate_dea_number,
    _validate_npi,
)


class TestMedicalRecordPattern:
    @pytest.mark.parametrize(
        "text",
        [
            "MRN: 123456",
            "MRN:12345678",
            "MR# 9876543210",
            "MED-1234567890",
            "mrn 00123456",
        ],
    )
    def test_valid_mrns_match(self, text: str) -> None:
        assert (
            MEDICAL_RECORD_PATTERN.search(text) is not None
        )

    @pytest.mark.parametrize(
        "text",
        [
            "MRN: 12345",
            "MORNING coffee",
            "random text without MRN",
        ],
    )
    def test_invalid_mrns_rejected(self, text: str) -> None:
        assert (
            MEDICAL_RECORD_PATTERN.search(text) is None
        )


class TestDEANumberPattern:
    def test_valid_dea_format_matches(self) -> None:
        assert (
            DEA_NUMBER_PATTERN.search("AB1234563") is not None
        )

    def test_lowercase_rejected(self) -> None:
        assert (
            DEA_NUMBER_PATTERN.search("ab1234563") is None
        )

    def test_too_short_rejected(self) -> None:
        assert (
            DEA_NUMBER_PATTERN.search("AB12345") is None
        )


class TestDEAValidation:
    def test_valid_dea_number(self) -> None:
        assert _validate_dea_number("AB1234563") is True

    def test_invalid_check_digit(self) -> None:
        assert _validate_dea_number("AB1234560") is False

    def test_too_short(self) -> None:
        assert _validate_dea_number("AB12345") is False

    def test_non_numeric_digits(self) -> None:
        assert _validate_dea_number("ABabcdefg") is False

    def test_valid_with_9_prefix(self) -> None:
        assert _validate_dea_number("A91234563") is True


class TestNPIPattern:
    def test_ten_digit_matches(self) -> None:
        assert NPI_PATTERN.search("1234567890") is not None

    def test_nine_digit_rejected(self) -> None:
        assert NPI_PATTERN.search("123456789") is None

    def test_eleven_digit_no_exact_match(self) -> None:
        match = NPI_PATTERN.search("12345678901")
        if match is not None:
            assert len(match.group()) == 10


class TestNPIValidation:
    def test_valid_npi(self) -> None:
        assert _validate_npi("1234567893") is True

    def test_invalid_check_digit(self) -> None:
        assert _validate_npi("1234567890") is False

    def test_non_numeric(self) -> None:
        assert _validate_npi("abcdefghij") is False

    def test_too_short(self) -> None:
        assert _validate_npi("12345") is False

    def test_valid_npi_second(self) -> None:
        assert _validate_npi("1679576722") is True

    def test_all_zeros_invalid(self) -> None:
        assert _validate_npi("0000000000") is False
