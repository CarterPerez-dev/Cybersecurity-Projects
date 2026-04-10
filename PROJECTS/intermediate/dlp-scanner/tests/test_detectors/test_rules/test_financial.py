"""
©AngelaMos | 2026
test_financial.py
"""


import pytest

from dlp_scanner.detectors.rules.financial import (
    VISA_PATTERN,
    MASTERCARD_PATTERN,
    AMEX_PATTERN,
    IBAN_PATTERN,
    luhn_check,
    iban_check,
    nhs_check,
)


class TestLuhnAlgorithm:
    @pytest.mark.parametrize(
        "number",
        [
            "4532015112830366",
            "4916338506082832",
            "5425233430109903",
            "2223000048410010",
            "374245455400126",
            "6011000990139424",
        ],
    )
    def test_valid_cards_pass_luhn(self, number: str) -> None:
        assert luhn_check(number) is True

    @pytest.mark.parametrize(
        "number",
        [
            "4532015112830367",
            "1234567890123456",
            "1111111111111112",
            "9999999999999991",
        ],
    )
    def test_invalid_cards_fail_luhn(self, number: str) -> None:
        assert luhn_check(number) is False

    def test_too_short_fails(self) -> None:
        assert luhn_check("123456") is False

    def test_with_spaces(self) -> None:
        assert luhn_check("4532 0151 1283 0366") is True

    def test_with_dashes(self) -> None:
        assert luhn_check("4532-0151-1283-0366") is True


class TestIBANCheck:
    @pytest.mark.parametrize(
        "iban",
        [
            "GB29NWBK60161331926819",
            "DE89370400440532013000",
            "FR7630006000011234567890189",
            "NL91ABNA0417164300",
        ],
    )
    def test_valid_ibans(self, iban: str) -> None:
        assert iban_check(iban) is True

    @pytest.mark.parametrize(
        "iban",
        [
            "GB29NWBK60161331926818",
            "XX00INVALID",
            "DE00000000000000000000",
            "SHORT",
        ],
    )
    def test_invalid_ibans(self, iban: str) -> None:
        assert iban_check(iban) is False

    def test_iban_with_spaces(self) -> None:
        assert iban_check("GB29 NWBK 6016 1331 9268 19") is True


class TestNHSCheck:
    def test_valid_nhs_number(self) -> None:
        assert nhs_check("9434765919") is True

    def test_invalid_nhs_number(self) -> None:
        assert nhs_check("1234567890") is False

    def test_nhs_too_short(self) -> None:
        assert nhs_check("12345") is False

    def test_nhs_non_numeric(self) -> None:
        assert nhs_check("abcdefghij") is False


class TestCreditCardPatterns:
    def test_visa_pattern_matches(self) -> None:
        assert VISA_PATTERN.search("4532015112830366") is not None

    def test_mastercard_classic_matches(self) -> None:
        assert MASTERCARD_PATTERN.search("5425233430109903") is not None

    def test_mastercard_2series_matches(self) -> None:
        assert MASTERCARD_PATTERN.search("2223000048410010") is not None

    def test_amex_matches(self) -> None:
        assert AMEX_PATTERN.search("374245455400126") is not None

    def test_visa_with_spaces(self) -> None:
        assert VISA_PATTERN.search("4532 0151 1283 0366") is not None

    def test_visa_with_dashes(self) -> None:
        assert VISA_PATTERN.search("4532-0151-1283-0366") is not None


class TestIBANPattern:
    def test_iban_pattern_matches_gb(self) -> None:
        assert IBAN_PATTERN.search("GB29NWBK60161331926819") is not None

    def test_iban_pattern_matches_de(self) -> None:
        assert IBAN_PATTERN.search("DE89370400440532013000") is not None
