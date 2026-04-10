"""
©AngelaMos | 2026
financial.py
"""


import re

from dlp_scanner.detectors.base import DetectionRule


VISA_PATTERN = re.compile(
    r"\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
)

MASTERCARD_PATTERN = re.compile(
    r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)"
    r"[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
)

AMEX_PATTERN = re.compile(r"\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b")

DISCOVER_PATTERN = re.compile(
    r"\b6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
)

IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"
)

NHS_PATTERN = re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b")


def luhn_check(number: str) -> bool:
    """
    Validate a number using the Luhn algorithm
    """
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False

    odd_digits = digits[-1 ::-2]
    even_digits = digits[-2 ::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def iban_check(value: str) -> bool:
    """
    Validate an IBAN using the mod-97 algorithm
    """
    cleaned = value.replace(" ", "").upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False

    rearranged = cleaned[4 :] + cleaned[: 4]
    numeric = ""
    for char in rearranged:
        if char.isalpha():
            numeric += str(ord(char) - ord("A") + 10)
        else:
            numeric += char

    return int(numeric) % 97 == 1


def nhs_check(value: str) -> bool:
    """
    Validate a UK NHS number using mod-11
    """
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False

    weights = range(10, 1, -1)
    total = sum(
        int(d) * w for d, w in zip(digits[: 9], weights, strict = False)
    )
    remainder = 11 - (total % 11)
    if remainder == 11:
        remainder = 0
    if remainder == 10:
        return False
    return remainder == int(digits[9])


CREDIT_CARD_CONTEXT = [
    "credit card",
    "card number",
    "cc",
    "cvv",
    "cvc",
    "expiry",
    "expiration",
    "visa",
    "mastercard",
    "amex",
    "card no",
    "payment card",
    "pan",
]

IBAN_CONTEXT = [
    "iban",
    "bank account",
    "account number",
    "swift",
    "bic",
    "wire transfer",
    "bank transfer",
]

NHS_CONTEXT = [
    "nhs",
    "nhs number",
    "national health",
    "health service",
    "patient id",
    "patient number",
]

FINANCIAL_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id = "FIN_CREDIT_CARD_VISA",
        rule_name = "Visa Credit Card Number",
        pattern = VISA_PATTERN,
        base_score = 0.50,
        context_keywords = CREDIT_CARD_CONTEXT,
        validator = luhn_check,
        compliance_frameworks = ["PCI_DSS",
                                 "GLBA"],
    ),
    DetectionRule(
        rule_id = "FIN_CREDIT_CARD_MC",
        rule_name = "Mastercard Credit Card Number",
        pattern = MASTERCARD_PATTERN,
        base_score = 0.50,
        context_keywords = CREDIT_CARD_CONTEXT,
        validator = luhn_check,
        compliance_frameworks = ["PCI_DSS",
                                 "GLBA"],
    ),
    DetectionRule(
        rule_id = "FIN_CREDIT_CARD_AMEX",
        rule_name = "American Express Card Number",
        pattern = AMEX_PATTERN,
        base_score = 0.50,
        context_keywords = CREDIT_CARD_CONTEXT,
        validator = luhn_check,
        compliance_frameworks = ["PCI_DSS",
                                 "GLBA"],
    ),
    DetectionRule(
        rule_id = "FIN_CREDIT_CARD_DISC",
        rule_name = "Discover Card Number",
        pattern = DISCOVER_PATTERN,
        base_score = 0.50,
        context_keywords = CREDIT_CARD_CONTEXT,
        validator = luhn_check,
        compliance_frameworks = ["PCI_DSS",
                                 "GLBA"],
    ),
    DetectionRule(
        rule_id = "FIN_IBAN",
        rule_name = "IBAN Number",
        pattern = IBAN_PATTERN,
        base_score = 0.40,
        context_keywords = IBAN_CONTEXT,
        validator = iban_check,
        compliance_frameworks = ["GDPR",
                                 "GLBA"],
    ),
    DetectionRule(
        rule_id = "FIN_NHS_NUMBER",
        rule_name = "UK NHS Number",
        pattern = NHS_PATTERN,
        base_score = 0.15,
        context_keywords = NHS_CONTEXT,
        validator = nhs_check,
        compliance_frameworks = ["GDPR"],
    ),
]
