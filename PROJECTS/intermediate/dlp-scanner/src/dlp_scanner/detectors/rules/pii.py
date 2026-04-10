"""
©AngelaMos | 2026
pii.py
"""


import re

from dlp_scanner.detectors.base import DetectionRule


SSN_PATTERN = re.compile(
    r"\b(?!000|666|9\d{2})\d{3}"
    r"[-\s]?"
    r"(?!00)\d{2}"
    r"[-\s]?"
    r"(?!0000)\d{4}\b"
)

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

PHONE_US_PATTERN = re.compile(
    r"\b(?:\+?1[-.\s]?)?"
    r"(?:\(?[2-9]\d{2}\)?[-.\s]?)"
    r"[2-9]\d{2}[-.\s]?\d{4}\b"
)

PHONE_E164_PATTERN = re.compile(r"\+[1-9]\d{6,14}\b")

PASSPORT_US_PATTERN = re.compile(r"\b[A-Z]{1,2}\d{6,7}\b")

PASSPORT_UK_PATTERN = re.compile(r"\b\d{9}\b")

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

DRIVERS_LICENSE_CA_PATTERN = re.compile(r"\b[A-Z]\d{7}\b")
DRIVERS_LICENSE_FL_PATTERN = re.compile(r"\b[A-Z]\d{12}\b")
DRIVERS_LICENSE_IL_PATTERN = re.compile(r"\b[A-Z]\d{11}\b")


def _validate_ssn(value: str) -> bool:
    """
    Validate SSN area, group, and serial numbers
    """
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 9 or not digits.isdigit():
        return False

    area = int(digits[0 : 3])
    group = int(digits[3 : 5])
    serial = int(digits[5 : 9])

    if area in {0, 666} or area >= 900:
        return False
    if group == 0:
        return False
    return serial != 0


SSN_CONTEXT = [
    "ssn",
    "social security",
    "social security number",
    "ss#",
    "taxpayer id",
    "sin",
    "tax id",
]

EMAIL_CONTEXT = [
    "email",
    "e-mail",
    "mail",
    "contact",
    "reach at",
]

PHONE_CONTEXT = [
    "phone",
    "mobile",
    "cell",
    "tel",
    "telephone",
    "fax",
    "contact number",
    "call",
]

PASSPORT_CONTEXT = [
    "passport",
    "pass no",
    "travel document",
    "passport number",
    "document number",
]

DRIVERS_LICENSE_CONTEXT = [
    "driver's license",
    "drivers license",
    "driver license",
    "dl#",
    "dl number",
    "license number",
    "licence number",
]

PII_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id = "PII_SSN",
        rule_name = "US Social Security Number",
        pattern = SSN_PATTERN,
        base_score = 0.45,
        context_keywords = SSN_CONTEXT,
        validator = _validate_ssn,
        compliance_frameworks = [
            "HIPAA",
            "CCPA",
            "GLBA",
            "GDPR",
        ],
    ),
    DetectionRule(
        rule_id = "PII_EMAIL",
        rule_name = "Email Address",
        pattern = EMAIL_PATTERN,
        base_score = 0.30,
        context_keywords = EMAIL_CONTEXT,
        compliance_frameworks = ["GDPR",
                                 "CCPA"],
    ),
    DetectionRule(
        rule_id = "PII_PHONE",
        rule_name = "US Phone Number",
        pattern = PHONE_US_PATTERN,
        base_score = 0.25,
        context_keywords = PHONE_CONTEXT,
        compliance_frameworks = [
            "GDPR",
            "CCPA",
            "HIPAA",
        ],
    ),
    DetectionRule(
        rule_id = "PII_PHONE_INTL",
        rule_name = "International Phone Number",
        pattern = PHONE_E164_PATTERN,
        base_score = 0.30,
        context_keywords = PHONE_CONTEXT,
        compliance_frameworks = ["GDPR",
                                 "CCPA"],
    ),
    DetectionRule(
        rule_id = "PII_PASSPORT_US",
        rule_name = "US Passport Number",
        pattern = PASSPORT_US_PATTERN,
        base_score = 0.15,
        context_keywords = PASSPORT_CONTEXT,
        compliance_frameworks = ["GDPR",
                                 "CCPA"],
    ),
    DetectionRule(
        rule_id = "PII_PASSPORT_UK",
        rule_name = "UK Passport Number",
        pattern = PASSPORT_UK_PATTERN,
        base_score = 0.10,
        context_keywords = PASSPORT_CONTEXT,
        compliance_frameworks = ["GDPR"],
    ),
    DetectionRule(
        rule_id = "PII_IPV4",
        rule_name = "IPv4 Address",
        pattern = IPV4_PATTERN,
        base_score = 0.15,
        context_keywords = [],
        compliance_frameworks = ["GDPR"],
    ),
    DetectionRule(
        rule_id = "PII_DRIVERS_LICENSE",
        rule_name = "US Driver's License (CA)",
        pattern = DRIVERS_LICENSE_CA_PATTERN,
        base_score = 0.10,
        context_keywords = DRIVERS_LICENSE_CONTEXT,
        compliance_frameworks = ["CCPA",
                                 "HIPAA"],
    ),
    DetectionRule(
        rule_id = "PII_DRIVERS_LICENSE_FL",
        rule_name = "US Driver's License (FL)",
        pattern = DRIVERS_LICENSE_FL_PATTERN,
        base_score = 0.10,
        context_keywords = DRIVERS_LICENSE_CONTEXT,
        compliance_frameworks = ["CCPA",
                                 "HIPAA"],
    ),
    DetectionRule(
        rule_id = "PII_DRIVERS_LICENSE_IL",
        rule_name = "US Driver's License (IL)",
        pattern = DRIVERS_LICENSE_IL_PATTERN,
        base_score = 0.10,
        context_keywords = DRIVERS_LICENSE_CONTEXT,
        compliance_frameworks = ["CCPA",
                                 "HIPAA"],
    ),
]
