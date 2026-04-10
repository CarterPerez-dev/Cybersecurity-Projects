"""
©AngelaMos | 2026
health.py
"""


import re

from dlp_scanner.detectors.base import DetectionRule


MEDICAL_RECORD_PATTERN = re.compile(
    r"\b(?:MRN|MR#|MED)\s*[-:#]?\s*\d{6,10}\b",
    re.IGNORECASE,
)

DEA_NUMBER_PATTERN = re.compile(r"\b[A-Z][A-Z9]\d{7}\b")

NPI_PATTERN = re.compile(r"\b\d{10}\b")

PHI_CONTEXT_KEYWORDS = [
    "patient",
    "diagnosis",
    "treatment",
    "medical",
    "health",
    "hospital",
    "clinical",
    "physician",
    "prescription",
    "medication",
    "lab result",
    "blood type",
    "allergies",
    "insurance",
    "claim",
    "icd",
    "cpt",
    "hcpcs",
    "hipaa",
    "phi",
    "protected health",
    "discharge",
    "admission",
    "prognosis",
]

MEDICAL_RECORD_CONTEXT = [
    "medical record",
    "mrn",
    "patient id",
    "chart number",
    "record number",
    "health record",
    "ehr",
    "emr",
]

DEA_CONTEXT = [
    "dea",
    "dea number",
    "drug enforcement",
    "prescriber",
    "controlled substance",
]

NPI_CONTEXT = [
    "npi",
    "national provider",
    "provider id",
    "provider number",
    "provider identifier",
    "cms",
]


def _validate_npi(value: str) -> bool:
    """
    Validate an NPI using Luhn with the 80840 prefix
    """
    digits = value.replace("-", "").replace(" ", "")
    if len(digits) != 10 or not digits.isdigit():
        return False

    prefixed = "80840" + digits
    total = 0
    for i, d in enumerate(reversed(prefixed)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _validate_dea_number(value: str) -> bool:
    """
    Validate a DEA number using its check digit algorithm
    """
    if len(value) != 9:
        return False
    digits = value[2 :]
    if not digits.isdigit():
        return False

    odd_sum = (int(digits[0]) + int(digits[2]) + int(digits[4]))
    even_sum = (int(digits[1]) + int(digits[3]) + int(digits[5]))
    check = (odd_sum + even_sum * 2) % 10
    return check == int(digits[6])


HEALTH_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id = "HEALTH_MEDICAL_RECORD",
        rule_name = "Medical Record Number",
        pattern = MEDICAL_RECORD_PATTERN,
        base_score = 0.55,
        context_keywords = MEDICAL_RECORD_CONTEXT,
        compliance_frameworks = ["HIPAA"],
    ),
    DetectionRule(
        rule_id = "HEALTH_DEA_NUMBER",
        rule_name = "DEA Registration Number",
        pattern = DEA_NUMBER_PATTERN,
        base_score = 0.35,
        context_keywords = DEA_CONTEXT,
        validator = _validate_dea_number,
        compliance_frameworks = ["HIPAA"],
    ),
    DetectionRule(
        rule_id = "HEALTH_NPI",
        rule_name = "National Provider Identifier",
        pattern = NPI_PATTERN,
        base_score = 0.10,
        context_keywords = NPI_CONTEXT,
        validator = _validate_npi,
        compliance_frameworks = ["HIPAA"],
    ),
]
