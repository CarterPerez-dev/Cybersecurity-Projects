"""
©AngelaMos | 2026
scoring.py
"""


from dlp_scanner.compliance import (
    get_frameworks_for_rule,
    get_remediation_for_rule,
    score_to_severity,
)
from dlp_scanner.constants import RedactionStyle
from dlp_scanner.detectors.base import DetectorMatch
from dlp_scanner.models import Finding, Location
from dlp_scanner.redaction import redact


def match_to_finding(
    match: DetectorMatch,
    text: str,
    location: Location,
    redaction_style: RedactionStyle,
) -> Finding:
    """
    Convert a detector match into a fully classified finding
    """
    severity = score_to_severity(match.score)
    frameworks = get_frameworks_for_rule(match.rule_id)
    if match.compliance_frameworks:
        combined = (
            set(frameworks) | set(match.compliance_frameworks)
        )
        frameworks = sorted(combined)
    remediation = get_remediation_for_rule(match.rule_id)

    snippet = redact(
        text,
        match.start,
        match.end,
        style = redaction_style,
    )

    return Finding(
        rule_id = match.rule_id,
        rule_name = match.rule_name,
        severity = severity,
        confidence = match.score,
        location = location,
        redacted_snippet = snippet,
        compliance_frameworks = frameworks,
        remediation = remediation,
    )
