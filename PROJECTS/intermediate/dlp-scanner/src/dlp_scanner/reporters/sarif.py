"""
©AngelaMos | 2026
sarif.py
"""


from typing import Any

import orjson

from dlp_scanner.constants import SARIF_SEVERITY_MAP
from dlp_scanner.models import Finding, ScanResult


SARIF_SCHEMA: str = (
    "https://raw.githubusercontent.com/"
    "oasis-tcs/sarif-spec/main/sarif-2.1/"
    "schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION: str = "2.1.0"
TOOL_NAME: str = "dlp-scanner"


class SarifReporter:
    """
    SARIF 2.1.0 output for CI/CD integration
    """
    def generate(self, result: ScanResult) -> str:
        """
        Generate SARIF 2.1.0 report as JSON string
        """
        sarif = _build_sarif(result)
        return orjson.dumps(
            sarif,
            option = (orjson.OPT_INDENT_2
                      | orjson.OPT_NON_STR_KEYS),
        ).decode("utf-8")


def _build_sarif(
    result: ScanResult,
) -> dict[str,
          Any]:
    """
    Build complete SARIF document
    """
    rules = _collect_rules(result.findings)
    results = [_build_result(f, rules) for f in result.findings]

    return {
        "$schema":
        SARIF_SCHEMA,
        "version":
        SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": (result.tool_version),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _collect_rules(
    findings: list[Finding],
) -> dict[str,
          dict[str,
               Any]]:
    """
    Collect unique rules from findings
    """
    rules: dict[str, dict[str, Any]] = {}

    for finding in findings:
        if finding.rule_id in rules:
            continue

        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.rule_name,
            "shortDescription": {
                "text": finding.rule_name,
            },
            "properties": {
                "compliance_frameworks": (finding.compliance_frameworks),
            },
        }

    return rules


def _build_result(
    finding: Finding,
    rules: dict[str,
                dict[str,
                     Any]],
) -> dict[str,
          Any]:
    """
    Build a single SARIF result entry
    """
    level = SARIF_SEVERITY_MAP.get(finding.severity, "note")

    location = _build_location(finding)

    return {
        "ruleId": finding.rule_id,
        "ruleIndex": list(rules.keys()).index(finding.rule_id),
        "level": level,
        "message": {
            "text": (
                f"{finding.rule_name} detected "
                f"with {finding.confidence:.0%} "
                f"confidence"
            ),
        },
        "locations": [location],
        "properties": {
            "confidence": round(finding.confidence,
                                4),
            "redactedSnippet": (finding.redacted_snippet),
            "complianceFrameworks": (finding.compliance_frameworks),
            "remediation": finding.remediation,
        },
    }


def _build_location(
    finding: Finding,
) -> dict[str,
          Any]:
    """
    Build SARIF location from finding
    """
    loc = finding.location

    physical: dict[str,
                   Any] = {
                       "artifactLocation": {
                           "uri": loc.uri
                       },
                   }

    region: dict[str, Any] = {}
    if loc.line is not None:
        region["startLine"] = loc.line
    if loc.column is not None:
        region["startColumn"] = loc.column
    if region:
        physical["region"] = region

    result: dict[str,
                 Any] = {
                     "physicalLocation": physical,
                 }

    if loc.table_name:
        result["logicalLocations"] = [
            {
                "name": loc.table_name,
                "kind": "table",
            }
        ]

    return result
