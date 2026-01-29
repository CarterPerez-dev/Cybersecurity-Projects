"""
©AngelaMos | 2025
IDOR/BOLA vulnerability scanner

Based on OWASP API1:2023 - Broken Object Level Authorization
"""

from __future__ import annotations

import re
from typing import Any

from core.enums import ScanStatus, Severity, TestType
from schemas.test_result_schemas import TestResultCreate
from .base_scanner import BaseScanner
from .payloads import IDORPayloads


class IDORScanner(BaseScanner):
    """
    Tests for Insecure Direct Object Reference (IDOR) vulnerabilities

    Also known as Broken Object Level Authorization (BOLA).
    Ranked #1 in OWASP API Security Top 10 2023.

    Detects:
    - Sequential ID enumeration
    - UUID exposure and access
    - Missing authorization checks on object access

    Maps to OWASP API Security Top 10 2023: API1:2023
    """
    def scan(self) -> TestResultCreate:
        """
        Execute IDOR/BOLA tests

        Returns:
            TestResultCreate: Scan result with findings
        """
        id_enumeration_test = self._test_id_enumeration()

        if id_enumeration_test["vulnerable"]:
            return self._create_vulnerable_result(
                details =
                f"IDOR vulnerability detected: {id_enumeration_test['vulnerability_type']}",
                evidence = id_enumeration_test,
                severity = Severity.HIGH,
                recommendations = [
                    "Implement proper authorization checks for all object access",
                    "Verify user owns/has permission to access requested resource",
                    "Use UUIDs instead of sequential IDs (but still check authorization)",
                    "Implement access control lists (ACLs) or role-based access control (RBAC)",
                    "Log and monitor unauthorized access attempts",
                ],
            )

        predictable_id_test = self._test_predictable_id_patterns()

        if predictable_id_test["vulnerable"]:
            return self._create_vulnerable_result(
                details =
                "Predictable ID patterns detected enabling enumeration",
                evidence = predictable_id_test,
                severity = Severity.MEDIUM,
                recommendations = [
                    "Use non-sequential, non-predictable identifiers (UUIDs)",
                    "Implement rate limiting on ID-based endpoints",
                    "Add authorization checks regardless of ID format",
                ],
            )

        return TestResultCreate(
            test_name = TestType.IDOR,
            status = ScanStatus.SAFE,
            severity = Severity.INFO,
            details = "No IDOR/BOLA vulnerabilities detected",
            evidence_json = {
                "id_enumeration_test": id_enumeration_test,
                "predictable_id_test": predictable_id_test,
            },
            recommendations_json = [
                "Authorization checks appear to be in place",
                "Continue monitoring for authorization bypasses",
            ],
        )

    def _test_id_enumeration(self) -> dict[str, Any]:
        """
        Test for ID enumeration vulnerabilities

        Attempts to access resources with modified IDs to detect
        missing authorization checks.

        Returns:
            dict[str, Any]: ID enumeration test results
        """
        extracted_ids = self._extract_ids_from_response()

        if not extracted_ids:
            return {
                "vulnerable": False,
                "description": "No IDs found in endpoint responses",
            }

        numeric_test = self._test_numeric_id_manipulation(
            extracted_ids
        )
        if numeric_test["vulnerable"]:
            return numeric_test

        string_test = self._test_string_id_manipulation(extracted_ids)
        if string_test["vulnerable"]:
            return string_test

        return {
            "vulnerable": False,
            "ids_tested": len(extracted_ids),
            "description": "ID enumeration not possible or blocked",
        }

    def _extract_ids_from_response(self) -> list[Any]:
        """
        Extract potential IDs from API response

        Looks for numeric IDs, UUIDs, and other identifier patterns.

        Returns:
            list[Any]: List of extracted IDs
        """
        try:
            response = self.make_request("GET", "/")

            if response.status_code != 200:
                return []

            response_text = response.text

            uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
            uuids = re.findall(
                uuid_pattern,
                response_text,
                re.IGNORECASE
            )

            numeric_id_pattern = r'"id"\s*:\s*(\d+)'
            numeric_ids = re.findall(
                numeric_id_pattern,
                response_text
            )

            ids = []
            ids.extend(uuids[: 3])
            ids.extend([int(nid) for nid in numeric_ids[: 3]])

            return ids

        except Exception:
            return []

    def _test_numeric_id_manipulation(self,
                                      extracted_ids: list[Any]
                                      ) -> dict[str,
                                                Any]:
        """
        Test numeric ID manipulation for IDOR

        Args:
            extracted_ids: List of IDs extracted from responses

        Returns:
            dict[str, Any]: Numeric ID manipulation test results
        """
        numeric_ids = [
            id_val for id_val in extracted_ids
            if isinstance(id_val, int)
        ]

        if not numeric_ids:
            return {
                "vulnerable": False,
                "description": "No numeric IDs to test",
            }

        base_id = numeric_ids[0]

        test_ids = IDORPayloads.NUMERIC_ID_MANIPULATIONS

        accessible_unauthorized = []

        for test_id in test_ids:
            if test_id == base_id:
                continue

            try:
                response = self.make_request("GET", f"/{test_id}")

                if response.status_code == 200:
                    accessible_unauthorized.append(
                        {
                            "id": test_id,
                            "status_code": response.status_code,
                            "response_length": len(response.text),
                        }
                    )

            except Exception:
                continue

        if accessible_unauthorized:
            return {
                "vulnerable": True,
                "vulnerability_type": "Numeric ID Enumeration",
                "base_id": base_id,
                "unauthorized_access": accessible_unauthorized,
                "count": len(accessible_unauthorized),
            }

        return {
            "vulnerable": False,
            "numeric_ids_tested": len(test_ids),
        }

    def _test_string_id_manipulation(self,
                                     extracted_ids: list[Any]
                                     ) -> dict[str,
                                               Any]:
        """
        Test string/UUID ID manipulation for IDOR

        Args:
            extracted_ids: List of IDs extracted from responses

        Returns:
            dict[str, Any]: String ID manipulation test results
        """
        string_ids = [
            id_val for id_val in extracted_ids
            if isinstance(id_val, str)
        ]

        if not string_ids:
            return {
                "vulnerable": False,
                "description": "No string IDs to test",
            }

        test_ids = IDORPayloads.STRING_ID_MANIPULATIONS

        accessible_unauthorized = []

        for test_id in test_ids:
            try:
                response = self.make_request("GET", f"/{test_id}")

                if response.status_code == 200:
                    accessible_unauthorized.append(
                        {
                            "id": test_id,
                            "status_code": response.status_code,
                            "response_length": len(response.text),
                        }
                    )

            except Exception:
                continue

        if accessible_unauthorized:
            return {
                "vulnerable": True,
                "vulnerability_type": "String ID Manipulation",
                "unauthorized_access": accessible_unauthorized,
                "count": len(accessible_unauthorized),
            }

        return {
            "vulnerable": False,
            "string_ids_tested": len(test_ids),
        }

    def _test_predictable_id_patterns(self) -> dict[str, Any]:
        """
        Test if IDs follow predictable patterns

        Predictable IDs (sequential, timestamps) enable enumeration attacks.

        Returns:
            dict[str, Any]: Predictable ID pattern test results
        """
        try:
            ids1 = self._extract_ids_from_response()

            ids2 = self._extract_ids_from_response()

            numeric_ids1 = [id for id in ids1 if isinstance(id, int)]
            numeric_ids2 = [id for id in ids2 if isinstance(id, int)]

            if len(numeric_ids1) >= 2:
                diff1 = abs(numeric_ids1[1] - numeric_ids1[0])

                if len(numeric_ids2) >= 2:
                    diff2 = abs(numeric_ids2[1] - numeric_ids2[0])

                    if diff1 == diff2 and diff1 == 1:
                        return {
                            "vulnerable": True,
                            "pattern_type": "Sequential IDs",
                            "id_difference": diff1,
                            "example_ids": numeric_ids1[: 3],
                        }

            return {
                "vulnerable": False,
                "description": "No predictable ID patterns detected",
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description": "Error testing ID patterns",
            }

    def _create_vulnerable_result(
        self,
        details: str,
        evidence: dict[str,
                       Any],
        severity: Severity = Severity.HIGH,
        recommendations: list[str] | None = None,
    ) -> TestResultCreate:
        """
        Create a vulnerable scan result

        Args:
            details: Vulnerability description
            evidence: Evidence dictionary
            severity: Vulnerability severity
            recommendations: List of remediation recommendations

        Returns:
            TestResultCreate: Vulnerable result
        """
        return TestResultCreate(
            test_name = TestType.IDOR,
            status = ScanStatus.VULNERABLE,
            severity = severity,
            details = details,
            evidence_json = evidence,
            recommendations_json = recommendations or [],
        )
