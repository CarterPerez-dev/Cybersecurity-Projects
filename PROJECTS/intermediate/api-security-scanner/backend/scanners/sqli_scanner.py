"""
©AngelaMos | 2025
SQL injection vulnerability scanner

Tests error based, boolean based, and time based blind SQLi
"""

import time
import statistics
from typing import Any

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .payloads import SQLiPayloads
from .base_scanner import BaseScanner


class SQLiScanner(BaseScanner):
    """
    Tests for SQL injection vulnerabilities

    Detects:
    - Error-based SQLi (database error messages)
    - Boolean-based blind SQLi (response differences)
    - Time-based blind SQLi (response timing analysis)

    Uses payloads covering MySQL, PostgreSQL, MSSQL, Oracle
    """
    def scan(self) -> TestResultCreate:
        """
        Execute SQL injection tests

        Returns:
            TestResultCreate: Scan result with findings
        """
        error_based_test = self._test_error_based_sqli()
        if error_based_test["vulnerable"]:
            return self._create_vulnerable_result(
                details =
                f"Error-based SQL injection detected: {error_based_test['database_type']}",
                evidence = error_based_test,
                severity = Severity.CRITICAL,
                recommendations = [
                    "Use parameterized queries (prepared statements)",
                    "Never concatenate user input into SQL queries",
                    "Implement input validation and sanitization",
                    "Disable detailed error messages in production",
                    "Use ORM frameworks with proper escaping",
                ],
            )

        boolean_based_test = self._test_boolean_based_sqli()
        if boolean_based_test["vulnerable"]:
            return self._create_vulnerable_result(
                details = "Boolean-based blind SQL injection detected",
                evidence = boolean_based_test,
                severity = Severity.CRITICAL,
                recommendations = [
                    "Use parameterized queries for all database operations",
                    "Implement proper input validation",
                    "Avoid exposing different responses for true/false conditions",
                ],
            )

        time_based_test = self._test_time_based_sqli()
        if time_based_test["vulnerable"]:
            return self._create_vulnerable_result(
                details =
                f"Time-based blind SQL injection detected: {time_based_test['database_type']}",
                evidence = time_based_test,
                severity = Severity.CRITICAL,
                recommendations = [
                    "Use parameterized queries exclusively",
                    "Implement strict input validation",
                    "Monitor for unusual response time patterns",
                ],
            )

        return TestResultCreate(
            test_name = TestType.SQLI,
            status = ScanStatus.SAFE,
            severity = Severity.INFO,
            details = "No SQL injection vulnerabilities detected",
            evidence_json = {
                "error_based_test": error_based_test,
                "boolean_based_test": boolean_based_test,
                "time_based_test": time_based_test,
            },
            recommendations_json = [
                "Continue using parameterized queries",
                "Regularly update security testing",
            ],
        )

    def _test_error_based_sqli(self) -> dict[str, Any]:
        """
        Test for error based SQL injection

        Detects database errors in responses indicating SQLi vulnerability

        Returns:
            dict[str, Any]: Error-based SQLi test results
        """
        error_signatures = SQLiPayloads.get_error_signatures()

        basic_payloads = SQLiPayloads.BASIC_AUTHENTICATION_BYPASS

        for payload in basic_payloads:
            try:
                response = self.make_request("GET", f"/?id={payload}")

                response_text_lower = response.text.lower()

                for db_type, signatures in error_signatures.items():
                    for signature in signatures:
                        if signature in response_text_lower:
                            return {
                                "vulnerable": True,
                                "database_type": db_type,
                                "payload": payload,
                                "status_code": response.status_code,
                                "error_signature": signature,
                                "response_excerpt":
                                response.text[: 500],
                            }

            except Exception:
                continue

        return {
            "vulnerable": False,
            "payloads_tested": len(basic_payloads),
            "description": "No database errors detected",
        }

    def _test_boolean_based_sqli(self) -> dict[str, Any]:
        """
        Test for boolean based blind SQL injection

        Compares responses from true vs false conditions to detect SQLi

        Returns:
            dict[str, Any]: Boolean based SQLi test results
        """
        try:
            baseline_response = self.make_request("GET", "/?id=1")
            baseline_length = len(baseline_response.text)
            baseline_status = baseline_response.status_code

            if baseline_status != 200:
                return {
                    "vulnerable": False,
                    "description": "Baseline request failed",
                    "baseline_status": baseline_status,
                }

            boolean_payloads = SQLiPayloads.BOOLEAN_BASED_BLIND
            true_payloads = [
                p for p in boolean_payloads
                if "AND '1'='1" in p or "AND 1=1" in p
            ]
            false_payloads = [
                p for p in boolean_payloads if "AND '1'='2" in p
                or "AND 1=2" in p or "AND 1=0" in p
            ]

            true_lengths = []
            for payload in true_payloads:
                response = self.make_request("GET", f"/?id={payload}")
                true_lengths.append(len(response.text))

            false_lengths = []
            for payload in false_payloads:
                response = self.make_request("GET", f"/?id={payload}")
                false_lengths.append(len(response.text))

            avg_true = statistics.mean(true_lengths)
            avg_false = statistics.mean(false_lengths)

            length_diff = abs(avg_true - avg_false)

            if length_diff > 100 and avg_true != avg_false:
                return {
                    "vulnerable":
                    True,
                    "baseline_length":
                    baseline_length,
                    "true_condition_avg_length":
                    avg_true,
                    "false_condition_avg_length":
                    avg_false,
                    "length_difference":
                    length_diff,
                    "confidence":
                    "HIGH" if length_diff > 500 else "MEDIUM",
                }

            return {
                "vulnerable": False,
                "description": "No boolean-based SQLi detected",
                "length_difference": length_diff,
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description": "Error testing boolean-based SQLi",
            }

    def _test_time_based_sqli(self,
                              delay_seconds: int = 5) -> dict[str,
                                                              Any]:
        """
        Test for time based blind SQL injection

        Uses baseline timing comparison with statistical analysis
        for false positive reduction

        Args:
            delay_seconds: Delay to inject (from settings)

        Returns:
            dict[str, Any]: Time-based SQLi test results
        """
        try:
            baseline_mean, baseline_stdev = self.get_baseline_timing("/")

            threshold = baseline_mean + (3 * baseline_stdev)
            expected_delay_time = baseline_mean + delay_seconds

            all_time_payloads = SQLiPayloads.TIME_BASED_BLIND

            delay_payloads = {
                "mysql":
                [p for p in all_time_payloads if "SLEEP" in p],
                "postgres": [
                    p for p in all_time_payloads if "pg_sleep" in p
                ],
                "mssql": [
                    p for p in all_time_payloads if "WAITFOR" in p
                ],
            }

            for db_type, payloads in delay_payloads.items():
                for payload in payloads:
                    delay_times = []

                    for _ in range(3):
                        try:
                            response = self.make_request(
                                "GET",
                                f"/?id={payload}",
                                timeout = delay_seconds + 10,
                            )
                            elapsed = getattr(
                                response,
                                "request_time",
                                0.0
                            )
                            delay_times.append(elapsed)

                        except Exception:
                            delay_times.append(delay_seconds + 10)

                        time.sleep(1)

                    avg_delay = statistics.mean(delay_times)

                    if avg_delay >= expected_delay_time - 1:
                        confidence = "HIGH" if avg_delay >= expected_delay_time else "MEDIUM"

                        return {
                            "vulnerable":
                            True,
                            "database_type":
                            db_type,
                            "payload":
                            payload,
                            "baseline_time":
                            f"{baseline_mean:.3f}s",
                            "response_time":
                            f"{avg_delay:.3f}s",
                            "expected_delay":
                            f"{expected_delay_time:.3f}s",
                            "confidence":
                            confidence,
                            "individual_times":
                            [f"{t:.3f}s" for t in delay_times],
                        }

            return {
                "vulnerable": False,
                "baseline_time": f"{baseline_mean:.3f}s",
                "threshold": f"{threshold:.3f}s",
                "description": "No time-based SQLi detected",
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description": "Error testing time-based SQLi",
            }

    def _create_vulnerable_result(
        self,
        details: str,
        evidence: dict[str,
                       Any],
        severity: Severity = Severity.CRITICAL,
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
            test_name = TestType.SQLI,
            status = ScanStatus.VULNERABLE,
            severity = severity,
            details = details,
            evidence_json = evidence,
            recommendations_json = recommendations or [],
        )
