"""
©AngelaMos | 2025
Rate limiting detection and bypass testing scanner

OWASP API4:2023
"""

from __future__ import annotations

import re
import time
from typing import Any

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .base_scanner import BaseScanner
from .payloads import RateLimitBypassPayloads


class RateLimitScanner(BaseScanner):
    """
    Rate limiting and bypass vulnerabilities tests
    """
    def scan(self) -> TestResultCreate:
        """
        Execute rate limiting tests

        Returns:
            TestResultCreate: Scan result with findings
        """
        rate_limit_info = self._detect_rate_limiting()

        if not rate_limit_info["rate_limit_detected"]:
            return self._create_vulnerable_result(
                details =
                "No rate limiting detected on target endpoint",
                evidence = rate_limit_info,
                recommendations = [
                    "Implement rate limiting to prevent abuse and DoS attacks",
                    "Use standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining)",
                    "Return 429 Too Many Requests when limits are exceeded",
                    "Include Retry-After header with 429 responses",
                ],
            )

        if rate_limit_info["enforcement_status"] == "HEADERS_ONLY":
            return self._create_vulnerable_result(
                details =
                "Rate limit headers present but not enforced",
                evidence = rate_limit_info,
                severity = Severity.MEDIUM,
                recommendations = [
                    "Enforce rate limits with 429 responses when thresholds are exceeded",
                    "Rate limit headers without enforcement provide false security",
                ],
            )

        bypass_results = self._test_bypass_techniques()

        if bypass_results["bypass_successful"]:
            return self._create_vulnerable_result(
                details =
                f"Rate limiting bypassed using: {bypass_results['bypass_method']}",
                evidence = {
                    "rate_limit_info": rate_limit_info,
                    "bypass_details": bypass_results,
                },
                severity = Severity.HIGH,
                recommendations = [
                    f"Fix bypass vulnerability: {bypass_results['bypass_method']}",
                    "Do not trust client-provided IP headers (X-Forwarded-For, X-Real-IP)",
                    "Implement rate limiting at multiple layers (IP, user, API key)",
                    "Validate and sanitize all client-provided headers",
                ],
            )

        return TestResultCreate(
            test_name = TestType.RATE_LIMIT,
            status = ScanStatus.SAFE,
            severity = Severity.INFO,
            details =
            "Rate limiting properly implemented and enforced",
            evidence_json = {
                "rate_limit_info": rate_limit_info,
                "bypass_attempts": bypass_results,
            },
            recommendations_json = [
                "Rate limiting is properly configured",
                "Continue monitoring for new bypass techniques",
            ],
        )

    def _detect_rate_limiting(self,
                              test_request_count: int = 20
                              ) -> dict[str,
                                        Any]:
        """
        Detect rate limiting by analyzing headers and response patterns

        Based on industry research: checks for standard headers and 429 responses

        Args:
            test_request_count: Number of requests to send

        Returns:
            dict[str, Any]: Rate limiting detection results
        """
        rate_limit_patterns = RateLimitBypassPayloads.get_header_patterns(
        )

        results = {
            "rate_limit_detected": False,
            "rate_limit_headers": {},
            "limit_threshold": None,
            "reset_window": None,
            "enforcement_status": None,
            "attempts_until_limit": None,
            "request_results": [],
        }

        for attempt in range(1, test_request_count + 1):
            try:
                response = self.make_request("GET", "/")

                headers_lower = {
                    k.lower(): v
                    for k, v in response.headers.items()
                }

                for header_type, pattern in rate_limit_patterns.items():
                    for header_name, header_value in headers_lower.items():
                        if re.search(pattern,
                                     header_name,
                                     re.IGNORECASE):
                            results["rate_limit_headers"][
                                header_type] = {
                                    "header_name": header_name,
                                    "value": header_value,
                                }
                            results["rate_limit_detected"] = True

                results["request_results"].append(
                    {
                        "attempt":
                        attempt,
                        "status_code":
                        response.status_code,
                        "response_time_ms":
                        round(
                            getattr(response,
                                    "request_time",
                                    0.0) * 1000,
                            2
                        ),
                    }
                )

                if response.status_code == 429:
                    results["enforcement_status"] = "ACTIVE"
                    results["attempts_until_limit"] = attempt

                    retry_after = response.headers.get("Retry-After")
                    if retry_after:
                        results["retry_after_seconds"] = retry_after

                    break

                time.sleep(0.1)

            except Exception as e:
                results["request_results"].append(
                    {
                        "attempt": attempt,
                        "error": str(e)
                    }
                )
                break

        if results["rate_limit_detected"]:
            if "limit" in results["rate_limit_headers"]:
                results["limit_threshold"] = results[
                    "rate_limit_headers"]["limit"]["value"]

            if "reset" in results["rate_limit_headers"]:
                results["reset_window"] = results["rate_limit_headers"
                                                  ]["reset"]["value"]

            if not results["enforcement_status"]:
                results["enforcement_status"] = "HEADERS_ONLY"
        else:
            results["enforcement_status"] = "NONE"

        return results

    def _test_bypass_techniques(self) -> dict[str, Any]:
        """
        Test common rate limit bypass techniques

        Based on HackTricks and OWASP:
        - IP header spoofing (X-Forwarded-For, X-Real-IP, etc.)
        - Endpoint case variations

        Returns:
            dict[str, Any]: Bypass test results
        """
        results = {
            "bypass_successful": False,
            "bypass_method": None,
            "bypass_details": {},
        }

        ip_bypass = self._test_ip_header_bypass()
        if ip_bypass["bypass_successful"]:
            results["bypass_successful"] = True
            results["bypass_method"] = "IP Header Spoofing"
            results["bypass_details"] = ip_bypass
            return results

        endpoint_bypass = self._test_endpoint_variation_bypass()
        if endpoint_bypass["bypass_successful"]:
            results["bypass_successful"] = True
            results["bypass_method"] = "Endpoint Case Variation"
            results["bypass_details"] = endpoint_bypass
            return results

        results["bypass_details"] = {
            "ip_header_test": ip_bypass,
            "endpoint_variation_test": endpoint_bypass,
        }

        return results

    def _test_ip_header_bypass(self,
                               test_count: int = 15) -> dict[str,
                                                             Any]:
        """
        Test if rate limiting can be bypassed with IP spoofing headers

        Many rate limiters trust X-Forwarded-For and similar headers,
        allowing attackers to bypass limits by rotating fake IPs

        Args:
            test_count: Number of requests to test

        Returns:
            dict[str, Any]: IP bypass test results
        """
        bypass_headers = RateLimitBypassPayloads.HEADER_SPOOFING

        for header_dict in bypass_headers:
            header_name = list(header_dict.keys())[0]
            success_count = 0

            for i in range(test_count):
                fake_ip = f"10.{i % 255}.{(i // 255) % 255}.1"
                test_headers = {header_name: fake_ip}

                try:
                    response = self.make_request(
                        "GET",
                        "/",
                        headers = test_headers
                    )

                    if response.status_code != 429:
                        success_count += 1
                    else:
                        break

                except Exception:
                    break

            if success_count == test_count:
                return {
                    "bypass_successful": True,
                    "header_used": header_name,
                    "requests_completed": success_count,
                    "fake_ip_example": "10.0.0.1",
                }

        return {
            "bypass_successful": False,
            "headers_tested":
            [list(h.keys())[0] for h in bypass_headers],
        }

    def _test_endpoint_variation_bypass(self) -> dict[str, Any]:
        """
        Test if endpoint case variations bypass rate limiting

        Some rate limiters are case-sensitive or miss URL variations

        Returns:
            dict[str, Any]: Endpoint variation test results
        """
        variations = RateLimitBypassPayloads.get_endpoint_variations()

        for variant in variations:
            success_count = 0

            for _ in range(10):
                try:
                    response = self.make_request("GET", variant)
                    if response.status_code != 429:
                        success_count += 1
                    else:
                        break
                except Exception:
                    break

            if success_count == 10 and variant != "/":
                return {
                    "bypass_successful": True,
                    "bypass_variant": variant,
                    "requests_completed": success_count,
                }

        return {
            "bypass_successful": False,
            "variations_tested": variations,
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
            test_name = TestType.RATE_LIMIT,
            status = ScanStatus.VULNERABLE,
            severity = severity,
            details = details,
            evidence_json = evidence,
            recommendations_json = recommendations or [],
        )
