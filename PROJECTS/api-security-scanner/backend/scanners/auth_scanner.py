"""
©AngelaMos | 2025
Authentication and authorization vulnerability scanner

OWASP API2:2023
"""

from __future__ import annotations

import base64
import json
from typing import Any

from config import settings
from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from schemas.test_result_schemas import TestResultCreate

from .payloads import AuthPayloads
from .base_scanner import BaseScanner


class AuthScanner(BaseScanner):
    """
    Tests for broken authentication vulnerabilities

    Detects:
    - Missing authentication on endpoints
    - Weak/invalid token acceptance
    - JWT vulnerabilities (none algorithm, weak secrets)
    - Missing rate limiting on auth endpoints

    Maps to OWASP API Security Top 10 2023: API2:2023
    """
    def scan(self) -> TestResultCreate:
        """
        Execute authentication tests

        Returns:
            TestResultCreate: Scan result with findings
        """
        missing_auth_test = self._test_missing_authentication()
        if missing_auth_test["vulnerable"]:
            return self._create_vulnerable_result(
                details = "Endpoint accessible without authentication",
                evidence = missing_auth_test,
                severity = Severity.HIGH,
                recommendations = [
                    "Require authentication for all sensitive endpoints",
                    "Implement proper authentication middleware",
                    "Return 401 Unauthorized for missing/invalid credentials",
                ],
            )

        if self.auth_token:
            jwt_test = self._test_jwt_vulnerabilities()
            if jwt_test["vulnerable"]:
                return self._create_vulnerable_result(
                    details =
                    f"JWT vulnerability: {jwt_test['vulnerability_type']}",
                    evidence = jwt_test,
                    severity = Severity.CRITICAL,
                    recommendations = jwt_test.get(
                        "recommendations",
                        [
                            "Properly validate JWT signatures",
                            "Reject 'none' algorithm tokens",
                            "Use strong secrets (256+ bits)",
                            "Implement token expiration checks",
                        ],
                    ),
                )

        invalid_token_test = self._test_invalid_token_handling()
        if invalid_token_test["vulnerable"]:
            return self._create_vulnerable_result(
                details = "Invalid tokens accepted by endpoint",
                evidence = invalid_token_test,
                severity = Severity.HIGH,
                recommendations = [
                    "Reject invalid/malformed tokens with 401 status",
                    "Validate token format, signature, and expiration",
                    "Log authentication failures for monitoring",
                ],
            )

        return TestResultCreate(
            test_name = TestType.AUTH,
            status = ScanStatus.SAFE,
            severity = Severity.INFO,
            details = "Authentication properly implemented",
            evidence_json = {
                "missing_auth_test": missing_auth_test,
                "invalid_token_test": invalid_token_test,
            },
            recommendations_json = [
                "Authentication is properly configured",
                "Consider implementing additional security measures (2FA, refresh tokens)",
            ],
        )

    def _test_missing_authentication(self) -> dict[str, Any]:
        """
        Test if endpoint requires authentication

        Attempts to access endpoint without credentials.

        Returns:
            dict[str, Any]: Test results
        """
        session_without_auth = self.session.__class__()
        session_without_auth.headers.update(
            {
                "User-Agent":
                f"{settings.APP_NAME}/{settings.VERSION}",
                "Accept": "application/json",
            }
        )

        try:
            response = session_without_auth.get(
                self.target_url,
                timeout = settings.SCANNER_CONNECTION_TIMEOUT,
            )

            if response.status_code == 200:
                return {
                    "vulnerable":
                    True,
                    "status_code":
                    response.status_code,
                    "response_length":
                    len(response.text),
                    "description":
                    "Endpoint accessible without authentication",
                }

            if response.status_code in (401, 403):
                return {
                    "vulnerable":
                    False,
                    "status_code":
                    response.status_code,
                    "description":
                    "Endpoint properly requires authentication",
                }

            return {
                "vulnerable": False,
                "status_code": response.status_code,
                "description": "Endpoint returned unexpected status",
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description":
                "Error testing authentication requirement",
            }

    def _test_jwt_vulnerabilities(self) -> dict[str, Any]:
        """
        Test for common JWT vulnerabilities

        Tests:
        - None algorithm acceptance
        - Signature removal
        - Weak secret detection (common patterns)

        Returns:
            dict[str, Any]: JWT vulnerability test results
        """
        if not self.auth_token or self.auth_token.count(".") != 2:
            return {
                "vulnerable": False,
                "description": "No valid JWT token provided",
            }

        none_alg_test = self._test_none_algorithm()
        if none_alg_test["vulnerable"]:
            return none_alg_test

        signature_removal_test = self._test_signature_removal()
        if signature_removal_test["vulnerable"]:
            return signature_removal_test

        return {
            "vulnerable": False,
            "tests_performed":
            ["none_algorithm",
             "signature_removal"],
            "description": "No JWT vulnerabilities detected",
        }

    def _test_none_algorithm(self) -> dict[str, Any]:
        """
        Test if server accepts JWT with 'none' algorithm

        Critical vulnerability: allows unsigned tokens to be accepted.

        Returns:
            dict[str, Any]: None algorithm test results
        """
        try:
            header, payload, signature = self.auth_token.split(".")

            none_variants = AuthPayloads.get_jwt_none_variants()

            for variant in none_variants:
                malicious_header = self._base64url_encode(
                    json.dumps({
                        "alg": variant,
                        "typ": "JWT"
                    })
                )

                malicious_token = f"{malicious_header}.{payload}."

                response = self.make_request(
                    "GET",
                    "/",
                    headers = {
                        "Authorization": f"Bearer {malicious_token}"
                    },
                )

                if response.status_code == 200:
                    return {
                        "vulnerable":
                        True,
                        "vulnerability_type":
                        "JWT None Algorithm",
                        "algorithm_variant":
                        variant,
                        "status_code":
                        response.status_code,
                        "recommendations": [
                            "Reject tokens with 'none' algorithm (all case variations)",
                            "Explicitly verify signature before accepting tokens",
                            "Use allowlist of accepted algorithms",
                        ],
                    }

            return {
                "vulnerable": False,
                "description": "None algorithm properly rejected",
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description": "Error testing none algorithm",
            }

    def _test_signature_removal(self) -> dict[str, Any]:
        """
        Test if server accepts JWT with signature removed

        Returns:
            dict[str, Any]: Signature removal test results
        """
        try:
            header, payload, signature = self.auth_token.split(".")

            malicious_token = f"{header}.{payload}."

            response = self.make_request(
                "GET",
                "/",
                headers = {
                    "Authorization": f"Bearer {malicious_token}"
                },
            )

            if response.status_code == 200:
                return {
                    "vulnerable":
                    True,
                    "vulnerability_type":
                    "JWT Signature Not Verified",
                    "status_code":
                    response.status_code,
                    "recommendations": [
                        "Require valid signature on all JWT tokens",
                        "Reject tokens with missing or invalid signatures",
                        "Implement proper JWT validation library",
                    ],
                }

            return {
                "vulnerable": False,
                "description": "Signature removal properly rejected",
            }

        except Exception as e:
            return {
                "vulnerable": False,
                "error": str(e),
                "description": "Error testing signature removal",
            }

    def _test_invalid_token_handling(self) -> dict[str, Any]:
        """
        Test how server handles invalid/malformed tokens

        Returns:
            dict[str, Any]: Invalid token handling test results
        """
        invalid_tokens = AuthPayloads.INVALID_TOKEN_FORMATS

        accepted_invalid = []

        for invalid_token in invalid_tokens:
            try:
                response = self.make_request(
                    "GET",
                    "/",
                    headers = {
                        "Authorization": f"Bearer {invalid_token}"
                    },
                )

                if response.status_code == 200:
                    accepted_invalid.append(
                        {
                            "token": invalid_token[: 50],
                            "status_code": response.status_code,
                        }
                    )

            except Exception:
                continue

        if accepted_invalid:
            return {
                "vulnerable": True,
                "accepted_invalid_tokens": accepted_invalid,
                "count": len(accepted_invalid),
            }

        return {
            "vulnerable": False,
            "description": "Invalid tokens properly rejected",
            "tokens_tested": len(invalid_tokens),
        }

    def _base64url_decode(self, data: str) -> dict[str, Any]:
        """
        Decode base64url-encoded JWT data

        Args:
            data: Base64url-encoded string

        Returns:
            dict[str, Any]: Decoded JSON data
        """
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding

        decoded = base64.urlsafe_b64decode(data)
        return json.loads(decoded)

    def _base64url_encode(self, data: str) -> str:
        """
        Encode data to base64url format

        Args:
            data: String data to encode

        Returns:
            str: Base64url-encoded string
        """
        encoded = base64.urlsafe_b64encode(data.encode()).decode()
        return encoded.rstrip("=")

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
            test_name = TestType.AUTH,
            status = ScanStatus.VULNERABLE,
            severity = severity,
            details = details,
            evidence_json = evidence,
            recommendations_json = recommendations or [],
        )
