"""
©AngelaMos | 2025
Base scanner class with common HTTP logic and evidence collection
"""

from __future__ import annotations

import time
import random
import statistics
from typing import Any
from urllib.parse import urljoin
from abc import ABC, abstractmethod

import requests

from config import settings
from schemas.test_result_schemas import TestResultCreate


class BaseScanner(ABC):
    """
    Abstract base class for all security scanners

    Provides common HTTP functionality, request spacing, retry logic,
    and evidence collection. Specific scanners inherit and implement scan().
    """
    def __init__(
        self,
        target_url: str,
        auth_token: str | None = None,
        max_requests: int | None = None,
    ):
        """
        Initialize scanner with target and configuration

        Args:
            target_url: Base URL of API to scan
            auth_token: Optional authentication token
            max_requests: Optional limit on requests (from settings if None)
        """
        self.target_url = target_url.rstrip("/")
        self.auth_token = auth_token
        self.max_requests = max_requests or settings.DEFAULT_MAX_REQUESTS
        self.session = self._create_session()
        self.last_request_time = 0.0
        self.request_count = 0

    def _create_session(self) -> requests.Session:
        """
        Create persistent HTTP session with proper headers

        Returns:
            requests.Session: Configured session object
        """
        session = requests.Session()

        session.headers.update(
            {
                "User-Agent":
                f"{settings.APP_NAME}/{settings.VERSION}",
                "Accept": "application/json",
            }
        )

        if self.auth_token:
            session.headers.update(
                {"Authorization": f"Bearer {self.auth_token}"}
            )

        return session

    def _wait_before_request(
        self,
        jitter_ms: int | None = None
    ) -> None:
        """
        Implement request spacing to avoid overwhelming target

        Based on research: production-safe scanning requires spacing
        requests to avoid triggering rate limits or affecting service.

        Args:
            jitter_ms: Random jitter in milliseconds to add (DEFAULT_JITTER_MS)
        """
        if jitter_ms is None:
            jitter_ms = settings.DEFAULT_JITTER_MS

        required_delay = 1.0 / (
            self.max_requests /
            settings.SCANNER_RATE_LIMIT_WINDOW_SECONDS
        )
        jitter = random.uniform(0, jitter_ms / 1000.0)

        elapsed = time.time() - self.last_request_time

        if elapsed < required_delay:
            time.sleep(required_delay - elapsed + jitter)
        else:
            time.sleep(jitter)

        self.last_request_time = time.time()

    def make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any,
    ) -> requests.Response:
        """
        Make HTTP request with retry logic and rate limit handling

        Implements exponential backoff for server errors and respects
        Retry-After headers for 429 responses.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: Endpoint path (will be joined with target_url)
            **kwargs: Additional arguments passed to requests

        Returns:
            requests.Response: Response object

        Raises:
            requests.RequestException: If request fails after retries
        """
        self._wait_before_request()

        url = urljoin(self.target_url, endpoint)
        retry_count = 0
        backoff_factor = 2.0

        kwargs.setdefault(
            "timeout",
            settings.SCANNER_CONNECTION_TIMEOUT
        )

        while retry_count <= settings.DEFAULT_RETRY_COUNT:
            try:
                start_time = time.time()
                response = self.session.request(method, url, **kwargs)
                setattr(
                    response,
                    "request_time",
                    time.time() - start_time
                )

                self.request_count += 1

                if response.status_code == 429:
                    retry_after = response.headers.get(
                        "Retry-After",
                        str(settings.DEFAULT_RETRY_WAIT_SECONDS)
                    )
                    wait_time = (
                        int(retry_after) if retry_after.isdigit() else
                        settings.DEFAULT_RETRY_WAIT_SECONDS
                    )
                    time.sleep(wait_time)
                    retry_count += 1
                    continue

                if response.status_code >= 500 and retry_count < settings.DEFAULT_RETRY_COUNT:
                    wait_time = backoff_factor**retry_count
                    time.sleep(wait_time)
                    retry_count += 1
                    continue

                return response

            except (requests.Timeout, requests.ConnectionError):
                if retry_count < settings.DEFAULT_RETRY_COUNT:
                    wait_time = backoff_factor**retry_count
                    time.sleep(wait_time)
                    retry_count += 1
                else:
                    raise

        return response

    def get_baseline_timing(
        self,
        endpoint: str,
        samples: int | None = None
    ) -> tuple[float,
               float]:
        """
        Establish baseline response time for an endpoint

        Critical for time-based detection (e.g., blind SQLi). Takes multiple
        samples and calculates mean and standard deviation.

        Args:
            endpoint: Endpoint to test
            samples: Number of samples to take (DEFAULT_BASELINE_SAMPLES)

        Returns:
            tuple[float, float]: (mean_time, stdev_time) in seconds
        """
        if samples is None:
            samples = settings.DEFAULT_BASELINE_SAMPLES

        times = []

        for _ in range(samples):
            response = self.make_request("GET", endpoint)
            times.append(getattr(response, "request_time", 0.0))
            time.sleep(0.5)

        return statistics.mean(times), statistics.stdev(times)

    def collect_evidence(
        self,
        response: requests.Response,
        payload: Any | None = None,
        **additional_data: Any,
    ) -> dict[str,
              Any]:
        """
        Collect evidence from test execution with sensitive data redaction

        Args:
            response: HTTP response object
            payload: Payload used in test
            **additional_data: Additional evidence data

        Returns:
            dict[str, Any]: Evidence dictionary
        """
        evidence = {
            "status_code":
            response.status_code,
            "response_time_ms":
            round(getattr(response,
                          "request_time",
                          0.0) * 1000,
                  2),
            "response_length":
            len(response.text),
            "headers":
            self._redact_sensitive_headers(dict(response.headers)),
        }

        if payload is not None:
            evidence["payload"] = str(payload)

        evidence.update(additional_data)

        return evidence

    def _redact_sensitive_headers(self,
                                  headers: dict[str,
                                                str]) -> dict[str,
                                                              str]:
        """
        Redact sensitive header values for evidence collection

        Args:
            headers: Original headers dictionary

        Returns:
            dict[str, str]: Headers with sensitive values redacted
        """
        sensitive_headers = [
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
        ]

        redacted = {}
        for key, value in headers.items():
            if key.lower() in sensitive_headers:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value

        return redacted

    @abstractmethod
    def scan(self) -> TestResultCreate:
        """
        Execute the security scan

        Must be implemented by specific scanner classes.

        Returns:
            TestResultCreate: Result of the scan
        """
