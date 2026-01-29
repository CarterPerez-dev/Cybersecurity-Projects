"""
ⒸAngelaMos | 2025
Scan model API validation and serialization
"""

from __future__ import annotations

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
)
from datetime import datetime

from config import settings
from core.enums import TestType
from .test_result_schemas import TestResultResponse


class ScanRequest(BaseModel):
    """
    Schema for creating a new security scan
    """

    target_url: HttpUrl = Field(max_length = settings.URL_MAX_LENGTH)
    auth_token: str | None = None
    tests_to_run: list[TestType] = Field(min_length = 1)
    max_requests: int = Field(
        default = settings.DEFAULT_MAX_REQUESTS,
        ge = 1,
        le = settings.SCANNER_MAX_CONCURRENT_REQUESTS,
    )


class ScanResponse(BaseModel):
    """
    Schema for scan data in API responses
    """

    model_config = ConfigDict(from_attributes = True)

    id: int
    user_id: int
    target_url: str
    scan_date: datetime
    created_at: datetime
    test_results: list[TestResultResponse] = []

    @property
    def total_tests(self) -> int:
        """
        Total number of tests run
        """
        return len(self.test_results)

    @property
    def vulnerabilities_found(self) -> int:
        """
        Number of vulnerabilities found
        """
        return sum(
            1 for r in self.test_results if r.status == "vulnerable"
        )
