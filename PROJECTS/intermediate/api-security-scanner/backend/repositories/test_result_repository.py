"""
ⒸAngelaMos | 2025
TestResult repository for database operations
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from models.TestResult import TestResult


class TestResultRepository:
    """
    Repository for TestResult database operations
    """
    @staticmethod
    def create_test_result(
        db: Session,
        scan_id: int,
        *,
        test_name: TestType,
        status: ScanStatus,
        severity: Severity,
        details: str,
        evidence_json: dict[str,
                            Any],
        recommendations_json: list[str],
        commit: bool = True,
    ) -> TestResult:
        """
        Create a new test result.

        Args:
            db: Database session
            scan_id: Scan ID this result belongs to
            test_name: Type of security test
            status: Test status (vulnerable, safe, error)
            severity: Vulnerability severity
            details: Detailed description
            evidence_json: Evidence data as JSON
            recommendations_json: List of recommendations
            commit: Whether to commit the transaction

        Returns:
            TestResult: Created test result instance
        """
        test_result = TestResult(
            scan_id = scan_id,
            test_name = test_name,
            status = status,
            severity = severity,
            details = details,
            evidence_json = evidence_json,
            recommendations_json = recommendations_json,
        )
        db.add(test_result)
        if commit:
            db.commit()
            db.refresh(test_result)
        return test_result

    @staticmethod
    def bulk_create(
        db: Session,
        test_results: list[TestResult],
        commit: bool = True
    ) -> list[TestResult]:
        """
        Create multiple test results in bulk

        Args:
            db: Database session
            test_results: List of TestResult instances to create
            commit: Whether to commit the transaction

        Returns:
            list[TestResult]: Created test result instances
        """
        db.add_all(test_results)
        if commit:
            db.commit()
            for result in test_results:
                db.refresh(result)
        return test_results

    @staticmethod
    def get_by_scan(db: Session, scan_id: int) -> list[TestResult]:
        """
        Get all test results for a specific scan

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            list[TestResult]: List of test results for the scan
        """
        return (
            db.query(TestResult).filter(
                TestResult.scan_id == scan_id
            ).order_by(TestResult.created_at.asc()).all()
        )

    @staticmethod
    def get_by_status(db: Session,
                      scan_id: int,
                      status: ScanStatus) -> list[TestResult]:
        """
        Get test results by status for a scan

        Args:
            db: Database session
            scan_id: Scan ID
            status: Status to filter by

        Returns:
            list[TestResult]: Filtered test results
        """
        return (
            db.query(TestResult).filter(
                TestResult.scan_id == scan_id,
                TestResult.status == status
            ).all()
        )

    @staticmethod
    def get_vulnerabilities(db: Session,
                            scan_id: int) -> list[TestResult]:
        """
        Get only vulnerable test results for a scan

        Args:
            db: Database session
            scan_id: Scan ID

        Returns:
            list[TestResult]: Vulnerable test results only
        """
        return TestResultRepository.get_by_status(
            db,
            scan_id,
            ScanStatus.VULNERABLE
        )

    @staticmethod
    def delete_by_scan(
        db: Session,
        scan_id: int,
        commit: bool = True
    ) -> int:
        """
        Delete all test results for a scan

        Args:
            db: Database session
            scan_id: Scan ID
            commit: Whether to commit the transaction

        Returns:
            int: Number of test results deleted
        """
        count = db.query(TestResult).filter(
            TestResult.scan_id == scan_id
        ).delete()
        if commit:
            db.commit()
        return count
