"""
©AngelaMos | 2025
Coordinates scanners and saves results
"""

from __future__ import annotations

from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from core.enums import TestType
from repositories.scan_repository import ScanRepository
from repositories.test_result_repository import TestResultRepository

from scanners.base_scanner import BaseScanner
from scanners.auth_scanner import AuthScanner
from scanners.idor_scanner import IDORScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.rate_limit_scanner import RateLimitScanner
from schemas.test_result_schemas import TestResultCreate
from schemas.scan_schemas import ScanRequest, ScanResponse


class ScanService:
    """
    Orchestrates security scanning workflow
    """

    @staticmethod
    def run_scan(db: Session, user_id: int, scan_request: ScanRequest) -> ScanResponse:
        """
        Execute security scan with selected tests

        Args:
            db: Database session
            user_id: User ID initiating the scan
            scan_request: Scan configuration and tests to run

        Returns:
            ScanResponse: Scan results with all test outcomes
        """
        scan = ScanRepository.create_scan(
            db=db,
            user_id=user_id,
            target_url=str(scan_request.target_url),
        )

        scanner_mapping: dict[TestType, type[BaseScanner]] = {
            TestType.RATE_LIMIT: RateLimitScanner,
            TestType.AUTH: AuthScanner,
            TestType.SQLI: SQLiScanner,
            TestType.IDOR: IDORScanner,
        }

        results: list[TestResultCreate] = []

        for test_type in scan_request.tests_to_run:
            scanner_class: type[BaseScanner] | None = scanner_mapping.get(test_type)

            if not scanner_class:
                continue

            try:
                scanner = scanner_class(
                    target_url=str(scan_request.target_url),
                    auth_token=scan_request.auth_token,
                    max_requests=scan_request.max_requests,
                )

                result = scanner.scan()
                results.append(result)

            except Exception as e:
                results.append(
                    TestResultCreate(
                        test_name=test_type,
                        status="error",
                        severity="info",
                        details=f"Scanner error: {str(e)}",
                        evidence_json={"error": str(e)},
                        recommendations_json=[
                            "Check target URL is accessible",
                            "Verify authentication token if provided",
                        ],
                    )
                )

        for result in results:
            TestResultRepository.create_test_result(
                db=db,
                scan_id=scan.id,
                test_name=result.test_name,
                status=result.status,
                severity=result.severity,
                details=result.details,
                evidence_json=result.evidence_json,
                recommendations_json=result.recommendations_json,
            )

        db.refresh(scan)

        return ScanResponse.model_validate(scan)

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: int, user_id: int) -> ScanResponse:
        """
        Get scan by ID with authorization check

        Args:
            db: Database session
            scan_id: Scan ID to retrieve
            user_id: User ID for authorization

        Returns:
            ScanResponse: Scan data with results
        """
        scan = ScanRepository.get_by_id(db, scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        if scan.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to access this scan",
            )

        return ScanResponse.model_validate(scan)

    @staticmethod
    def get_user_scans(
        db: Session, user_id: int, skip: int = 0, limit: int | None = None
    ) -> list[ScanResponse]:
        """
        Get all scans for a user with pagination

        Args:
            db: Database session
            user_id: User ID
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            list[ScanResponse]: List of user's scans
        """
        scans = ScanRepository.get_by_user(db=db, user_id=user_id, skip=skip, limit=limit)

        return [ScanResponse.model_validate(scan) for scan in scans]

    @staticmethod
    def delete_scan(db: Session, scan_id: int, user_id: int) -> bool:
        """
        Delete scan with authorization check

        Args:
            db: Database session
            scan_id: Scan ID to delete
            user_id: User ID for authorization

        Returns:
            bool: True if deleted successfully
        """
        scan = ScanRepository.get_by_id(db, scan_id)

        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )

        if scan.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to delete this scan",
            )

        return ScanRepository.delete(db, scan_id)
