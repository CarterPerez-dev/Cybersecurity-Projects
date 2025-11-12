"""
ⒸAngelaMos | 2025
TestResult model for storing individual security test results
"""

from sqlalchemy import (
    Column,
    Enum,
    Integer,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSON

from core.enums import (
    ScanStatus,
    Severity,
    TestType,
)
from .Base import BaseModel


class TestResult(BaseModel):
    """
    Stores individual test results for each security scan
    """

    __tablename__ = "test_results"

    scan_id = Column(
        Integer,
        ForeignKey("scans.id",
                   ondelete = "CASCADE"),
        nullable = False,
        index = True,
    )
    test_name = Column(
        Enum(TestType),
        nullable = False,
        index = True,
    )
    status = Column(
        Enum(ScanStatus),
        nullable = False,
        index = True,
    )
    severity = Column(
        Enum(Severity),
        nullable = False,
        index = True,
    )
    details = Column(Text, nullable = False)
    evidence_json = Column(JSON, nullable = False, default = dict)
    recommendations_json = Column(
        JSON,
        nullable = False,
        default = list
    )

    scan = relationship("Scan", back_populates = "test_results")

    def __repr__(self) -> str:
        """
        String representation of TestResult
        """
        return (
            f"<TestResult(id={self.id}, test_name={self.test_name.value}, "
            f"status={self.status.value})>"
        )

    @property
    def is_vulnerable(self) -> bool:
        """
        Check if this test result indicates a vulnerability

        Returns:
            bool: True if status is vulnerable
        """
        return self.status == ScanStatus.VULNERABLE

    @property
    def is_high_severity(self) -> bool:
        """
        Check if this is a high severity vulnerability

        Returns:
            bool: True if severity is high
        """
        return self.severity == Severity.HIGH
