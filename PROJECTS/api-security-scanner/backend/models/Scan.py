"""
ⒸAngelaMos | 2025
Scan model for storing security scan metadata
"""

from datetime import (
    UTC,
    datetime,
)
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.orm import relationship

from config import settings
from .Base import BaseModel


class Scan(BaseModel):
    """
    Stores metadata about scans performed on target URLs
    """

    __tablename__ = "scans"

    user_id = Column(
        Integer,
        ForeignKey("users.id",
                   ondelete = "CASCADE"),
        nullable = False,
        index = True,
    )
    target_url = Column(
        String(settings.URL_MAX_LENGTH),
        nullable = False,
    )
    scan_date = Column(
        DateTime(timezone = True),
        default = lambda: datetime.now(UTC),
        nullable = False,
    )

    user = relationship("User", backref = "scans")
    test_results = relationship(
        "TestResult",
        back_populates = "scan",
        cascade = "all, delete-orphan",
    )

    def __repr__(self) -> str:
        """
        String representation of Scan
        """
        return f"<Scan(id={self.id}, target_url={self.target_url}, user_id={self.user_id})>"

    @property
    def has_vulnerabilities(self) -> bool:
        """
        Check if scan found any vulnerabilities

        Returns:
            bool: True if any test result is vulnerable
        """
        return any(
            result.status == "vulnerable"
            for result in self.test_results
        )

    @property
    def vulnerability_count(self) -> int:
        """
        Count of vulnerabilities found in this scan

        Returns:
            int: Number of vulnerable test results
        """
        return sum(
            1 for result in self.test_results
            if result.status == "vulnerable"
        )
