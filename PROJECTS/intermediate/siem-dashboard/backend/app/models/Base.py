"""
©AngelaMos | 2026
Base.py

Abstract MongoEngine document with timestamps and shared query helpers

All MongoEngine models extend BaseDocument to get created_at and
updated_at timestamps with auto-refresh on save, plus get_by_id,
get_or_none, and paginate class methods used across every controller.

Key exports:
  BaseDocument - abstract base class for all MongoEngine documents

Connects to:
  config.py - reads DEFAULT_PAGE_SIZE
  core/errors.py - raises NotFoundError from get_by_id
  Alert.py, CorrelationRule.py, LogEvent.py, ScenarioRun.py, User.py - all extend BaseDocument
"""

from typing import Any, Self
from datetime import datetime, UTC

from mongoengine import (
    Document,
    DateTimeField,
    QuerySet,
)

from app.config import settings
from app.core.errors import NotFoundError


class BaseDocument(Document):  # type: ignore[misc]
    """
    Abstract base with timestamps and common query helpers
    """
    meta = {"abstract": True}  # noqa: RUF012

    created_at = DateTimeField(default = lambda: datetime.now(UTC))
    updated_at = DateTimeField(default = lambda: datetime.now(UTC))

    def save(self, *args: Any, **kwargs: Any) -> Any:
        """
        Auto-update the updated_at timestamp on every save
        """
        self.updated_at = datetime.now(UTC)
        return super().save(*args, **kwargs)

    @classmethod
    def get_by_id(cls, doc_id: str) -> Self:
        """
        Fetch by ID or raise NotFoundError
        """
        doc = cls.objects(id = doc_id).first()
        if doc is None:
            raise NotFoundError(f"{cls.__name__} not found")
        return doc  # type: ignore[no-any-return]

    @classmethod
    def get_or_none(cls, doc_id: str) -> Self | None:
        """
        Fetch by ID or return None
        """
        return cls.objects(id = doc_id).first()  # type: ignore[no-any-return]

    @classmethod
    def paginate(
        cls,
        queryset: QuerySet | None = None,
        page: int = 1,
        per_page: int = settings.DEFAULT_PAGE_SIZE,
    ) -> dict[str,
              Any]:
        """
        Return a paginated result dict from any queryset
        """
        qs = queryset if queryset is not None else cls.objects
        total = qs.count()
        offset = (page - 1) * per_page
        items = list(qs.skip(offset).limit(per_page))
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
        }
