"""
©AngelaMos | 2026
User.py

MongoEngine model for SIEM user accounts

Stores credentials, role, and active status. Provides class methods
for lookups, existence checks, creation, and listing. Instance methods
handle role changes, soft-delete via deactivate/activate, and hard
delete. USERNAME_MIN and USERNAME_MAX are shared with the auth schema.

Key exports:
  User - user document with auth and admin query methods
  UserRole - StrEnum for analyst and admin roles
  USERNAME_MIN, USERNAME_MAX - length constraints shared with schemas

Connects to:
  models/Base.py - extends BaseDocument
  config.py - reads DEFAULT_PAGE_SIZE
  core/decorators/endpoint.py - User loaded from JWT sub claim
  controllers/auth_ctrl.py, controllers/admin_ctrl.py - CRUD operations
  schemas/auth.py - imports USERNAME_MIN, USERNAME_MAX
  cli.py - calls create_user, find_by_username, set_role
"""

from typing import Any
from enum import StrEnum

from mongoengine import (
    StringField,
    BooleanField,
    EmailField,
)

from app.config import settings
from app.models.Base import BaseDocument


class UserRole(StrEnum):
    """
    Available user roles
    """
    ANALYST = "analyst"
    ADMIN = "admin"


USERNAME_MIN = 3
USERNAME_MAX = 32


class User(BaseDocument):
    """
    User document with repository query methods
    """
    meta: dict[str, Any] = {"collection": "users"}  # noqa: RUF012

    username = StringField(
        required = True,
        unique = True,
        min_length = USERNAME_MIN,
        max_length = USERNAME_MAX,
    )
    email = EmailField(required = True, unique = True)
    password_hash = StringField(required = True)
    role = StringField(
        required = True,
        default = UserRole.ANALYST,
        choices = [r.value for r in UserRole],
    )
    is_active = BooleanField(default = True)

    @classmethod
    def find_by_username(cls, username: str) -> User | None:
        """
        Look up a user by their username
        """
        return cls.objects(username = username).first()  # type: ignore[no-untyped-call, no-any-return]

    @classmethod
    def find_by_email(cls, email: str) -> User | None:
        """
        Look up a user by their email
        """
        return cls.objects(email = email).first()  # type: ignore[no-untyped-call, no-any-return]

    @classmethod
    def username_exists(cls, username: str) -> bool:
        """
        Check if a username is already taken
        """
        return cls.objects(username = username).count() > 0  # type: ignore[no-untyped-call, no-any-return]

    @classmethod
    def email_exists(cls, email: str) -> bool:
        """
        Check if an email is already registered
        """
        return cls.objects(email = email).count() > 0  # type: ignore[no-untyped-call, no-any-return]

    @classmethod
    def create_user(
        cls,
        username: str,
        email: str,
        password_hash: str,
        role: str = UserRole.ANALYST,
    ) -> User:
        """
        Create and save a new user with a pre hashed password
        """
        user = cls(
            username = username,
            email = email,
            password_hash = password_hash,
            role = role,
        )
        user.save()  # type: ignore[no-untyped-call]
        return user

    @classmethod
    def list_all(
        cls,
        page: int = 1,
        per_page: int = settings.DEFAULT_PAGE_SIZE,
    ) -> dict[str,
              Any]:
        """
        Paginated list of all users ordered by creation date
        """
        qs = cls.objects.order_by("-created_at")  # type: ignore[attr-defined]
        return cls.paginate(qs, page, per_page)

    @classmethod
    def count_admins(cls) -> int:
        """
        Count active users with the admin role
        """
        return cls.objects(role = UserRole.ADMIN, is_active = True).count()  # type: ignore[no-untyped-call, no-any-return]

    def update_profile(self, **fields: str) -> User:
        """
        Update mutable profile fields and save
        """
        allowed = {"username", "email", "password_hash"}
        for key, value in fields.items():
            if key in allowed and value is not None:
                setattr(self, key, value)
        self.save()  # type: ignore[no-untyped-call]
        return self

    def set_role(self, role: str) -> None:
        """
        Change the user role and persist
        """
        self.role = role
        self.save()  # type: ignore[no-untyped-call]

    def deactivate(self) -> None:
        """
        Soft-delete by marking the account inactive
        """
        self.is_active = False
        self.save()  # type: ignore[no-untyped-call]

    def activate(self) -> None:
        """
        Re-enable a previously deactivated account
        """
        self.is_active = True
        self.save()  # type: ignore[no-untyped-call]

    def hard_delete(self) -> None:
        """
        Permanently remove the user document
        """
        self.delete()  # type: ignore[no-untyped-call]
