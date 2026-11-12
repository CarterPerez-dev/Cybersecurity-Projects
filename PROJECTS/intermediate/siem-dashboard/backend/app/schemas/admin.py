"""
©AngelaMos | 2026
admin.py

Pydantic schemas for the admin user management endpoints

The role field in AdminUpdateRoleRequest uses a regex pattern built
from UserRole values to block invalid strings before they reach the
database layer.

Key exports:
  AdminUpdateRoleRequest - role change payload with pattern validation
  AdminUserListParams - pagination params for user listing

Connects to:
  models/User.py - imports UserRole for pattern generation
  config.py - reads DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
  routes/admin.py - passed to S()
"""

from pydantic import BaseModel, Field

from app.config import settings
from app.models.User import UserRole


VALID_ROLES = [r.value for r in UserRole]


class AdminUpdateRoleRequest(BaseModel):
    """
    Payload for changing a user role
    """
    role: str = Field(pattern = f"^({'|'.join(VALID_ROLES)})$")


class AdminUserListParams(BaseModel):
    """
    Query parameters for paginated user listing
    """
    page: int = Field(default = 1, ge = 1)
    per_page: int = Field(
        default = settings.DEFAULT_PAGE_SIZE,
        ge = 1,
        le = settings.MAX_PAGE_SIZE
    )
