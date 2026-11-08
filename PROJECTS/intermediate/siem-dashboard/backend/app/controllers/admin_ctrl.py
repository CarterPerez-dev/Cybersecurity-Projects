"""
©AngelaMos | 2026
admin_ctrl.py

Business logic for admin user management

Handles paginated user listing, single user lookup, role changes
with last-admin guard, and soft and hard delete with self-action
prevention. All operations are admin-only, enforced at the route
layer via the endpoint() decorator.

Key exports:
  list_users, get_user, update_role, deactivate_user, activate_user, delete_user

Connects to:
  models/User.py - CRUD and role operations
  core/errors.py - raises ForbiddenError, NotFoundError
  schemas/auth.py - uses UserResponse for serialization
  routes/admin.py - called from route handlers
"""

from typing import Any

from flask import g

from app.core.errors import ForbiddenError, NotFoundError
from app.models.User import User, UserRole
from app.schemas.auth import UserResponse


def list_users() -> dict[str, Any]:
    """
    Paginated listing of all user accounts
    """
    data = g.validated
    result = User.list_all(page = data.page, per_page = data.per_page)
    result["items"] = [
        UserResponse(
            id = str(u.id),
            username = u.username,
            email = u.email,
            role = u.role,
            is_active = u.is_active,
        ).model_dump() for u in result["items"]
    ]
    return result


def get_user(user_id: str) -> dict[str, Any]:
    """
    Retrieve a single user by ID
    """
    user = User.get_by_id(user_id)
    return UserResponse(
        id = str(user.id),
        username = user.username,
        email = user.email,
        role = user.role,
        is_active = user.is_active,
    ).model_dump()


def update_role(user_id: str) -> dict[str, Any]:
    """
    Change a user's role with last-admin protection
    """
    caller = g.current_user
    target = User.get_by_id(user_id)
    data = g.validated

    if str(target.id) == str(
            caller.id) and data.role != UserRole.ADMIN and User.count_admins() <= 1:
        raise ForbiddenError("Cannot demote the last admin")

    target.set_role(data.role)
    return UserResponse(
        id = str(target.id),
        username = target.username,
        email = target.email,
        role = target.role,
        is_active = target.is_active,
    ).model_dump()


def _prevent_self_action(caller: User, target: User, action: str) -> None:
    """
    Block admins from deactivating or deleting their own account
    """
    if str(target.id) == str(caller.id):
        raise ForbiddenError(f"Cannot {action} your own account")


def deactivate_user(user_id: str) -> dict[str, Any]:
    """
    Soft-delete a user by marking them inactive
    """
    caller = g.current_user
    target = User.get_by_id(user_id)
    _prevent_self_action(caller, target, "deactivate")

    target.deactivate()
    return UserResponse(
        id = str(target.id),
        username = target.username,
        email = target.email,
        role = target.role,
        is_active = target.is_active,
    ).model_dump()


def activate_user(user_id: str) -> dict[str, Any]:
    """
    Re-enable a previously deactivated user
    """
    target = User.get_by_id(user_id)
    if target.is_active:
        raise NotFoundError("User is already active")

    target.activate()
    return UserResponse(
        id = str(target.id),
        username = target.username,
        email = target.email,
        role = target.role,
        is_active = target.is_active,
    ).model_dump()


def delete_user(user_id: str) -> dict[str, Any]:
    """
    Permanently remove a user document
    """
    caller = g.current_user
    target = User.get_by_id(user_id)
    _prevent_self_action(caller, target, "delete")

    target.hard_delete()
    return {"deleted": True}
