"""
©AngelaMos | 2026
rules.py

Route handlers for the correlation rules API (/v1/rules)

Mounts full CRUD (GET /, POST, GET /<id>, PATCH /<id>, DELETE /<id>)
plus POST /<id>/test for dry-run rule evaluation against historical
events.

Connects to:
  controllers/rule_ctrl.py - business logic
  schemas/rule.py - RuleCreateRequest, RuleUpdateRequest, RuleTestRequest
  routes/__init__.py - rules_bp registered here
"""

from typing import Any

from flask import Blueprint

from app.controllers import rule_ctrl
from app.core.decorators import endpoint, S, R
from app.schemas.rule import (
    RuleCreateRequest,
    RuleUpdateRequest,
    RuleTestRequest,
)


rules_bp = Blueprint("rules", __name__)


@rules_bp.get("")
@endpoint()
@R()
def list_rules() -> Any:
    """
    Return all correlation rules
    """
    return rule_ctrl.list_rules()


@rules_bp.post("")
@endpoint()
@S(RuleCreateRequest)
@R(status = 201)
def create_rule() -> Any:
    """
    Create a new correlation rule
    """
    return rule_ctrl.create_rule()


@rules_bp.get("/<rule_id>")
@endpoint()
@R()
def get_rule(rule_id: str) -> Any:
    """
    Return a single correlation rule by ID
    """
    return rule_ctrl.get_rule(rule_id)


@rules_bp.patch("/<rule_id>")
@endpoint()
@S(RuleUpdateRequest)
@R()
def update_rule(rule_id: str) -> Any:
    """
    Partially update a correlation rule
    """
    return rule_ctrl.update_rule(rule_id)


@rules_bp.delete("/<rule_id>")
@endpoint()
@R()
def delete_rule(rule_id: str) -> Any:
    """
    Delete a correlation rule
    """
    return rule_ctrl.delete_rule(rule_id)


@rules_bp.post("/<rule_id>/test")
@endpoint()
@S(RuleTestRequest)
@R()
def test_rule(rule_id: str) -> Any:
    """
    Test a rule against historical log events
    """
    return rule_ctrl.test_rule(rule_id)
