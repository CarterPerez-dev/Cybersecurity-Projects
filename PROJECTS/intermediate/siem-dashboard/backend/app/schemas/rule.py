"""
©AngelaMos | 2026
rule.py

Pydantic schemas for correlation rule endpoints

Defines condition schemas for each rule type (threshold, sequence,
aggregation) and validates the conditions dict in RuleCreateRequest
against the correct schema based on rule_type, catching structural
errors before a rule reaches the engine.

Key exports:
  RuleCreateRequest - creation schema with conditions validation
  RuleUpdateRequest - partial update schema
  RuleTestRequest - hours window for dry-run evaluation
  ThresholdConditions, SequenceConditions, AggregationConditions

Connects to:
  models/CorrelationRule.py - imports RuleType
  models/LogEvent.py - imports Severity
  config.py - reads TIMELINE_DEFAULT_HOURS, RULE_TEST_MAX_HOURS
  routes/rules.py - passed to S()
"""

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from app.config import settings
from app.models.CorrelationRule import RuleType
from app.models.LogEvent import Severity


class ThresholdConditions(BaseModel):
    """
    Conditions for threshold-based correlation rules
    """
    event_filter: dict[str, str]
    threshold: int = Field(ge = 1)
    window_seconds: int = Field(ge = 1)
    group_by: str


class SequenceStep(BaseModel):
    """
    A single step in a sequence correlation rule
    """
    event_filter: dict[str, str]
    count: int = Field(default = 1, ge = 1)


class SequenceConditions(BaseModel):
    """
    Conditions for sequence-based correlation rules
    """
    steps: list[SequenceStep] = Field(min_length = 2)
    window_seconds: int = Field(ge = 1)
    group_by: str


class AggregationConditions(BaseModel):
    """
    Conditions for aggregation-based correlation rules
    """
    event_filter: dict[str, str]
    aggregation: Literal["count_distinct"]
    aggregation_field: str
    threshold: int = Field(ge = 1)
    window_seconds: int = Field(ge = 1)
    group_by: str


CONDITION_SCHEMAS: dict[RuleType,
                        type[BaseModel]] = {
                            RuleType.THRESHOLD: ThresholdConditions,
                            RuleType.SEQUENCE: SequenceConditions,
                            RuleType.AGGREGATION: AggregationConditions,
                        }


class RuleCreateRequest(BaseModel):
    """
    Schema for creating a new correlation rule
    """
    name: str = Field(min_length = 1)
    description: str = ""
    rule_type: RuleType
    conditions: dict[str, Any]
    severity: Severity
    enabled: bool = True
    mitre_tactic: str | None = None
    mitre_technique: str | None = None

    @model_validator(mode = "after")
    def validate_conditions(self) -> RuleCreateRequest:
        """
        Validate conditions dict matches the expected structure for rule_type
        """
        schema = CONDITION_SCHEMAS[self.rule_type]
        schema.model_validate(self.conditions)
        return self


class RuleUpdateRequest(BaseModel):
    """
    Schema for updating an existing correlation rule
    """
    name: str | None = None
    description: str | None = None
    conditions: dict[str, Any] | None = None
    severity: Severity | None = None
    enabled: bool | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None


class RuleTestRequest(BaseModel):
    """
    Schema for testing a rule against historical events
    """
    hours: int = Field(
        default = settings.TIMELINE_DEFAULT_HOURS,
        ge = 1,
        le = settings.RULE_TEST_MAX_HOURS,
    )
