"""
ⒸAngelaMos | 2025
schemas.py
"""

from uuid import UUID
from decimal import Decimal

from pydantic import Field, field_validator, ValidationInfo

from config import (
    ASSET_IDENTIFIER_MAX_LENGTH,
    AssetType,
    PROGRAM_DESCRIPTION_MAX_LENGTH,
    PROGRAM_NAME_MAX_LENGTH,
    PROGRAM_RULES_MAX_LENGTH,
    PROGRAM_SLUG_MAX_LENGTH,
    ProgramStatus,
    ProgramVisibility,
    Severity,
)
from core.base_schema import (
    BaseSchema,
    BaseResponseSchema,
)


class RewardTierCreate(BaseSchema):
    """
    Schema for creating a reward tier
    """
    severity: Severity
    min_bounty: int = Field(ge = 0, default = 0)
    max_bounty: int = Field(ge = 0, default = 0)
    currency: str = Field(default = "USD", max_length = 3)

    @field_validator("max_bounty")
    @classmethod
    def max_gte_min(cls, v: int, info: ValidationInfo) -> int:
        """
        Ensure max bounty is greater than or equal to min bounty
        """
        if "min_bounty" in info.data and v < info.data["min_bounty"]:
            raise ValueError("max_bounty must be >= min_bounty")
        return v


class RewardTierResponse(BaseResponseSchema):
    """
    Schema for reward tier API responses
    """
    program_id: UUID
    severity: Severity
    min_bounty: int
    max_bounty: int
    currency: str


class AssetCreate(BaseSchema):
    """
    Schema for creating an asset
    """
    asset_type: AssetType = AssetType.DOMAIN
    identifier: str = Field(max_length = ASSET_IDENTIFIER_MAX_LENGTH)
    in_scope: bool = True
    description: str | None = None


class AssetUpdate(BaseSchema):
    """
    Schema for updating an asset
    """
    asset_type: AssetType | None = None
    identifier: str | None = Field(
        default = None,
        max_length = ASSET_IDENTIFIER_MAX_LENGTH
    )
    in_scope: bool | None = None
    description: str | None = None


class AssetResponse(BaseResponseSchema):
    """
    Schema for asset API responses
    """
    program_id: UUID
    asset_type: AssetType
    identifier: str
    in_scope: bool
    description: str | None


class ProgramCreate(BaseSchema):
    """
    Schema for creating a program
    """
    name: str = Field(max_length = PROGRAM_NAME_MAX_LENGTH)
    slug: str = Field(
        max_length = PROGRAM_SLUG_MAX_LENGTH,
        pattern = r"^[a-z0-9-]+$"
    )
    description: str | None = Field(
        default = None,
        max_length = PROGRAM_DESCRIPTION_MAX_LENGTH
    )
    rules: str | None = Field(
        default = None,
        max_length = PROGRAM_RULES_MAX_LENGTH
    )
    response_sla_hours: int = Field(default = 72, ge = 1, le = 720)
    visibility: ProgramVisibility = ProgramVisibility.PUBLIC


class ProgramUpdate(BaseSchema):
    """
    Schema for updating a program
    """
    name: str | None = Field(
        default = None,
        max_length = PROGRAM_NAME_MAX_LENGTH
    )
    description: str | None = Field(
        default = None,
        max_length = PROGRAM_DESCRIPTION_MAX_LENGTH
    )
    rules: str | None = Field(
        default = None,
        max_length = PROGRAM_RULES_MAX_LENGTH
    )
    response_sla_hours: int | None = Field(
        default = None,
        ge = 1,
        le = 720
    )
    status: ProgramStatus | None = None
    visibility: ProgramVisibility | None = None


class ProgramResponse(BaseResponseSchema):
    """
    Schema for program API responses
    """
    company_id: UUID
    name: str
    slug: str
    description: str | None
    rules: str | None
    response_sla_hours: int
    status: ProgramStatus
    visibility: ProgramVisibility


class ProgramDetailResponse(ProgramResponse):
    """
    Schema for program detail with assets and rewards
    """
    assets: list[AssetResponse]
    reward_tiers: list[RewardTierResponse]


class ProgramListResponse(BaseSchema):
    """
    Schema for paginated program list
    """
    items: list[ProgramResponse]
    total: int
    page: int
    size: int


class ProgramStatsResponse(BaseSchema):
    """
    Schema for program statistics
    """
    total_reports: int
    open_reports: int
    resolved_reports: int
    total_paid: int
    average_response_hours: Decimal | None
