"""
ⒸAngelaMos | 2025
routes.py
"""

from uuid import UUID

from fastapi import APIRouter, Query, status

from core.dependencies import CurrentUser
from core.responses import (
    AUTH_401,
    CONFLICT_409,
    FORBIDDEN_403,
    NOT_FOUND_404,
)
from .schemas import (
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    ProgramCreate,
    ProgramDetailResponse,
    ProgramListResponse,
    ProgramResponse,
    ProgramUpdate,
    RewardTierCreate,
    RewardTierResponse,
)
from .dependencies import ProgramServiceDep


router = APIRouter(prefix = "/programs", tags = ["programs"])


@router.post(
    "",
    response_model = ProgramResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {
        **AUTH_401,
        **CONFLICT_409
    },
)
async def create_program(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_data: ProgramCreate,
) -> ProgramResponse:
    """
    Create a new bug bounty program
    """
    return await program_service.create_program(current_user, program_data)


@router.get(
    "",
    response_model = ProgramListResponse,
)
async def list_programs(
    program_service: ProgramServiceDep,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(default = 20,
                      ge = 1,
                      le = 100),
) -> ProgramListResponse:
    """
    List active public programs
    """
    return await program_service.list_public_programs(page, size)


@router.get(
    "/mine",
    response_model = ProgramListResponse,
    responses = {**AUTH_401},
)
async def list_my_programs(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    page: int = Query(default = 1,
                      ge = 1),
    size: int = Query(default = 20,
                      ge = 1,
                      le = 100),
) -> ProgramListResponse:
    """
    List programs owned by current user
    """
    return await program_service.list_my_programs(current_user, page, size)


@router.get(
    "/{slug}",
    response_model = ProgramDetailResponse,
    responses = {**NOT_FOUND_404},
)
async def get_program(
    program_service: ProgramServiceDep,
    slug: str,
) -> ProgramDetailResponse:
    """
    Get program by slug with full details
    """
    return await program_service.get_program_by_slug(slug)


@router.patch(
    "/{program_id}",
    response_model = ProgramResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def update_program(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    program_data: ProgramUpdate,
) -> ProgramResponse:
    """
    Update program details
    """
    return await program_service.update_program(
        current_user,
        program_id,
        program_data
    )


@router.delete(
    "/{program_id}",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def delete_program(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
) -> None:
    """
    Delete a program
    """
    await program_service.delete_program(current_user, program_id)


@router.get(
    "/{program_id}/assets",
    response_model = list[AssetResponse],
    responses = {**NOT_FOUND_404},
)
async def list_assets(
    program_service: ProgramServiceDep,
    program_id: UUID,
) -> list[AssetResponse]:
    """
    List program assets (scope)
    """
    return await program_service.list_assets(program_id)


@router.post(
    "/{program_id}/assets",
    response_model = AssetResponse,
    status_code = status.HTTP_201_CREATED,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def add_asset(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    asset_data: AssetCreate,
) -> AssetResponse:
    """
    Add asset to program scope
    """
    return await program_service.add_asset(
        current_user,
        program_id,
        asset_data
    )


@router.patch(
    "/{program_id}/assets/{asset_id}",
    response_model = AssetResponse,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def update_asset(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    asset_id: UUID,
    asset_data: AssetUpdate,
) -> AssetResponse:
    """
    Update an asset
    """
    return await program_service.update_asset(
        current_user,
        program_id,
        asset_id,
        asset_data
    )


@router.delete(
    "/{program_id}/assets/{asset_id}",
    status_code = status.HTTP_204_NO_CONTENT,
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def delete_asset(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    asset_id: UUID,
) -> None:
    """
    Delete an asset
    """
    await program_service.delete_asset(current_user, program_id, asset_id)


@router.get(
    "/{program_id}/rewards",
    response_model = list[RewardTierResponse],
    responses = {**NOT_FOUND_404},
)
async def list_reward_tiers(
    program_service: ProgramServiceDep,
    program_id: UUID,
) -> list[RewardTierResponse]:
    """
    List program reward tiers
    """
    return await program_service.list_reward_tiers(program_id)


@router.put(
    "/{program_id}/rewards",
    response_model = list[RewardTierResponse],
    responses = {
        **AUTH_401,
        **FORBIDDEN_403,
        **NOT_FOUND_404
    },
)
async def set_reward_tiers(
    program_service: ProgramServiceDep,
    current_user: CurrentUser,
    program_id: UUID,
    tiers: list[RewardTierCreate],
) -> list[RewardTierResponse]:
    """
    Set reward tiers for program (replaces existing)
    """
    return await program_service.set_reward_tiers(
        current_user,
        program_id,
        tiers
    )
