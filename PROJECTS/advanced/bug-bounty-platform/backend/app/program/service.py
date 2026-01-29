"""
ⒸAngelaMos | 2025
service.py
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from core.exceptions import (
    AssetNotFound,
    NotProgramOwner,
    ProgramNotFound,
    SlugAlreadyExists,
)
from user.User import User
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
from .repository import (
    AssetRepository,
    ProgramRepository,
    RewardTierRepository,
)


class ProgramService:
    """
    Business logic for program operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_program(
        self,
        user: User,
        program_data: ProgramCreate,
    ) -> ProgramResponse:
        """
        Create a new bug bounty program
        """
        if await ProgramRepository.slug_exists(self.session,
                                               program_data.slug):
            raise SlugAlreadyExists(program_data.slug)

        program = await ProgramRepository.create(
            self.session,
            company_id = user.id,
            name = program_data.name,
            slug = program_data.slug,
            description = program_data.description,
            rules = program_data.rules,
            response_sla_hours = program_data.response_sla_hours,
            visibility = program_data.visibility,
        )
        return ProgramResponse.model_validate(program)

    async def get_program_by_slug(
        self,
        slug: str,
    ) -> ProgramDetailResponse:
        """
        Get program by slug with full details
        """
        program = await ProgramRepository.get_by_slug_with_details(
            self.session,
            slug
        )
        if not program:
            raise ProgramNotFound(slug)

        return ProgramDetailResponse(
            id = program.id,
            created_at = program.created_at,
            updated_at = program.updated_at,
            company_id = program.company_id,
            name = program.name,
            slug = program.slug,
            description = program.description,
            rules = program.rules,
            response_sla_hours = program.response_sla_hours,
            status = program.status,
            visibility = program.visibility,
            assets = [
                AssetResponse.model_validate(a) for a in program.assets
            ],
            reward_tiers = [
                RewardTierResponse.model_validate(r)
                for r in program.reward_tiers
            ],
        )

    async def get_program_by_id(
        self,
        program_id: UUID,
    ) -> ProgramResponse:
        """
        Get program by ID
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))
        return ProgramResponse.model_validate(program)

    async def list_public_programs(
        self,
        page: int,
        size: int,
    ) -> ProgramListResponse:
        """
        List active public programs
        """
        skip = (page - 1) * size
        programs = await ProgramRepository.get_public_programs(
            self.session,
            skip = skip,
            limit = size,
        )
        total = await ProgramRepository.count_public_programs(self.session)
        return ProgramListResponse(
            items = [ProgramResponse.model_validate(p) for p in programs],
            total = total,
            page = page,
            size = size,
        )

    async def list_my_programs(
        self,
        user: User,
        page: int,
        size: int,
    ) -> ProgramListResponse:
        """
        List programs owned by user
        """
        skip = (page - 1) * size
        programs = await ProgramRepository.get_by_company(
            self.session,
            company_id = user.id,
            skip = skip,
            limit = size,
        )
        total = await ProgramRepository.count_by_company(
            self.session,
            user.id
        )
        return ProgramListResponse(
            items = [ProgramResponse.model_validate(p) for p in programs],
            total = total,
            page = page,
            size = size,
        )

    async def update_program(
        self,
        user: User,
        program_id: UUID,
        program_data: ProgramUpdate,
    ) -> ProgramResponse:
        """
        Update program details
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        update_dict = program_data.model_dump(exclude_unset = True)
        updated = await ProgramRepository.update(
            self.session,
            program,
            **update_dict,
        )
        return ProgramResponse.model_validate(updated)

    async def delete_program(
        self,
        user: User,
        program_id: UUID,
    ) -> None:
        """
        Delete a program
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        await ProgramRepository.delete(self.session, program)

    async def add_asset(
        self,
        user: User,
        program_id: UUID,
        asset_data: AssetCreate,
    ) -> AssetResponse:
        """
        Add asset to program scope
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        asset = await AssetRepository.create(
            self.session,
            program_id = program_id,
            asset_type = asset_data.asset_type,
            identifier = asset_data.identifier,
            in_scope = asset_data.in_scope,
            description = asset_data.description,
        )
        return AssetResponse.model_validate(asset)

    async def update_asset(
        self,
        user: User,
        program_id: UUID,
        asset_id: UUID,
        asset_data: AssetUpdate,
    ) -> AssetResponse:
        """
        Update an asset
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        asset = await AssetRepository.get_by_id(self.session, asset_id)
        if not asset or asset.program_id != program_id:
            raise AssetNotFound(str(asset_id))

        update_dict = asset_data.model_dump(exclude_unset = True)
        updated = await AssetRepository.update(
            self.session,
            asset,
            **update_dict,
        )
        return AssetResponse.model_validate(updated)

    async def delete_asset(
        self,
        user: User,
        program_id: UUID,
        asset_id: UUID,
    ) -> None:
        """
        Delete an asset
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        asset = await AssetRepository.get_by_id(self.session, asset_id)
        if not asset or asset.program_id != program_id:
            raise AssetNotFound(str(asset_id))

        await AssetRepository.delete(self.session, asset)

    async def list_assets(
        self,
        program_id: UUID,
    ) -> list[AssetResponse]:
        """
        List all assets for a program
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        assets = await AssetRepository.get_by_program(
            self.session,
            program_id
        )
        return [AssetResponse.model_validate(a) for a in assets]

    async def set_reward_tiers(
        self,
        user: User,
        program_id: UUID,
        tiers: list[RewardTierCreate],
    ) -> list[RewardTierResponse]:
        """
        Set reward tiers for a program (replaces existing)
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        if program.company_id != user.id:
            raise NotProgramOwner()

        await RewardTierRepository.delete_by_program(
            self.session,
            program_id
        )

        created_tiers = []
        for tier_data in tiers:
            tier = await RewardTierRepository.create(
                self.session,
                program_id = program_id,
                severity = tier_data.severity,
                min_bounty = tier_data.min_bounty,
                max_bounty = tier_data.max_bounty,
                currency = tier_data.currency,
            )
            created_tiers.append(RewardTierResponse.model_validate(tier))

        return created_tiers

    async def list_reward_tiers(
        self,
        program_id: UUID,
    ) -> list[RewardTierResponse]:
        """
        List reward tiers for a program
        """
        program = await ProgramRepository.get_by_id(
            self.session,
            program_id
        )
        if not program:
            raise ProgramNotFound(str(program_id))

        tiers = await RewardTierRepository.get_by_program(
            self.session,
            program_id
        )
        return [RewardTierResponse.model_validate(t) for t in tiers]
