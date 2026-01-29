"""
ⒸAngelaMos | 2025
repository.py
"""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import ProgramStatus, ProgramVisibility
from core.base_repository import BaseRepository
from .Program import Program
from .Asset import Asset
from .RewardTier import RewardTier


class ProgramRepository(BaseRepository[Program]):
    """
    Repository for Program model database operations
    """
    model = Program

    @classmethod
    async def get_by_slug(
        cls,
        session: AsyncSession,
        slug: str,
    ) -> Program | None:
        """
        Get program by slug
        """
        result = await session.execute(
            select(Program).where(Program.slug == slug)
        )
        return result.scalars().first()

    @classmethod
    async def get_by_slug_with_details(
        cls,
        session: AsyncSession,
        slug: str,
    ) -> Program | None:
        """
        Get program by slug with assets and reward tiers
        """
        result = await session.execute(
            select(Program).where(Program.slug == slug).options(
                selectinload(Program.assets),
                selectinload(Program.reward_tiers),
            )
        )
        return result.scalars().first()

    @classmethod
    async def get_by_id_with_details(
        cls,
        session: AsyncSession,
        program_id: UUID,
    ) -> Program | None:
        """
        Get program by ID with assets and reward tiers
        """
        result = await session.execute(
            select(Program).where(Program.id == program_id).options(
                selectinload(Program.assets),
                selectinload(Program.reward_tiers),
            )
        )
        return result.scalars().first()

    @classmethod
    async def slug_exists(
        cls,
        session: AsyncSession,
        slug: str,
    ) -> bool:
        """
        Check if slug is already taken
        """
        result = await session.execute(
            select(Program.id).where(Program.slug == slug)
        )
        return result.scalars().first() is not None

    @classmethod
    async def get_public_programs(
        cls,
        session: AsyncSession,
        skip: int = 0,
        limit: int = 20,
    ) -> Sequence[Program]:
        """
        Get active public programs
        """
        result = await session.execute(
            select(Program).where(
                Program.status == ProgramStatus.ACTIVE,
                Program.visibility == ProgramVisibility.PUBLIC,
            ).order_by(Program.created_at.desc()
                       ).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count_public_programs(
        cls,
        session: AsyncSession,
    ) -> int:
        """
        Count active public programs
        """
        result = await session.execute(
            select(func.count()).select_from(Program).where(
                Program.status == ProgramStatus.ACTIVE,
                Program.visibility == ProgramVisibility.PUBLIC,
            )
        )
        return result.scalar_one()

    @classmethod
    async def get_by_company(
        cls,
        session: AsyncSession,
        company_id: UUID,
        skip: int = 0,
        limit: int = 20,
    ) -> Sequence[Program]:
        """
        Get programs by company/owner
        """
        result = await session.execute(
            select(Program).where(Program.company_id == company_id
                                  ).order_by(Program.created_at.desc()
                                             ).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count_by_company(
        cls,
        session: AsyncSession,
        company_id: UUID,
    ) -> int:
        """
        Count programs by company
        """
        result = await session.execute(
            select(func.count()).select_from(Program).where(
                Program.company_id == company_id
            )
        )
        return result.scalar_one()


class AssetRepository(BaseRepository[Asset]):
    """
    Repository for Asset model database operations
    """
    model = Asset

    @classmethod
    async def get_by_program(
        cls,
        session: AsyncSession,
        program_id: UUID,
    ) -> Sequence[Asset]:
        """
        Get all assets for a program
        """
        result = await session.execute(
            select(Asset).where(
                Asset.program_id == program_id
            ).order_by(Asset.in_scope.desc(),
                       Asset.created_at)
        )
        return result.scalars().all()


class RewardTierRepository(BaseRepository[RewardTier]):
    """
    Repository for RewardTier model database operations
    """
    model = RewardTier

    @classmethod
    async def get_by_program(
        cls,
        session: AsyncSession,
        program_id: UUID,
    ) -> Sequence[RewardTier]:
        """
        Get all reward tiers for a program
        """
        result = await session.execute(
            select(RewardTier).where(RewardTier.program_id == program_id)
        )
        return result.scalars().all()

    @classmethod
    async def get_by_program_and_severity(
        cls,
        session: AsyncSession,
        program_id: UUID,
        severity: str,
    ) -> RewardTier | None:
        """
        Get reward tier by program and severity
        """
        result = await session.execute(
            select(RewardTier).where(
                RewardTier.program_id == program_id,
                RewardTier.severity == severity,
            )
        )
        return result.scalars().first()

    @classmethod
    async def delete_by_program(
        cls,
        session: AsyncSession,
        program_id: UUID,
    ) -> None:
        """
        Delete all reward tiers for a program
        """
        tiers = await cls.get_by_program(session, program_id)
        for tier in tiers:
            await session.delete(tier)
        await session.flush()
