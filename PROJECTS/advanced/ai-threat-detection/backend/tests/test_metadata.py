"""
©AngelaMos | 2026
test_metadata.py

Tests SHA-256 model version hashing and async metadata
persistence to the database

TestComputeModelVersion verifies 12-char hex output,
deterministic hashing (same file = same version), and
distinct versions for different files. TestSaveModel
Metadata uses an in-memory SQLite session and fake ONNX
artifacts to validate 3-row creation (one per model type),
is_active flag on new rows, correct model_type values
(autoencoder, random_forest, isolation_forest), previous
active row deactivation on re-save, and inactive row
preservation (6 total rows after two saves)

Connects to:
  ml/metadata             - compute_model_version,
                            save_model_metadata
  models/model_metadata   - ModelMetadata ORM model
"""

import json
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool
from sqlalchemy import select
from sqlmodel import SQLModel

from app.models.model_metadata import ModelMetadata
from ml.metadata import compute_model_version, save_model_metadata


@pytest.fixture
async def db_session(tmp_path: Path):
    """
    In-memory SQLite session for metadata tests
    """
    from app.models import model_metadata as _reg  # noqa: F401

    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    factory = async_sessionmaker(engine,
                                 class_=AsyncSession,
                                 expire_on_commit=False)
    async with factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def model_artifacts(tmp_path: Path) -> Path:
    """
    Create fake ONNX model files for version hashing
    """
    (tmp_path / "ae.onnx").write_bytes(b"ae-model-data-123")
    (tmp_path / "rf.onnx").write_bytes(b"rf-model-data-456")
    (tmp_path / "if.onnx").write_bytes(b"if-model-data-789")
    (tmp_path / "scaler.json").write_text(
        json.dumps({
            "center": [0.0],
            "scale": [1.0]
        }))
    (tmp_path / "threshold.json").write_text(json.dumps({"threshold": 0.05}))
    return tmp_path


class TestComputeModelVersion:
    """
    Test SHA-256 based model version hashing
    """

    def test_returns_12_char_hex(self, model_artifacts: Path) -> None:
        """
        Version string is a 12-character hex digest
        """
        version = compute_model_version(model_artifacts / "ae.onnx")

        assert len(version) == 12
        assert all(c in "0123456789abcdef" for c in version)

    def test_same_file_same_version(self, model_artifacts: Path) -> None:
        """
        Same file produces the same version string
        """
        v1 = compute_model_version(model_artifacts / "ae.onnx")
        v2 = compute_model_version(model_artifacts / "ae.onnx")

        assert v1 == v2

    def test_different_files_different_versions(self,
                                                model_artifacts: Path) -> None:
        """
        Different files produce different version strings
        """
        v_ae = compute_model_version(model_artifacts / "ae.onnx")
        v_rf = compute_model_version(model_artifacts / "rf.onnx")

        assert v_ae != v_rf


class TestSaveModelMetadata:
    """
    Test model metadata persistence to database
    """

    @pytest.mark.asyncio
    async def test_creates_three_rows(
        self,
        db_session: AsyncSession,
        model_artifacts: Path,
    ) -> None:
        """
        save_model_metadata creates one row per model type
        """
        rows = await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=500,
            metrics={
                "f1": 0.9,
                "pr_auc": 0.88
            },
        )

        assert len(rows) == 3

    @pytest.mark.asyncio
    async def test_all_rows_active(
        self,
        db_session: AsyncSession,
        model_artifacts: Path,
    ) -> None:
        """
        All newly saved models are marked as active
        """
        rows = await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=500,
            metrics={"f1": 0.9},
        )

        assert all(r.is_active for r in rows)

    @pytest.mark.asyncio
    async def test_model_types_correct(
        self,
        db_session: AsyncSession,
        model_artifacts: Path,
    ) -> None:
        """
        Row model types are autoencoder, random_forest, isolation_forest
        """
        rows = await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=500,
            metrics={},
        )
        types = {r.model_type for r in rows}

        assert types == {
            "autoencoder",
            "random_forest",
            "isolation_forest",
        }

    @pytest.mark.asyncio
    async def test_previous_active_replaced(
        self,
        db_session: AsyncSession,
        model_artifacts: Path,
    ) -> None:
        """
        Saving new metadata replaces previous active models
        """
        await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=500,
            metrics={"f1": 0.9},
        )

        (model_artifacts / "ae.onnx").write_bytes(b"new-ae-data")
        await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=600,
            metrics={"f1": 0.95},
        )

        result = await db_session.execute(select(ModelMetadata))
        all_rows = result.scalars().all()
        active_rows = [r for r in all_rows if r.is_active]

        assert len(active_rows) == 3
        assert all(r.training_samples == 600 for r in active_rows)

    @pytest.mark.asyncio
    async def test_previous_inactive_rows_preserved(
        self,
        db_session: AsyncSession,
        model_artifacts: Path,
    ) -> None:
        """
        Old model rows are deactivated, not deleted, after a new save
        """
        await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=500,
            metrics={"f1": 0.9},
        )

        (model_artifacts / "ae.onnx").write_bytes(b"new-ae-data")
        await save_model_metadata(
            db_session,
            model_dir=model_artifacts,
            training_samples=600,
            metrics={"f1": 0.95},
        )

        result = await db_session.execute(select(ModelMetadata))
        all_rows = result.scalars().all()
        inactive = [r for r in all_rows if not r.is_active]

        assert len(all_rows) == 6
        assert len(inactive) == 3
        assert all(r.training_samples == 500 for r in inactive)
