"""
©AngelaMos | 2026
initial schema

Revision ID: 65c8ac60f6f6
Revises:
Create Date: 2026-02-11 17:43:24.263837
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

revision: str = "65c8ac60f6f6"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "threat_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "source_ip", sqlmodel.sql.sqltypes.AutoString(length=45), nullable=False
        ),
        sa.Column(
            "request_method",
            sqlmodel.sql.sqltypes.AutoString(length=10),
            nullable=False,
        ),
        sa.Column(
            "request_path", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("status_code", sa.SmallInteger(), nullable=False),
        sa.Column("response_size", sa.Integer(), nullable=False),
        sa.Column(
            "user_agent", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("threat_score", sa.Float(), nullable=False),
        sa.Column(
            "severity", sqlmodel.sql.sqltypes.AutoString(length=6), nullable=False
        ),
        sa.Column("component_scores", sa.JSON(), nullable=False),
        sa.Column(
            "geo_country",
            sqlmodel.sql.sqltypes.AutoString(length=2),
            nullable=True,
        ),
        sa.Column(
            "geo_city",
            sqlmodel.sql.sqltypes.AutoString(length=255),
            nullable=True,
        ),
        sa.Column("geo_lat", sa.Float(), nullable=True),
        sa.Column("geo_lon", sa.Float(), nullable=True),
        sa.Column("feature_vector", sa.JSON(), nullable=False),
        sa.Column("matched_rules", sa.JSON(), nullable=True),
        sa.Column(
            "model_version",
            sqlmodel.sql.sqltypes.AutoString(length=64),
            nullable=True,
        ),
        sa.Column("reviewed", sa.Boolean(), nullable=False),
        sa.Column(
            "review_label",
            sqlmodel.sql.sqltypes.AutoString(length=20),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index("idx_threat_events_created_at", "threat_events", ["created_at"])
    op.create_index("idx_threat_events_source_ip", "threat_events", ["source_ip"])
    op.create_index("idx_threat_events_severity", "threat_events", ["severity"])
    op.create_index("idx_threat_events_score", "threat_events", ["threat_score"])
    op.create_index(
        "idx_threat_events_reviewed",
        "threat_events",
        ["reviewed"],
        postgresql_where=sa.text("reviewed = FALSE"),
    )

    op.create_table(
        "model_metadata",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "model_type",
            sqlmodel.sql.sqltypes.AutoString(length=30),
            nullable=False,
        ),
        sa.Column(
            "version", sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False
        ),
        sa.Column("training_samples", sa.Integer(), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column(
            "artifact_path", sqlmodel.sql.sqltypes.AutoString(), nullable=False
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column(
            "mlflow_run_id",
            sqlmodel.sql.sqltypes.AutoString(length=64),
            nullable=True,
        ),
        sa.Column("threshold", sa.Float(), nullable=True),
        sa.Column("notes", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index(
        "idx_model_metadata_active",
        "model_metadata",
        ["model_type"],
        unique=True,
        postgresql_where=sa.text("is_active = TRUE"),
    )


def downgrade() -> None:
    op.drop_index("idx_model_metadata_active", table_name="model_metadata")
    op.drop_table("model_metadata")

    op.drop_index("idx_threat_events_reviewed", table_name="threat_events")
    op.drop_index("idx_threat_events_score", table_name="threat_events")
    op.drop_index("idx_threat_events_severity", table_name="threat_events")
    op.drop_index("idx_threat_events_source_ip", table_name="threat_events")
    op.drop_index("idx_threat_events_created_at", table_name="threat_events")
    op.drop_table("threat_events")
