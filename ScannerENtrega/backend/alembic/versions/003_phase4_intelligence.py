"""phase4_service_intelligence_and_history

Revision ID: 003_phase4_intelligence
Revises: 002_service_heartbeats
Create Date: 2026-08-05 12:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "003_phase4_intelligence"
down_revision: Union[str, None] = "002_service_heartbeats"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create service_observations table
    op.create_table(
        "service_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("raw_service_name", sa.String(length=120), nullable=True),
        sa.Column("normalized_service_name", sa.String(length=120), nullable=True),
        sa.Column("raw_product", sa.String(length=255), nullable=True),
        sa.Column("normalized_product", sa.String(length=255), nullable=True),
        sa.Column("raw_version", sa.String(length=120), nullable=True),
        sa.Column("normalized_version", sa.String(length=120), nullable=True),
        sa.Column("cpe", sa.String(length=255), nullable=True),
        sa.Column("category", sa.String(length=60), nullable=True),
        sa.Column("confidence", sa.String(length=20), nullable=True),
        sa.ForeignKeyConstraint(["execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["discovered_services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("execution_id", "service_id", name="uq_service_observation_exec_service"),
    )
    op.create_index("ix_service_obs_exec_id", "service_observations", ["execution_id"], unique=False)
    op.create_index("ix_service_obs_observed_at", "service_observations", ["observed_at"], unique=False)
    op.create_index("ix_service_obs_service_id", "service_observations", ["service_id"], unique=False)

    # 2. Create service_risk_assessments table
    op.create_table(
        "service_risk_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("service_id", sa.String(length=36), nullable=False),
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=20), nullable=False),
        sa.Column("reasons_json", sa.Text(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_id"], ["scan_executions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["discovered_services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("execution_id", "service_id", name="uq_service_risk_assessment_exec_service"),
    )
    op.create_index("ix_service_risk_exec_id", "service_risk_assessments", ["execution_id"], unique=False)
    op.create_index("ix_service_risk_level", "service_risk_assessments", ["level"], unique=False)
    op.create_index("ix_service_risk_service_id", "service_risk_assessments", ["service_id"], unique=False)

    # 3. Add columns to discovered_services
    op.add_column("discovered_services", sa.Column("normalized_service_name", sa.String(length=120), nullable=True))
    op.add_column("discovered_services", sa.Column("normalized_product", sa.String(length=255), nullable=True))
    op.add_column("discovered_services", sa.Column("normalized_version", sa.String(length=120), nullable=True))
    op.add_column("discovered_services", sa.Column("cpe", sa.String(length=255), nullable=True))
    op.add_column("discovered_services", sa.Column("category", sa.String(length=60), nullable=True))
    op.add_column("discovered_services", sa.Column("risk_score", sa.Integer(), nullable=True))
    op.add_column("discovered_services", sa.Column("risk_level", sa.String(length=20), nullable=True))
    op.add_column("discovered_services", sa.Column("last_observation_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "fk_discovered_services_last_observation_id",
        "discovered_services",
        "service_observations",
        ["last_observation_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_discovered_services_last_observation_id", "discovered_services", type_="foreignkey")
    op.drop_column("discovered_services", "last_observation_id")
    op.drop_column("discovered_services", "risk_level")
    op.drop_column("discovered_services", "risk_score")
    op.drop_column("discovered_services", "category")
    op.drop_column("discovered_services", "cpe")
    op.drop_column("discovered_services", "normalized_version")
    op.drop_column("discovered_services", "normalized_product")
    op.drop_column("discovered_services", "normalized_service_name")
    op.drop_table("service_risk_assessments")
    op.drop_table("service_observations")
