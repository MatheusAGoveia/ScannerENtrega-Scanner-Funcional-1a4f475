"""Service heartbeats and schedule idempotency

Revision ID: 002_service_heartbeats
Revises: 001_initial_schema
Create Date: 2026-08-04 17:30:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_service_heartbeats"
down_revision: str | None = "001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_heartbeats",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("service_name", sa.String(length=60), nullable=False),
        sa.Column("instance_id", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="healthy"),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("service_name", "instance_id", name="uq_service_instance"),
    )
    op.create_index("ix_service_heartbeats_service_name", "service_heartbeats", ["service_name"])
    op.create_index(
        "ix_service_heartbeats_last_heartbeat_at", "service_heartbeats", ["last_heartbeat_at"]
    )

    op.add_column(
        "scan_executions", sa.Column("scheduled_run_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index(
        "ix_scan_executions_scheduled_run_at",
        "scan_executions",
        ["schedule_id", "scheduled_run_at"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_scan_executions_scheduled_run_at", table_name="scan_executions")
    op.drop_column("scan_executions", "scheduled_run_at")
    op.drop_index("ix_service_heartbeats_last_heartbeat_at", table_name="service_heartbeats")
    op.drop_index("ix_service_heartbeats_service_name", table_name="service_heartbeats")
    op.drop_table("service_heartbeats")
