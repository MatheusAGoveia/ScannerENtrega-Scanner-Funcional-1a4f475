"""Initial schema

Revision ID: 001_initial_schema
Revises:
Create Date: 2026-08-04 16:42:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy import inspect

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. authorized_ranges
    if "authorized_ranges" not in existing_tables:
        op.create_table(
            "authorized_ranges",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("cidr", sa.String(length=64), nullable=False, unique=True),
            sa.Column("address_count", sa.Integer(), nullable=False),
            sa.Column("environment", sa.String(length=60), nullable=False),
            sa.Column("owner", sa.String(length=120), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("authorization_reference", sa.String(length=255), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("allow_public", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    # 2. scanner_profiles
    if "scanner_profiles" not in existing_tables:
        op.create_table(
            "scanner_profiles",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("slug", sa.String(length=40), nullable=False, unique=True),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("discovery_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("service_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("vulnerability_detection_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("tcp_ports", sa.Text(), nullable=False),
            sa.Column("udp_ports", sa.Text(), nullable=False, server_default=""),
            sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="10"),
            sa.Column("max_parallelism", sa.Integer(), nullable=False, server_default="10"),
            sa.Column("rate_limit_per_second", sa.Integer(), nullable=False, server_default="25"),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )

    # 3. scan_schedules
    if "scan_schedules" not in existing_tables:
        op.create_table(
            "scan_schedules",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("name", sa.String(length=120), nullable=False),
            sa.Column("range_id", sa.String(length=36), sa.ForeignKey("authorized_ranges.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("profile_id", sa.String(length=36), sa.ForeignKey("scanner_profiles.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("cron_expression", sa.String(length=80), nullable=False),
            sa.Column("timezone_name", sa.String(length=80), nullable=False, server_default="America/Sao_Paulo"),
            sa.Column("max_duration_minutes", sa.Integer(), nullable=False, server_default="120"),
            sa.Column("intensity", sa.String(length=20), nullable=False, server_default="low"),
            sa.Column("sync_zabbix", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("justification", sa.Text(), nullable=False),
            sa.Column("created_by", sa.String(length=120), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"])

    # 4. scan_executions
    if "scan_executions" not in existing_tables:
        op.create_table(
            "scan_executions",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("schedule_id", sa.String(length=36), sa.ForeignKey("scan_schedules.id", ondelete="SET NULL"), nullable=True),
            sa.Column("range_id", sa.String(length=36), sa.ForeignKey("authorized_ranges.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("profile_id", sa.String(length=36), sa.ForeignKey("scanner_profiles.id", ondelete="RESTRICT"), nullable=False),
            sa.Column("trigger_type", sa.String(length=20), nullable=False, server_default="manual"),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="queued"),
            sa.Column("requested_by", sa.String(length=120), nullable=False),
            sa.Column("justification", sa.Text(), nullable=False),
            sa.Column("cancellation_requested", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("active_ips", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("services_discovered", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("vulnerabilities_discovered", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("critical_vulnerabilities", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_summary", sa.Text(), nullable=True),
        )
        op.create_index("ix_scan_execution_queue", "scan_executions", ["status", "queued_at"])
        op.create_index("ix_scan_executions_heartbeat_at", "scan_executions", ["heartbeat_at"])

    # 5. engine_runs
    if "engine_runs" not in existing_tables:
        op.create_table(
            "engine_runs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("execution_id", sa.String(length=36), sa.ForeignKey("scan_executions.id", ondelete="CASCADE"), nullable=False),
            sa.Column("engine", sa.String(length=40), nullable=False),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="pending"),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.UniqueConstraint("execution_id", "engine", name="uq_execution_engine"),
        )

    # 6. discovered_assets
    if "discovered_assets" not in existing_tables:
        op.create_table(
            "discovered_assets",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("range_id", sa.String(length=36), sa.ForeignKey("authorized_ranges.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ip_address", sa.String(length=64), nullable=False),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("state", sa.String(length=20), nullable=False, server_default="active"),
            sa.Column("os_name", sa.String(length=255), nullable=True),
            sa.Column("municipal_service", sa.String(length=255), nullable=True),
            sa.Column("zabbix_status", sa.String(length=30), nullable=False, server_default="not_configured"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_execution_id", sa.String(length=36), sa.ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True),
            sa.UniqueConstraint("range_id", "ip_address", name="uq_range_ip"),
        )
        op.create_index("ix_discovered_assets_ip_address", "discovered_assets", ["ip_address"])

    # 7. discovered_services
    if "discovered_services" not in existing_tables:
        op.create_table(
            "discovered_services",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("protocol", sa.String(length=10), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False),
            sa.Column("state", sa.String(length=20), nullable=False, server_default="open"),
            sa.Column("service_name", sa.String(length=120), nullable=True),
            sa.Column("product", sa.String(length=255), nullable=True),
            sa.Column("version", sa.String(length=120), nullable=True),
            sa.Column("banner", sa.Text(), nullable=True),
            sa.Column("tls_details", sa.Text(), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_execution_id", sa.String(length=36), sa.ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True),
            sa.UniqueConstraint("asset_id", "protocol", "port", name="uq_asset_protocol_port"),
        )

    # 8. vulnerability_findings
    if "vulnerability_findings" not in existing_tables:
        op.create_table(
            "vulnerability_findings",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("fingerprint", sa.String(length=64), nullable=False),
            sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False),
            sa.Column("service_id", sa.String(length=36), sa.ForeignKey("discovered_services.id", ondelete="SET NULL"), nullable=True),
            sa.Column("engine", sa.String(length=40), nullable=False),
            sa.Column("template_id", sa.String(length=255), nullable=False),
            sa.Column("name", sa.String(length=500), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False),
            sa.Column("matched_at", sa.String(length=1000), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("reference", sa.Text(), nullable=True),
            sa.Column("status", sa.String(length=30), nullable=False, server_default="open"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_execution_id", sa.String(length=36), sa.ForeignKey("scan_executions.id", ondelete="SET NULL"), nullable=True),
            sa.UniqueConstraint("fingerprint", name="uq_finding_fingerprint"),
        )

    # 9. import_batches
    if "import_batches" not in existing_tables:
        op.create_table(
            "import_batches",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("filename", sa.String(length=255), nullable=False),
            sa.Column("environment", sa.String(length=60), nullable=False),
            sa.Column("owner", sa.String(length=120), nullable=False),
            sa.Column("authorization_reference", sa.String(length=255), nullable=False),
            sa.Column("payload_json", sa.Text(), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="previewed"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )

    # 10. audit_logs
    if "audit_logs" not in existing_tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("action", sa.String(length=100), nullable=False),
            sa.Column("resource_type", sa.String(length=60), nullable=False),
            sa.Column("resource_id", sa.String(length=64), nullable=True),
            sa.Column("actor", sa.String(length=120), nullable=False),
            sa.Column("details_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
        op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("import_batches")
    op.drop_table("vulnerability_findings")
    op.drop_table("discovered_services")
    op.drop_table("discovered_assets")
    op.drop_table("engine_runs")
    op.drop_table("scan_executions")
    op.drop_table("scan_schedules")
    op.drop_table("scanner_profiles")
    op.drop_table("authorized_ranges")
