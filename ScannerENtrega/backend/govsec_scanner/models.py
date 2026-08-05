from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from govsec_scanner.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid4())


class AuthorizedRange(Base):
    __tablename__ = "authorized_ranges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    address_count: Mapped[int] = mapped_column(Integer, nullable=False)
    environment: Mapped[str] = mapped_column(String(60), nullable=False)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    authorization_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allow_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    schedules: Mapped[list[ScanSchedule]] = relationship(back_populates="authorized_range")


class ScannerProfile(Base):
    __tablename__ = "scanner_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    slug: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    discovery_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    service_detection_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    vulnerability_detection_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_ports: Mapped[str] = mapped_column(Text, nullable=False)
    udp_ports: Mapped[str] = mapped_column(Text, nullable=False, default="")
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    rate_limit_per_second: Mapped[int] = mapped_column(Integer, nullable=False, default=25)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    schedules: Mapped[list[ScanSchedule]] = relationship(back_populates="profile")


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    range_id: Mapped[str] = mapped_column(
        ForeignKey("authorized_ranges.id", ondelete="RESTRICT"), nullable=False
    )
    profile_id: Mapped[str] = mapped_column(
        ForeignKey("scanner_profiles.id", ondelete="RESTRICT"), nullable=False
    )
    cron_expression: Mapped[str] = mapped_column(String(80), nullable=False)
    timezone_name: Mapped[str] = mapped_column(
        String(80), nullable=False, default="America/Sao_Paulo"
    )
    max_duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=120)
    intensity: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    sync_zabbix: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    authorized_range: Mapped[AuthorizedRange] = relationship(back_populates="schedules")
    profile: Mapped[ScannerProfile] = relationship(back_populates="schedules")


class ScanExecution(Base):
    __tablename__ = "scan_executions"
    __table_args__ = (
        Index("ix_scan_execution_queue", "status", "queued_at"),
        Index("ix_scan_executions_scheduled_run_at", "schedule_id", "scheduled_run_at", unique=True),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    schedule_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_schedules.id", ondelete="SET NULL")
    )
    scheduled_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    range_id: Mapped[str] = mapped_column(
        ForeignKey("authorized_ranges.id", ondelete="RESTRICT"), nullable=False
    )
    profile_id: Mapped[str] = mapped_column(
        ForeignKey("scanner_profiles.id", ondelete="RESTRICT"), nullable=False
    )
    trigger_type: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="queued")
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    cancellation_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    active_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    vulnerabilities_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    critical_vulnerabilities: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)

    authorized_range: Mapped[AuthorizedRange] = relationship()
    profile: Mapped[ScannerProfile] = relationship()
    engine_runs: Mapped[list[EngineRun]] = relationship(
        back_populates="execution", cascade="all, delete-orphan"
    )


class EngineRun(Base):
    __tablename__ = "engine_runs"
    __table_args__ = (UniqueConstraint("execution_id", "engine", name="uq_execution_engine"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="CASCADE"), nullable=False
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text)

    execution: Mapped[ScanExecution] = relationship(back_populates="engine_runs")


class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"
    __table_args__ = (UniqueConstraint("range_id", "ip_address", name="uq_range_ip"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    range_id: Mapped[str] = mapped_column(
        ForeignKey("authorized_ranges.id", ondelete="CASCADE"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    os_name: Mapped[str | None] = mapped_column(String(255))
    municipal_service: Mapped[str | None] = mapped_column(String(255))
    zabbix_status: Mapped[str] = mapped_column(String(30), nullable=False, default="not_configured")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="SET NULL")
    )

    services: Mapped[list[DiscoveredService]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list[VulnerabilityFinding]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class ServiceObservation(Base):
    __tablename__ = "service_observations"
    __table_args__ = (
        UniqueConstraint("execution_id", "service_id", name="uq_service_observation_exec_service"),
        Index("ix_service_obs_service_id", "service_id"),
        Index("ix_service_obs_exec_id", "execution_id"),
        Index("ix_service_obs_observed_at", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("discovered_services.id", ondelete="CASCADE"), nullable=False
    )
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="CASCADE"), nullable=False
    )
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    state: Mapped[str] = mapped_column(String(20), nullable=False)
    raw_service_name: Mapped[str | None] = mapped_column(String(120))
    normalized_service_name: Mapped[str | None] = mapped_column(String(120))
    raw_product: Mapped[str | None] = mapped_column(String(255))
    normalized_product: Mapped[str | None] = mapped_column(String(255))
    raw_version: Mapped[str | None] = mapped_column(String(120))
    normalized_version: Mapped[str | None] = mapped_column(String(120))
    cpe: Mapped[str | None] = mapped_column(String(255))
    category: Mapped[str | None] = mapped_column(String(60))
    confidence: Mapped[str | None] = mapped_column(String(20))


class ServiceRiskAssessment(Base):
    __tablename__ = "service_risk_assessments"
    __table_args__ = (
        UniqueConstraint("execution_id", "service_id", name="uq_service_risk_assessment_exec_service"),
        Index("ix_service_risk_service_id", "service_id"),
        Index("ix_service_risk_exec_id", "execution_id"),
        Index("ix_service_risk_level", "level"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(
        ForeignKey("discovered_services.id", ondelete="CASCADE"), nullable=False
    )
    execution_id: Mapped[str] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    reasons_json: Mapped[str] = mapped_column(Text, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DiscoveredService(Base):
    __tablename__ = "discovered_services"
    __table_args__ = (
        UniqueConstraint("asset_id", "protocol", "port", name="uq_asset_protocol_port"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False
    )
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    service_name: Mapped[str | None] = mapped_column(String(120))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(120))
    banner: Mapped[str | None] = mapped_column(Text)
    tls_details: Mapped[str | None] = mapped_column(Text)
    normalized_service_name: Mapped[str | None] = mapped_column(String(120))
    normalized_product: Mapped[str | None] = mapped_column(String(255))
    normalized_version: Mapped[str | None] = mapped_column(String(120))
    cpe: Mapped[str | None] = mapped_column(String(255))
    category: Mapped[str | None] = mapped_column(String(60))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    risk_level: Mapped[str | None] = mapped_column(String(20))
    last_observation_id: Mapped[str | None] = mapped_column(
        ForeignKey("service_observations.id", ondelete="SET NULL", use_alter=True, name="fk_discovered_services_last_observation_id")
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="SET NULL")
    )

    asset: Mapped[DiscoveredAsset] = relationship(back_populates="services")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_finding_fingerprint"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("discovered_assets.id", ondelete="CASCADE"), nullable=False
    )
    service_id: Mapped[str | None] = mapped_column(
        ForeignKey("discovered_services.id", ondelete="SET NULL")
    )
    engine: Mapped[str] = mapped_column(String(40), nullable=False)
    template_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    matched_at: Mapped[str] = mapped_column(String(1000), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    reference: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_execution_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_executions.id", ondelete="SET NULL")
    )

    asset: Mapped[DiscoveredAsset] = relationship(back_populates="findings")


class ImportBatch(Base):
    __tablename__ = "import_batches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(60), nullable=False)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="previewed")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(60), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )


class ServiceHeartbeat(Base):
    __tablename__ = "service_heartbeats"
    __table_args__ = (
        UniqueConstraint("service_name", "instance_id", name="uq_service_instance"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_name: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="healthy")
    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
