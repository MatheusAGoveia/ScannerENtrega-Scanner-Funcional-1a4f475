from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OrmModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RangeCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    cidr: str = Field(min_length=2, max_length=64)
    environment: str = Field(min_length=2, max_length=60)
    owner: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    authorization_reference: str = Field(min_length=5, max_length=255)
    allow_public: bool = False

    @field_validator("name", "environment", "owner", "authorization_reference")
    @classmethod
    def strip_required(cls, value: str) -> str:
        return value.strip()


class RangeOut(OrmModel):
    id: str
    name: str
    cidr: str
    address_count: int
    environment: str
    owner: str
    description: str | None
    authorization_reference: str
    enabled: bool
    allow_public: bool
    created_at: datetime
    updated_at: datetime


class RangePatch(BaseModel):
    enabled: bool


class ProfileOut(OrmModel):
    id: str
    slug: str
    name: str
    description: str
    discovery_enabled: bool
    service_detection_enabled: bool
    vulnerability_detection_enabled: bool
    tcp_ports: str
    udp_ports: str
    timeout_seconds: int
    max_parallelism: int
    rate_limit_per_second: int
    active: bool


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    range_id: str
    profile_id: str
    cron_expression: str = Field(min_length=5, max_length=80)
    timezone_name: str = "America/Sao_Paulo"
    max_duration_minutes: int = Field(default=120, ge=5, le=1440)
    intensity: Literal["low", "moderate"] = "low"
    sync_zabbix: bool = False
    justification: str = Field(min_length=10, max_length=2000)


class SchedulePatch(BaseModel):
    enabled: bool


class ScheduleOut(OrmModel):
    id: str
    name: str
    range_id: str
    profile_id: str
    cron_expression: str
    timezone_name: str
    max_duration_minutes: int
    intensity: str
    sync_zabbix: bool
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    justification: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    range_name: str | None = None
    cidr: str | None = None
    profile_name: str | None = None


class ExecutionCreate(BaseModel):
    range_id: str
    profile_id: str
    justification: str = Field(min_length=10, max_length=2000)


class EngineRunOut(OrmModel):
    engine: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    result_count: int
    error_message: str | None


class ExecutionOut(OrmModel):
    id: str
    schedule_id: str | None
    range_id: str
    profile_id: str
    trigger_type: str
    status: str
    requested_by: str
    justification: str
    cancellation_requested: bool
    queued_at: datetime
    started_at: datetime | None
    heartbeat_at: datetime | None = None
    finished_at: datetime | None
    active_ips: int
    services_discovered: int
    vulnerabilities_discovered: int
    critical_vulnerabilities: int
    error_summary: str | None
    range_name: str | None = None
    cidr: str | None = None
    profile_name: str | None = None
    engine_runs: list[EngineRunOut] = Field(default_factory=list)


class ServiceOut(OrmModel):
    id: str
    protocol: str
    port: int
    state: str
    service_name: str | None
    product: str | None
    version: str | None
    banner: str | None
    tls_details: str | None
    normalized_service_name: str | None = None
    normalized_product: str | None = None
    normalized_version: str | None = None
    cpe: str | None = None
    category: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    last_observation_id: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime
    reasons: list[str] = Field(default_factory=list)


class ServiceDetailOut(ServiceOut):
    asset_id: str
    ip_address: str | None = None


class ServiceObservationRead(OrmModel):
    id: str
    service_id: str
    execution_id: str
    observed_at: datetime
    state: str
    raw_service_name: str | None = None
    normalized_service_name: str | None = None
    raw_product: str | None = None
    normalized_product: str | None = None
    raw_version: str | None = None
    normalized_version: str | None = None
    cpe: str | None = None
    category: str | None = None
    confidence: str | None = None


class ServiceRiskAssessmentRead(OrmModel):
    id: str
    service_id: str
    execution_id: str
    score: int
    level: str
    reasons: list[str] = Field(default_factory=list)
    evaluated_at: datetime


class ServiceHistoryOut(BaseModel):
    observations: list[ServiceObservationRead] = Field(default_factory=list)
    risk_assessments: list[ServiceRiskAssessmentRead] = Field(default_factory=list)


class AssetOut(OrmModel):
    id: str
    range_id: str
    ip_address: str
    hostname: str | None
    state: str
    os_name: str | None
    municipal_service: str | None
    zabbix_status: str
    first_seen_at: datetime
    last_seen_at: datetime
    services: list[ServiceOut] = Field(default_factory=list)
    open_findings: int = 0
    highest_severity: str | None = None


class FindingOut(OrmModel):
    id: str
    asset_id: str
    service_id: str | None
    engine: str
    template_id: str
    name: str
    severity: str
    matched_at: str
    description: str | None
    reference: str | None
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    ip_address: str | None = None
    service: str | None = None


class ImportPreviewItem(BaseModel):
    original: str
    normalized: str | None
    valid: bool
    duplicate: bool = False
    overlap_with: str | None = None
    error: str | None = None


class ImportPreviewOut(BaseModel):
    batch_id: str
    filename: str
    total: int
    valid: int
    invalid: int
    duplicates: int
    overlaps: int
    expires_at: datetime
    items: list[ImportPreviewItem]


class ImportConfirm(BaseModel):
    batch_id: str


class EngineStatus(BaseModel):
    name: str
    available: bool
    version: str | None = None
    detail: str


class CoverageItem(BaseModel):
    id: str
    name: str
    cidr: str
    coverage_percent: int
    active_assets: int
    services: int
    critical_findings: int


class SummaryOut(BaseModel):
    authorized_ips: int
    ranges_count: int
    active_ips: int
    new_assets_30d: int
    services: int
    unlinked_assets: int
    open_findings: int
    critical_findings: int
    coverage: list[CoverageItem]
    next_runs: list[ScheduleOut]
    zabbix_configured: bool
    zabbix_pending: int
