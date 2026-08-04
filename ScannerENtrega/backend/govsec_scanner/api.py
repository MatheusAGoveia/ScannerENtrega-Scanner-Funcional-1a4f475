from __future__ import annotations

import json
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, timedelta

from croniter import CroniterBadCronError, croniter
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Response,
    UploadFile,
    status,
)
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from govsec_scanner.config import get_settings
from govsec_scanner.database import get_db, init_database
from govsec_scanner.importers import ImportValidationError, parse_import_file
from govsec_scanner.models import (
    AuditLog,
    AuthorizedRange,
    DiscoveredAsset,
    DiscoveredService,
    ImportBatch,
    ScanExecution,
    ScannerProfile,
    ScanSchedule,
    VulnerabilityFinding,
    utcnow,
)
from govsec_scanner.schemas import (
    AssetOut,
    CoverageItem,
    EngineRunOut,
    EngineStatus,
    ExecutionCreate,
    ExecutionOut,
    FindingOut,
    ImportConfirm,
    ImportPreviewItem,
    ImportPreviewOut,
    ProfileOut,
    RangeCreate,
    RangeOut,
    RangePatch,
    ScheduleCreate,
    ScheduleOut,
    SchedulePatch,
    ServiceOut,
    SummaryOut,
)
from govsec_scanner.scope import ScopeViolation, overlaps, validate_scope
from govsec_scanner.security import actor_from_header, require_api_key
from govsec_scanner.services import audit, engine_version, next_cron_run, seed_profiles


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    init_database()
    from govsec_scanner.database import SessionLocal

    with SessionLocal() as db:
        seed_profiles(db)
    yield


app = FastAPI(
    title="GovSec Scanner API",
    version="1.0.0",
    description="Varredura defensiva limitada a faixas formalmente autorizadas.",
    lifespan=lifespan,
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
router = APIRouter(prefix="/api/v1/scanner", dependencies=[Depends(require_api_key)])
settings = get_settings()
TARGET_CANDIDATE = re.compile(r"^[0-9A-Fa-f:.]+(?:/[0-9]{1,3})?$")


@app.exception_handler(ScopeViolation)
async def scope_error(_: object, exc: ScopeViolation) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok", "service": "govsec-scanner"}


@app.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict[str, object]:
    db.execute(select(1)).scalar_one()
    nmap_ok = engine_version(settings.nmap_binary) is not None
    nuclei_ok = not settings.nuclei_enabled or (
        engine_version(settings.nuclei_binary) is not None
        and settings.nuclei_templates_dir.exists()
    )
    if settings.production and (not nmap_ok or not nuclei_ok):
        raise HTTPException(status_code=503, detail="Motores obrigatorios indisponiveis.")
    return {"status": "ready", "database": "ok", "nmap": nmap_ok, "nuclei": nuclei_ok}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _range_out(item: AuthorizedRange) -> RangeOut:
    return RangeOut.model_validate(item)


def _schedule_out(item: ScanSchedule) -> ScheduleOut:
    return ScheduleOut(
        **{column.name: getattr(item, column.name) for column in ScanSchedule.__table__.columns},
        range_name=item.authorized_range.name if item.authorized_range else None,
        cidr=item.authorized_range.cidr if item.authorized_range else None,
        profile_name=item.profile.name if item.profile else None,
    )


def _execution_out(item: ScanExecution) -> ExecutionOut:
    return ExecutionOut(
        **{column.name: getattr(item, column.name) for column in ScanExecution.__table__.columns},
        range_name=item.authorized_range.name if item.authorized_range else None,
        cidr=item.authorized_range.cidr if item.authorized_range else None,
        profile_name=item.profile.name if item.profile else None,
        engine_runs=[EngineRunOut.model_validate(run) for run in item.engine_runs],
    )


@router.get("/ranges", response_model=list[RangeOut])
def list_ranges(db: Session = Depends(get_db)) -> list[RangeOut]:
    return [
        _range_out(item)
        for item in db.scalars(select(AuthorizedRange).order_by(AuthorizedRange.name)).all()
    ]


@router.post("/ranges", response_model=RangeOut, status_code=status.HTTP_201_CREATED)
def create_range(
    payload: RangeCreate,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> RangeOut:
    scope = validate_scope(
        payload.cidr,
        max_addresses=settings.max_addresses_per_range,
        allow_public=payload.allow_public,
        global_public_enabled=settings.allow_public_targets,
    )
    for current in db.scalars(select(AuthorizedRange)).all():
        if overlaps(scope.normalized, current.cidr):
            raise HTTPException(
                status_code=409,
                detail=f"A faixa sobrepoe o cadastro '{current.name}' ({current.cidr}).",
            )
    item = AuthorizedRange(
        name=payload.name,
        cidr=scope.normalized,
        address_count=scope.address_count,
        environment=payload.environment,
        owner=payload.owner,
        description=payload.description,
        authorization_reference=payload.authorization_reference,
        allow_public=payload.allow_public,
    )
    db.add(item)
    db.flush()
    audit(
        db,
        "scanner.range.created",
        "authorized_range",
        actor,
        resource_id=item.id,
        details={"cidr": item.cidr, "authorization_reference": item.authorization_reference},
    )
    db.commit()
    db.refresh(item)
    return _range_out(item)


@router.patch("/ranges/{range_id}", response_model=RangeOut)
def patch_range(
    range_id: str,
    payload: RangePatch,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> RangeOut:
    item = db.get(AuthorizedRange, range_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Faixa nao encontrada.")
    item.enabled = payload.enabled
    audit(
        db,
        "scanner.range.status_changed",
        "authorized_range",
        actor,
        resource_id=item.id,
        details={"enabled": item.enabled},
    )
    db.commit()
    db.refresh(item)
    return _range_out(item)


@router.post("/ranges/import/preview", response_model=ImportPreviewOut)
async def preview_import(
    file: UploadFile = File(...),
    environment: str = Form(...),
    owner: str = Form(...),
    authorization_reference: str = Form(...),
    db: Session = Depends(get_db),
) -> ImportPreviewOut:
    if len(authorization_reference.strip()) < 5:
        raise HTTPException(status_code=422, detail="Informe a referencia formal da autorizacao.")
    content = await file.read(settings.max_import_bytes + 1)
    try:
        raw_values = parse_import_file(
            file.filename or "lista.txt", content, max_bytes=settings.max_import_bytes
        )
    except ImportValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    candidates = [value for value in raw_values if TARGET_CANDIDATE.fullmatch(value)]
    if len(candidates) > settings.max_import_records:
        raise HTTPException(
            status_code=422, detail="A lista excede o limite de registros configurado."
        )
    if not candidates:
        raise HTTPException(
            status_code=422, detail="Nenhum IP ou CIDR foi identificado no arquivo."
        )

    existing = db.scalars(select(AuthorizedRange)).all()
    seen: list[str] = []
    preview_items: list[ImportPreviewItem] = []
    for original in candidates:
        try:
            scope = validate_scope(
                original,
                max_addresses=settings.max_addresses_per_range,
                allow_public=False,
                global_public_enabled=settings.allow_public_targets,
            )
            duplicate = scope.normalized in seen or any(
                row.cidr == scope.normalized for row in existing
            )
            overlap_with = next(
                (
                    row.cidr
                    for row in existing
                    if row.cidr != scope.normalized and overlaps(scope.normalized, row.cidr)
                ),
                None,
            ) or next(
                (
                    value
                    for value in seen
                    if value != scope.normalized and overlaps(scope.normalized, value)
                ),
                None,
            )
            valid = not duplicate and overlap_with is None
            preview_items.append(
                ImportPreviewItem(
                    original=original,
                    normalized=scope.normalized,
                    valid=valid,
                    duplicate=duplicate,
                    overlap_with=overlap_with,
                    error="Faixa duplicada."
                    if duplicate
                    else "Faixa sobreposta."
                    if overlap_with
                    else None,
                )
            )
            seen.append(scope.normalized)
        except ScopeViolation as exc:
            preview_items.append(
                ImportPreviewItem(original=original, normalized=None, valid=False, error=str(exc))
            )

    expires_at = utcnow() + timedelta(minutes=30)
    batch = ImportBatch(
        filename=file.filename or "lista",
        environment=environment.strip()[:60],
        owner=owner.strip()[:120],
        authorization_reference=authorization_reference.strip()[:255],
        payload_json=json.dumps([item.model_dump() for item in preview_items], ensure_ascii=False),
        expires_at=expires_at,
    )
    db.add(batch)
    db.commit()
    return ImportPreviewOut(
        batch_id=batch.id,
        filename=batch.filename,
        total=len(preview_items),
        valid=sum(item.valid for item in preview_items),
        invalid=sum(not item.valid and not item.duplicate for item in preview_items),
        duplicates=sum(item.duplicate for item in preview_items),
        overlaps=sum(item.overlap_with is not None for item in preview_items),
        expires_at=expires_at,
        items=preview_items,
    )


@router.post("/ranges/import/confirm", response_model=list[RangeOut])
def confirm_import(
    payload: ImportConfirm,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> list[RangeOut]:
    batch = db.get(ImportBatch, payload.batch_id)
    if batch is None:
        raise HTTPException(status_code=404, detail="Previa de importacao nao encontrada.")
    expires_at = (
        batch.expires_at if batch.expires_at.tzinfo else batch.expires_at.replace(tzinfo=UTC)
    )
    if batch.status != "previewed" or expires_at < utcnow():
        raise HTTPException(status_code=409, detail="A previa expirou ou ja foi confirmada.")
    created: list[AuthorizedRange] = []
    for raw_item in json.loads(batch.payload_json):
        item = ImportPreviewItem.model_validate(raw_item)
        if not item.valid or not item.normalized:
            continue
        scope = validate_scope(
            item.normalized,
            max_addresses=settings.max_addresses_per_range,
            allow_public=False,
            global_public_enabled=settings.allow_public_targets,
        )
        row = AuthorizedRange(
            name=f"{batch.filename[:60]} - {scope.normalized}",
            cidr=scope.normalized,
            address_count=scope.address_count,
            environment=batch.environment,
            owner=batch.owner,
            authorization_reference=batch.authorization_reference,
        )
        db.add(row)
        created.append(row)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Uma faixa foi cadastrada depois da previa; gere uma nova previa.",
        ) from exc
    batch.status = "confirmed"
    audit(
        db,
        "scanner.range.imported",
        "import_batch",
        actor,
        resource_id=batch.id,
        details={"created": len(created), "filename": batch.filename},
    )
    db.commit()
    return [_range_out(item) for item in created]


@router.get("/profiles", response_model=list[ProfileOut])
def list_profiles(db: Session = Depends(get_db)) -> list[ProfileOut]:
    return [
        ProfileOut.model_validate(item)
        for item in db.scalars(select(ScannerProfile).where(ScannerProfile.active.is_(True))).all()
    ]


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(db: Session = Depends(get_db)) -> list[ScheduleOut]:
    items = db.scalars(
        select(ScanSchedule)
        .options(selectinload(ScanSchedule.authorized_range), selectinload(ScanSchedule.profile))
        .order_by(ScanSchedule.created_at.desc())
    ).all()
    return [_schedule_out(item) for item in items]


@router.post("/schedules", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(
    payload: ScheduleCreate,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> ScheduleOut:
    authorized_range = db.get(AuthorizedRange, payload.range_id)
    profile = db.get(ScannerProfile, payload.profile_id)
    if authorized_range is None or not authorized_range.enabled:
        raise HTTPException(status_code=422, detail="Selecione uma faixa autorizada e ativa.")
    if profile is None or not profile.active:
        raise HTTPException(status_code=422, detail="Selecione um perfil ativo.")
    try:
        croniter(payload.cron_expression, utcnow())
        next_run = next_cron_run(payload.cron_expression, payload.timezone_name)
    except (ValueError, CroniterBadCronError) as exc:
        raise HTTPException(
            status_code=422, detail="Expressao cron ou fuso horario invalido."
        ) from exc
    item = ScanSchedule(
        name=payload.name.strip(),
        range_id=payload.range_id,
        profile_id=payload.profile_id,
        cron_expression=payload.cron_expression.strip(),
        timezone_name=payload.timezone_name,
        max_duration_minutes=payload.max_duration_minutes,
        intensity=payload.intensity,
        sync_zabbix=payload.sync_zabbix,
        next_run_at=next_run,
        justification=payload.justification.strip(),
        created_by=actor,
    )
    db.add(item)
    db.flush()
    audit(
        db,
        "scanner.schedule.created",
        "scan_schedule",
        actor,
        resource_id=item.id,
        details={"range_id": item.range_id, "profile_id": item.profile_id},
    )
    db.commit()
    db.refresh(item)
    item.authorized_range = authorized_range
    item.profile = profile
    return _schedule_out(item)


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def patch_schedule(
    schedule_id: str,
    payload: SchedulePatch,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> ScheduleOut:
    item = db.scalar(
        select(ScanSchedule)
        .options(selectinload(ScanSchedule.authorized_range), selectinload(ScanSchedule.profile))
        .where(ScanSchedule.id == schedule_id)
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Agendamento nao encontrado.")
    item.enabled = payload.enabled
    item.next_run_at = (
        next_cron_run(item.cron_expression, item.timezone_name) if item.enabled else None
    )
    audit(
        db,
        "scanner.schedule.status_changed",
        "scan_schedule",
        actor,
        resource_id=item.id,
        details={"enabled": item.enabled},
    )
    db.commit()
    return _schedule_out(item)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: str,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> Response:
    item = db.get(ScanSchedule, schedule_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Agendamento nao encontrado.")
    audit(db, "scanner.schedule.deleted", "scan_schedule", actor, resource_id=item.id)
    db.delete(item)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/executions", response_model=list[ExecutionOut])
def list_executions(limit: int = 100, db: Session = Depends(get_db)) -> list[ExecutionOut]:
    items = db.scalars(
        select(ScanExecution)
        .options(
            selectinload(ScanExecution.authorized_range),
            selectinload(ScanExecution.profile),
            selectinload(ScanExecution.engine_runs),
        )
        .order_by(ScanExecution.queued_at.desc())
        .limit(min(max(limit, 1), 500))
    ).all()
    return [_execution_out(item) for item in items]


@router.get("/executions/{execution_id}", response_model=ExecutionOut)
def get_execution(execution_id: str, db: Session = Depends(get_db)) -> ExecutionOut:
    item = db.scalar(
        select(ScanExecution)
        .options(
            selectinload(ScanExecution.authorized_range),
            selectinload(ScanExecution.profile),
            selectinload(ScanExecution.engine_runs),
        )
        .where(ScanExecution.id == execution_id)
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Execucao nao encontrada.")
    return _execution_out(item)


@router.post("/executions", response_model=ExecutionOut, status_code=status.HTTP_202_ACCEPTED)
def create_execution(
    payload: ExecutionCreate,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> ExecutionOut:
    authorized_range = db.get(AuthorizedRange, payload.range_id)
    profile = db.get(ScannerProfile, payload.profile_id)
    if authorized_range is None or not authorized_range.enabled:
        raise HTTPException(status_code=422, detail="Faixa autorizada indisponivel.")
    if profile is None or not profile.active:
        raise HTTPException(status_code=422, detail="Perfil de scanner indisponivel.")
    item = ScanExecution(
        range_id=payload.range_id,
        profile_id=payload.profile_id,
        requested_by=actor,
        justification=payload.justification.strip(),
    )
    db.add(item)
    db.flush()
    audit(
        db,
        "scanner.execution.queued",
        "scan_execution",
        actor,
        resource_id=item.id,
        details={"range_id": item.range_id, "profile_id": item.profile_id},
    )
    db.commit()
    db.refresh(item)
    item.authorized_range = authorized_range
    item.profile = profile
    return _execution_out(item)


@router.post("/executions/{execution_id}/cancel", response_model=ExecutionOut)
def cancel_execution(
    execution_id: str,
    actor: str = Depends(actor_from_header),
    db: Session = Depends(get_db),
) -> ExecutionOut:
    item = db.scalar(
        select(ScanExecution)
        .options(
            selectinload(ScanExecution.authorized_range),
            selectinload(ScanExecution.profile),
            selectinload(ScanExecution.engine_runs),
        )
        .where(ScanExecution.id == execution_id)
    )
    if item is None:
        raise HTTPException(status_code=404, detail="Execucao nao encontrada.")
    if item.status not in {"queued", "running"}:
        raise HTTPException(status_code=409, detail="A execucao ja foi finalizada.")
    item.cancellation_requested = True
    if item.status == "queued":
        item.status = "cancelled"
        item.finished_at = utcnow()
    audit(db, "scanner.execution.cancel_requested", "scan_execution", actor, resource_id=item.id)
    db.commit()
    return _execution_out(item)


@router.get("/assets", response_model=list[AssetOut])
def list_assets(range_id: str | None = None, db: Session = Depends(get_db)) -> list[AssetOut]:
    statement = (
        select(DiscoveredAsset)
        .options(selectinload(DiscoveredAsset.services), selectinload(DiscoveredAsset.findings))
        .order_by(DiscoveredAsset.ip_address)
    )
    if range_id:
        statement = statement.where(DiscoveredAsset.range_id == range_id)
    items = db.scalars(statement).all()
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    output: list[AssetOut] = []
    for item in items:
        open_findings = [finding for finding in item.findings if finding.status == "open"]
        highest = max(
            (finding.severity for finding in open_findings),
            key=lambda value: severity_order.get(value, -1),
            default=None,
        )
        output.append(
            AssetOut(
                **{
                    column.name: getattr(item, column.name)
                    for column in DiscoveredAsset.__table__.columns
                },
                services=[
                    ServiceOut.model_validate(service)
                    for service in item.services
                    if service.state == "open"
                ],
                open_findings=len(open_findings),
                highest_severity=highest,
            )
        )
    return output


@router.get("/findings", response_model=list[FindingOut])
def list_findings(db: Session = Depends(get_db)) -> list[FindingOut]:
    items = db.scalars(
        select(VulnerabilityFinding)
        .options(selectinload(VulnerabilityFinding.asset))
        .order_by(VulnerabilityFinding.last_seen_at.desc())
        .limit(1000)
    ).all()
    output: list[FindingOut] = []
    for item in items:
        service = db.get(DiscoveredService, item.service_id) if item.service_id else None
        output.append(
            FindingOut(
                **{
                    column.name: getattr(item, column.name)
                    for column in VulnerabilityFinding.__table__.columns
                },
                ip_address=item.asset.ip_address if item.asset else None,
                service=f"{service.service_name or 'servico'}:{service.port}" if service else None,
            )
        )
    return output


@router.get("/engines", response_model=list[EngineStatus])
def engines(db: Session = Depends(get_db)) -> list[EngineStatus]:
    db.execute(select(1)).scalar_one()
    nmap_version = engine_version(settings.nmap_binary)
    nuclei_version = engine_version(settings.nuclei_binary)
    nuclei_ready = bool(nuclei_version and settings.nuclei_templates_dir.exists())
    return [
        EngineStatus(
            name="nmap",
            available=nmap_version is not None,
            version=nmap_version,
            detail="Descoberta TCP/UDP e identificacao de servicos.",
        ),
        EngineStatus(
            name="banner_tls",
            available=True,
            version="python-asyncio",
            detail="Coleta limitada de banners e metadados TLS.",
        ),
        EngineStatus(
            name="nuclei",
            available=nuclei_ready,
            version=nuclei_version,
            detail="Templates nao invasivos; OAST, fuzzing e DoS desativados.",
        ),
        EngineStatus(
            name="zabbix",
            available=bool(settings.zabbix_url and settings.zabbix_token),
            detail="Reconciliacao de hosts existentes, sem criacao automatica.",
        ),
    ]


@router.get("/summary", response_model=SummaryOut)
def summary(db: Session = Depends(get_db)) -> SummaryOut:
    ranges = db.scalars(select(AuthorizedRange).where(AuthorizedRange.enabled.is_(True))).all()
    active_ips = (
        db.scalar(
            select(func.count())
            .select_from(DiscoveredAsset)
            .where(DiscoveredAsset.state == "active")
        )
        or 0
    )
    services = (
        db.scalar(
            select(func.count())
            .select_from(DiscoveredService)
            .where(DiscoveredService.state == "open")
        )
        or 0
    )
    open_findings = (
        db.scalar(
            select(func.count())
            .select_from(VulnerabilityFinding)
            .where(VulnerabilityFinding.status == "open")
        )
        or 0
    )
    critical = (
        db.scalar(
            select(func.count())
            .select_from(VulnerabilityFinding)
            .where(
                VulnerabilityFinding.status == "open", VulnerabilityFinding.severity == "critical"
            )
        )
        or 0
    )
    new_assets = (
        db.scalar(
            select(func.count())
            .select_from(DiscoveredAsset)
            .where(DiscoveredAsset.first_seen_at >= utcnow() - timedelta(days=30))
        )
        or 0
    )
    unlinked = (
        db.scalar(
            select(func.count())
            .select_from(DiscoveredAsset)
            .where(DiscoveredAsset.state == "active", DiscoveredAsset.municipal_service.is_(None))
        )
        or 0
    )
    coverage: list[CoverageItem] = []
    for authorized_range in ranges:
        range_active = (
            db.scalar(
                select(func.count())
                .select_from(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == authorized_range.id,
                    DiscoveredAsset.state == "active",
                )
            )
            or 0
        )
        range_services = (
            db.scalar(
                select(func.count())
                .select_from(DiscoveredService)
                .join(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == authorized_range.id,
                    DiscoveredService.state == "open",
                )
            )
            or 0
        )
        range_critical = (
            db.scalar(
                select(func.count())
                .select_from(VulnerabilityFinding)
                .join(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == authorized_range.id,
                    VulnerabilityFinding.status == "open",
                    VulnerabilityFinding.severity == "critical",
                )
            )
            or 0
        )
        coverage.append(
            CoverageItem(
                id=authorized_range.id,
                name=authorized_range.name,
                cidr=authorized_range.cidr,
                coverage_percent=min(
                    100, round((range_active / authorized_range.address_count) * 100)
                )
                if authorized_range.address_count
                else 0,
                active_assets=range_active,
                services=range_services,
                critical_findings=range_critical,
            )
        )
    next_items = db.scalars(
        select(ScanSchedule)
        .options(selectinload(ScanSchedule.authorized_range), selectinload(ScanSchedule.profile))
        .where(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at.is_not(None))
        .order_by(ScanSchedule.next_run_at)
        .limit(5)
    ).all()
    zabbix_pending = (
        db.scalar(
            select(func.count())
            .select_from(DiscoveredAsset)
            .where(DiscoveredAsset.zabbix_status == "pending")
        )
        or 0
    )
    return SummaryOut(
        authorized_ips=sum(item.address_count for item in ranges),
        ranges_count=len(ranges),
        active_ips=active_ips,
        new_assets_30d=new_assets,
        services=services,
        unlinked_assets=unlinked,
        open_findings=open_findings,
        critical_findings=critical,
        coverage=coverage,
        next_runs=[_schedule_out(item) for item in next_items],
        zabbix_configured=bool(settings.zabbix_url and settings.zabbix_token),
        zabbix_pending=zabbix_pending,
    )


@router.get("/audit")
def list_audit(limit: int = 200, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    items = db.scalars(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(min(max(limit, 1), 1000))
    ).all()
    return [
        {
            "id": item.id,
            "action": item.action,
            "resource_type": item.resource_type,
            "resource_id": item.resource_id,
            "actor": item.actor,
            "details": json.loads(item.details_json),
            "created_at": item.created_at,
        }
        for item in items
    ]


app.include_router(router)
