from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import shutil
import subprocess
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Any

from croniter import croniter
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from govsec_scanner.config import Settings, get_settings
from govsec_scanner.engines import BannerEngine, NmapEngine, NucleiEngine
from govsec_scanner.engines.base import (
    EngineExecutionError,
    EngineUnavailable,
    FindingObservation,
    HostObservation,
)
from govsec_scanner.models import (
    AuditLog,
    DiscoveredAsset,
    DiscoveredService,
    EngineRun,
    ScanExecution,
    ScannerProfile,
    ServiceHeartbeat,
    VulnerabilityFinding,
    utcnow,
)
from govsec_scanner.scope import validate_scope
from govsec_scanner.zabbix import ZabbixClient, ZabbixError

logger = logging.getLogger(__name__)


DEFAULT_TCP_PORTS = "22,25,53,80,110,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3306,3389,5432,6379,8080,8443,9000,9200"
DEFAULT_UDP_PORTS = "53,69,123,137,138,161,162,500,514,1900,4500"


def audit(
    db: Session,
    action: str,
    resource_type: str,
    actor: str,
    *,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor=actor,
            details_json=json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")),
        )
    )


def seed_profiles(db: Session) -> None:
    profiles = [
        {
            "slug": "availability",
            "name": "Disponibilidade",
            "description": "Confirma resposta em portas essenciais com intensidade baixa.",
            "discovery_enabled": True,
            "service_detection_enabled": False,
            "vulnerability_detection_enabled": False,
            "tcp_ports": "22,53,80,443,445,3389",
            "udp_ports": "53,123,161",
            "timeout_seconds": 5,
            "max_parallelism": 6,
            "rate_limit_per_second": 20,
        },
        {
            "slug": "discovery",
            "name": "Descoberta de ativos e servicos",
            "description": "Mapeia TCP/UDP e identifica servicos e banners sem scripts invasivos.",
            "discovery_enabled": True,
            "service_detection_enabled": True,
            "vulnerability_detection_enabled": False,
            "tcp_ports": DEFAULT_TCP_PORTS,
            "udp_ports": DEFAULT_UDP_PORTS,
            "timeout_seconds": 8,
            "max_parallelism": 8,
            "rate_limit_per_second": 25,
        },
        {
            "slug": "vulnerability",
            "name": "Descoberta + vulnerabilidades",
            "description": "Executa descoberta e templates Nuclei nao invasivos, sem OAST, fuzzing ou DoS.",
            "discovery_enabled": True,
            "service_detection_enabled": True,
            "vulnerability_detection_enabled": True,
            "tcp_ports": DEFAULT_TCP_PORTS,
            "udp_ports": DEFAULT_UDP_PORTS,
            "timeout_seconds": 10,
            "max_parallelism": 8,
            "rate_limit_per_second": 20,
        },
    ]
    for values in profiles:
        existing = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == values["slug"]))
        if existing is None:
            db.add(ScannerProfile(**values))
    db.commit()


def next_cron_run(expression: str, timezone_name: str, base: datetime | None = None) -> datetime:
    from zoneinfo import ZoneInfo

    zone = ZoneInfo(timezone_name)
    origin = (base or utcnow()).astimezone(zone)
    return croniter(expression, origin).get_next(datetime).astimezone(UTC)


def engine_version(binary: str) -> str | None:
    path = shutil.which(binary)
    if path is None:
        return None
    try:
        result = subprocess.run(
            [path, "-version" if binary.endswith("nuclei") else "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    line = (result.stdout or result.stderr).strip().splitlines()
    return line[0][:200] if line else "instalado"


def _engine_run(db: Session, execution: ScanExecution, engine: str) -> EngineRun:
    current = db.scalar(
        select(EngineRun).where(EngineRun.execution_id == execution.id, EngineRun.engine == engine)
    )
    if current is None:
        current = EngineRun(execution_id=execution.id, engine=engine)
        db.add(current)
    now = utcnow()
    current.status = "running"
    current.started_at = now
    current.finished_at = None
    current.error_message = None
    execution.heartbeat_at = now
    db.commit()
    return current


def _finish_engine(
    db: Session,
    engine_run: EngineRun,
    *,
    status: str,
    result_count: int = 0,
    error: str | None = None,
) -> None:
    engine_run.status = status
    engine_run.result_count = result_count
    engine_run.error_message = error[:2000] if error else None
    engine_run.finished_at = utcnow()
    db.commit()


def _cancel_requested(db: Session, execution_id: str) -> bool:
    value = db.scalar(
        select(ScanExecution.cancellation_requested).where(ScanExecution.id == execution_id)
    )
    return bool(value)


def _persist_hosts(
    db: Session,
    execution: ScanExecution,
    hosts: list[HostObservation],
) -> tuple[int, int]:
    now = utcnow()
    seen_ips = {host.ip_address for host in hosts}
    existing_assets = {
        asset.ip_address: asset
        for asset in db.scalars(
            select(DiscoveredAsset)
            .options(selectinload(DiscoveredAsset.services))
            .where(DiscoveredAsset.range_id == execution.range_id)
        ).all()
    }
    service_count = 0
    for host in hosts:
        asset = existing_assets.get(host.ip_address)
        if asset is None:
            asset = DiscoveredAsset(range_id=execution.range_id, ip_address=host.ip_address)
            db.add(asset)
            db.flush()
            existing_assets[host.ip_address] = asset
        asset.hostname = host.hostname
        asset.os_name = host.os_name
        asset.state = "active"
        asset.last_seen_at = now
        asset.last_execution_id = execution.id
        existing_services = {
            (service.protocol, service.port): service for service in asset.services
        }
        seen_services: set[tuple[str, int]] = set()
        for observed in host.services:
            key = (observed.protocol, observed.port)
            seen_services.add(key)
            service = existing_services.get(key)
            if service is None:
                service = DiscoveredService(
                    asset_id=asset.id,
                    protocol=observed.protocol,
                    port=observed.port,
                )
                db.add(service)
                existing_services[key] = service
            service.state = observed.state
            service.service_name = observed.service_name
            service.product = observed.product
            service.version = observed.version
            service.banner = observed.banner
            service.tls_details = observed.tls_details
            service.last_seen_at = now
            service.last_execution_id = execution.id
            service_count += 1
        for key, service in existing_services.items():
            if key not in seen_services and service.state == "open":
                service.state = "closed"

    for ip_address, asset in existing_assets.items():
        if ip_address not in seen_ips and asset.state == "active":
            asset.state = "inactive"
    db.commit()
    return len(hosts), service_count


def _persist_findings(
    db: Session,
    execution: ScanExecution,
    findings: list[FindingObservation],
) -> int:
    now = utcnow()
    assets = {
        asset.ip_address: asset
        for asset in db.scalars(
            select(DiscoveredAsset).where(DiscoveredAsset.range_id == execution.range_id)
        ).all()
    }
    count = 0
    for observed in findings:
        asset = assets.get(observed.ip_address)
        if asset is None:
            continue
        service = None
        if observed.port is not None:
            service = db.scalar(
                select(DiscoveredService).where(
                    DiscoveredService.asset_id == asset.id,
                    DiscoveredService.port == observed.port,
                    DiscoveredService.protocol == (observed.protocol or "tcp"),
                )
            )
        fingerprint_source = "|".join(
            [
                observed.template_id,
                observed.ip_address,
                str(observed.port or 0),
                observed.matched_at,
            ]
        )
        fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()
        finding = db.scalar(
            select(VulnerabilityFinding).where(VulnerabilityFinding.fingerprint == fingerprint)
        )
        if finding is None:
            finding = VulnerabilityFinding(
                fingerprint=fingerprint,
                asset_id=asset.id,
                service_id=service.id if service else None,
                engine="nuclei",
                template_id=observed.template_id,
                name=observed.name,
                severity=observed.severity,
                matched_at=observed.matched_at,
                description=observed.description,
                reference=observed.reference,
            )
            db.add(finding)
        finding.last_seen_at = now
        finding.last_execution_id = execution.id
        finding.status = "open"
        count += 1
    db.commit()
    return count


def _sanitize_error_message(exc: Exception) -> str:
    msg = str(exc)
    msg = re.sub(
        r"postgresql(?:\+[\w]+)?://[^:\s]+:[^@\s]+@",
        "postgresql://[redacted]:[redacted]@",
        msg,
        flags=re.IGNORECASE,
    )
    msg = re.sub(r"(?:[a-zA-Z]:\\|[/\\])[\w\-./\\]+", "[path-redacted]", msg)
    msg = re.sub(r"Traceback.*", "[traceback-redacted]", msg, flags=re.DOTALL)
    msg = re.sub(
        r"(key|secret|token|pass|password|auth|authorization)\s*[:=]\s*\S+",
        r"\1=[redacted]",
        msg,
        flags=re.IGNORECASE,
    )
    msg = re.sub(
        r"(key|secret|token|pass|password|auth|authorization)\s+\S+",
        r"\1 [redacted]",
        msg,
        flags=re.IGNORECASE,
    )
    return msg[:2000].strip() or "Falha no processamento da execucao."


async def _periodic_heartbeat(
    execution_id: str,
    interval_seconds: float,
    stop_event: asyncio.Event,
    bind_engine: Any = None,
    on_heartbeat: Any = None,
) -> None:
    from sqlalchemy.orm import Session as SQLAlchemySession

    from govsec_scanner.database import SessionLocal

    while not stop_event.is_set():
        try:
            await asyncio.sleep(interval_seconds)
            if stop_event.is_set():
                break
            if bind_engine is not None:
                with SQLAlchemySession(bind=bind_engine) as hb_db:
                    touch_execution_heartbeat(hb_db, execution_id)
            else:
                with SessionLocal() as hb_db:
                    touch_execution_heartbeat(hb_db, execution_id)

            if on_heartbeat is not None and callable(on_heartbeat):
                on_heartbeat()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning(
                "Falha ao atualizar heartbeat para execucao %s: %s",
                execution_id,
                _sanitize_error_message(exc),
            )


async def execute_scan(
    db: Session,
    execution_id: str,
    settings: Settings | None = None,
    hb_interval_override: float | None = None,
    on_heartbeat: Any = None,
) -> None:
    settings = settings or get_settings()
    hb_interval = hb_interval_override or max(0.5, settings.worker_stale_timeout_seconds / 4.0)
    stop_event = asyncio.Event()
    bind_engine = db.get_bind()
    heartbeat_task = asyncio.create_task(
        _periodic_heartbeat(
            execution_id,
            hb_interval,
            stop_event,
            bind_engine=bind_engine,
            on_heartbeat=on_heartbeat,
        )
    )

    partial_errors: list[str] = []
    hosts: list[HostObservation] = []

    try:
        execution = db.scalar(
            select(ScanExecution)
            .options(
                selectinload(ScanExecution.authorized_range),
                selectinload(ScanExecution.profile),
            )
            .where(ScanExecution.id == execution_id)
        )
        if execution is None or execution.status != "running":
            return

        if not execution.authorized_range or not execution.profile:
            raise EngineExecutionError("Faixa autorizada ou perfil nao encontrados.")

        scope = validate_scope(
            execution.authorized_range.cidr,
            max_addresses=settings.max_addresses_per_range,
            allow_public=execution.authorized_range.allow_public,
            global_public_enabled=settings.allow_public_targets,
        )
        if (
            not execution.authorized_range.enabled
            or not execution.authorized_range.authorization_reference
        ):
            raise EngineExecutionError("A faixa nao possui autorizacao ativa.")

        maximum_seconds = 7200
        if execution.schedule_id:
            from govsec_scanner.models import ScanSchedule

            schedule = db.get(ScanSchedule, execution.schedule_id)
            if schedule:
                maximum_seconds = schedule.max_duration_minutes * 60
                intensity = schedule.intensity
                sync_zabbix = schedule.sync_zabbix
            else:
                intensity = "low"
                sync_zabbix = False
        else:
            intensity = "low"
            sync_zabbix = False

        audit(
            db,
            "scan.execution.started",
            "scan_execution",
            execution.requested_by,
            resource_id=execution.id,
            details={
                "target": scope.normalized,
                "authorization_reference": execution.authorized_range.authorization_reference,
                "profile": execution.profile.slug,
                "nmap_version": engine_version(settings.nmap_binary),
                "nuclei_version": engine_version(settings.nuclei_binary)
                if execution.profile.vulnerability_detection_enabled
                else None,
            },
        )

        nmap_run = _engine_run(db, execution, "nmap")
        hosts = await NmapEngine(settings).scan(
            scope.normalized,
            execution.profile,
            intensity=intensity,
            maximum_duration_seconds=maximum_seconds,
        )
        _persist_hosts(db, execution, hosts)
        _finish_engine(db, nmap_run, status="completed", result_count=len(hosts))

        if _cancel_requested(db, execution.id):
            execution.status = "cancelled"
            execution.finished_at = utcnow()
            audit(
                db,
                "scan.execution.cancelled",
                "scan_execution",
                execution.requested_by,
                resource_id=execution.id,
                details={"status": "cancelled"},
            )
            db.commit()
            return

        if execution.profile.service_detection_enabled:
            banner_run = _engine_run(db, execution, "banner_tls")
            enriched = await BannerEngine().enrich(
                hosts,
                timeout_seconds=execution.profile.timeout_seconds,
                max_parallelism=execution.profile.max_parallelism,
            )
            _persist_hosts(db, execution, hosts)
            _finish_engine(db, banner_run, status="completed", result_count=enriched)

        if execution.profile.vulnerability_detection_enabled:
            nuclei_run = _engine_run(db, execution, "nuclei")
            try:
                findings = await NucleiEngine(settings).scan(
                    scope.normalized,
                    hosts,
                    execution.profile,
                    maximum_duration_seconds=maximum_seconds,
                )
                _persist_findings(db, execution, findings)
                _finish_engine(db, nuclei_run, status="completed", result_count=len(findings))
            except (EngineUnavailable, EngineExecutionError) as exc:
                sanitized = _sanitize_error_message(exc)
                partial_errors.append(sanitized)
                _finish_engine(db, nuclei_run, status="failed", error=sanitized)

        if sync_zabbix:
            zabbix_run = _engine_run(db, execution, "zabbix")
            try:
                client = ZabbixClient(settings)
                result = await asyncio.to_thread(client.reconcile, hosts)
                for host in hosts:
                    asset = db.scalar(
                        select(DiscoveredAsset).where(
                            DiscoveredAsset.range_id == execution.range_id,
                            DiscoveredAsset.ip_address == host.ip_address,
                        )
                    )
                    if asset:
                        asset.zabbix_status = "synchronized" if result.pending == 0 else "pending"
                db.commit()
                _finish_engine(db, zabbix_run, status="completed", result_count=result.linked)
            except ZabbixError as exc:
                sanitized = _sanitize_error_message(exc)
                partial_errors.append(sanitized)
                _finish_engine(db, zabbix_run, status="failed", error=sanitized)

        execution.active_ips = (
            db.scalar(
                select(func.count())
                .select_from(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == execution.range_id,
                    DiscoveredAsset.state == "active",
                )
            )
            or 0
        )
        execution.services_discovered = (
            db.scalar(
                select(func.count())
                .select_from(DiscoveredService)
                .join(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == execution.range_id,
                    DiscoveredService.state == "open",
                )
            )
            or 0
        )
        execution.vulnerabilities_discovered = (
            db.scalar(
                select(func.count())
                .select_from(VulnerabilityFinding)
                .join(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == execution.range_id,
                    VulnerabilityFinding.status == "open",
                )
            )
            or 0
        )
        execution.critical_vulnerabilities = (
            db.scalar(
                select(func.count())
                .select_from(VulnerabilityFinding)
                .join(DiscoveredAsset)
                .where(
                    DiscoveredAsset.range_id == execution.range_id,
                    VulnerabilityFinding.status == "open",
                    VulnerabilityFinding.severity == "critical",
                )
            )
            or 0
        )
        execution.status = "partially_completed" if partial_errors else "completed"
        execution.error_summary = "; ".join(partial_errors)[:4000] or None
        execution.finished_at = utcnow()
        audit(
            db,
            "scan.execution.finished",
            "scan_execution",
            execution.requested_by,
            resource_id=execution.id,
            details={
                "status": execution.status,
                "duration_seconds": (execution.finished_at - execution.started_at).total_seconds()
                if execution.finished_at and execution.started_at
                else 0,
                "active_ips": execution.active_ips,
                "services_discovered": execution.services_discovered,
                "vulnerabilities_discovered": execution.vulnerabilities_discovered,
                "partial_errors": partial_errors,
            },
        )
        db.commit()
    except Exception as exc:
        sanitized_msg = _sanitize_error_message(exc)
        logger.error("Falha na execucao %s: %s", execution_id, sanitized_msg)
        with suppress(Exception):
            db.rollback()

        try:
            bind_engine = db.get_bind()
            with Session(bind=bind_engine) as fail_db:
                execution_post = fail_db.scalar(select(ScanExecution).where(ScanExecution.id == execution_id))
                if execution_post is not None:
                    running_engine = fail_db.scalar(
                        select(EngineRun).where(
                            EngineRun.execution_id == execution_post.id,
                            EngineRun.status == "running",
                        )
                    )
                    if running_engine:
                        _finish_engine(fail_db, running_engine, status="failed", error=sanitized_msg)

                    if hosts:
                        execution_post.status = "partially_completed"
                    else:
                        execution_post.status = "failed"

                    execution_post.error_summary = sanitized_msg[:4000]
                    execution_post.finished_at = utcnow()
                    audit(
                        fail_db,
                        "scan.execution.failed",
                        "scan_execution",
                        execution_post.requested_by,
                        resource_id=execution_post.id,
                        details={"status": execution_post.status, "error": sanitized_msg[:2000]},
                    )
                    fail_db.commit()
        except Exception as db_exc:
            logger.warning("Nao foi possivel persistir estado de falha para execucao %s: %s", execution_id, _sanitize_error_message(db_exc))
    finally:
        stop_event.set()
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task


def claim_next_execution(db: Session) -> str | None:
    statement = (
        select(ScanExecution)
        .where(ScanExecution.status == "queued")
        .order_by(ScanExecution.queued_at)
        .limit(1)
    )
    if db.bind and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    execution = db.scalar(statement)
    if execution is None:
        return None

    now = utcnow()
    result = db.execute(
        update(ScanExecution)
        .where(ScanExecution.id == execution.id, ScanExecution.status == "queued")
        .values(status="running", started_at=now, heartbeat_at=now)
    )
    if getattr(result, "rowcount", 0) == 0:
        db.rollback()
        return None

    db.commit()
    return execution.id


def touch_execution_heartbeat(db: Session, execution_id: str) -> None:
    now = utcnow()
    db.execute(
        update(ScanExecution)
        .where(ScanExecution.id == execution_id, ScanExecution.status == "running")
        .values(heartbeat_at=now)
    )
    db.commit()


def update_service_heartbeat(
    db: Session,
    service_name: str,
    instance_id: str,
    status: str = "healthy",
    details: dict[str, Any] | None = None,
) -> None:
    now = utcnow()
    details_str = json.dumps(details or {}, ensure_ascii=False, separators=(",", ":"))
    heartbeat = db.scalar(
        select(ServiceHeartbeat).where(
            ServiceHeartbeat.service_name == service_name,
            ServiceHeartbeat.instance_id == instance_id,
        )
    )
    if heartbeat is None:
        heartbeat = ServiceHeartbeat(
            service_name=service_name,
            instance_id=instance_id,
            status=status,
            last_heartbeat_at=now,
            details_json=details_str,
        )
        db.add(heartbeat)
    else:
        heartbeat.status = status
        heartbeat.last_heartbeat_at = now
        heartbeat.details_json = details_str
    db.commit()



def recover_stale_executions(db: Session, stale_timeout_seconds: float = 300.0) -> int:
    now = utcnow()
    cutoff = now - timedelta(seconds=stale_timeout_seconds)
    statement = (
        select(ScanExecution)
        .where(
            ScanExecution.status == "running",
            func.coalesce(ScanExecution.heartbeat_at, ScanExecution.started_at) <= cutoff,
        )
    )
    if db.bind and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    stale_executions = db.scalars(statement).all()
    count = 0
    for execution in stale_executions:
        running_engine = db.scalar(
            select(EngineRun).where(
                EngineRun.execution_id == execution.id,
                EngineRun.status == "running",
            )
        )
        if running_engine:
            _finish_engine(
                db,
                running_engine,
                status="failed",
                error=f"Motor interrompido por expiracao de heartbeat (sem heartbeat ativo ha mais de {int(stale_timeout_seconds)}s).",
            )
        execution.status = "failed"
        execution.error_summary = (
            f"Execucao obsoleta recuperada por reinicializacao/verificacao do worker "
            f"(sem heartbeat ativo por mais de {int(stale_timeout_seconds)} segundos)."
        )
        execution.finished_at = now
        audit(
            db,
            "scan.execution.recovered_stale",
            "scan_execution",
            "worker",
            resource_id=execution.id,
            details={
                "previous_status": "running",
                "stale_timeout_seconds": stale_timeout_seconds,
                "recovered_at": now.isoformat(),
            },
        )
        count += 1
    if count > 0:
        db.commit()
    return count

