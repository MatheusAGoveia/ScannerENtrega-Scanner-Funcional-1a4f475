from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, timedelta
from pathlib import Path

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import sessionmaker

from govsec_scanner.config import Settings
from govsec_scanner.database import Base
from govsec_scanner.engines.base import EngineExecutionError, HostObservation, ServiceObservation
from govsec_scanner.engines.nmap import NmapEngine
from govsec_scanner.engines.nuclei import NucleiEngine
from govsec_scanner.models import (
    AuthorizedRange,
    DiscoveredAsset,
    DiscoveredService,
    EngineRun,
    ScanExecution,
    ScannerProfile,
    ScanSchedule,
    utcnow,
)
from govsec_scanner.scheduler import enqueue_due_schedules
from govsec_scanner.services import (
    claim_next_execution,
    execute_scan,
    recover_stale_executions,
    seed_profiles,
)


def _init_test_db(db_path: Path):
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return engine, Session


def test_schema_creation_and_idempotency(tmp_path: Path) -> None:
    db_file = tmp_path / "schema_test.db"
    engine, Session = _init_test_db(db_file)

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    expected_tables = {
        "authorized_ranges",
        "scanner_profiles",
        "scan_schedules",
        "scan_executions",
        "engine_runs",
        "discovered_assets",
        "discovered_services",
        "vulnerability_findings",
        "import_batches",
        "audit_logs",
    }
    assert expected_tables.issubset(tables)

    with Session() as db:
        seed_profiles(db)
        count_before = len(db.scalars(select(ScannerProfile)).all())
        assert count_before == 3

    # Re-running creation metadata should be idempotent and preserve existing records
    Base.metadata.create_all(bind=engine)
    with Session() as db:
        count_after = len(db.scalars(select(ScannerProfile)).all())
        assert count_after == 3

    engine.dispose()


def test_scan_execution_full_status_lifecycle(tmp_path: Path, monkeypatch: object) -> None:
    db_file = tmp_path / "lifecycle_test.db"
    engine, Session = _init_test_db(db_file)

    async def nmap_mock(*args: object, **kwargs: object) -> list[HostObservation]:
        return []

    monkeypatch.setattr(NmapEngine, "scan", nmap_mock)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        assert profile is not None

        range_item = AuthorizedRange(
            name="Faixa Ciclo Vida",
            cidr="10.100.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-LIFECYCLE-001",
        )
        db.add(range_item)
        db.flush()

        # 1. Queued status
        execution = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="queued",
            trigger_type="manual",
            requested_by="tester",
            justification="Teste do ciclo de status completo.",
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id

        # 2. Claim -> Running status
        claimed_id = claim_next_execution(db)
        assert claimed_id == execution_id

        persisted = db.get(ScanExecution, execution_id)
        assert persisted is not None
        assert persisted.status == "running"
        assert persisted.started_at is not None

        # 3. Cancellation test
        persisted.cancellation_requested = True
        db.commit()

        # Running scan pipeline handles cancellation request
        asyncio.run(execute_scan(db, execution_id, Settings(api_key="test-api-key-with-at-least-24-chars")))
        persisted_cancelled = db.get(ScanExecution, execution_id)
        assert persisted_cancelled is not None
        assert persisted_cancelled.status == "cancelled"
        assert persisted_cancelled.finished_at is not None

    engine.dispose()


def test_worker_atomic_claim_and_concurrency(tmp_path: Path) -> None:
    db_file = tmp_path / "concurrency_test.db"
    engine, Session = _init_test_db(db_file)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        range_item = AuthorizedRange(
            name="Faixa Concorrencia",
            cidr="10.200.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-CONCURRENCY-001",
        )
        db.add(range_item)
        db.flush()

        execution = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="queued",
            trigger_type="manual",
            requested_by="tester",
            justification="Teste de operacao atomica do worker.",
        )
        db.add(execution)
        db.commit()

    def worker_claim_task():
        with Session() as db:
            return claim_next_execution(db)

    # 2 concurrent workers attempting to claim the single queued task
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(worker_claim_task)
        f2 = executor.submit(worker_claim_task)
        results = [f1.result(), f2.result()]

    claimed_results = [r for r in results if r is not None]
    none_results = [r for r in results if r is None]

    assert len(claimed_results) == 1
    assert len(none_results) == 1

    engine.dispose()


def test_worker_stale_execution_recovery_expiration_based(tmp_path: Path) -> None:
    db_file = tmp_path / "recovery_test.db"
    engine, Session = _init_test_db(db_file)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        assert profile is not None
        range_item = AuthorizedRange(
            name="Faixa Queda Worker",
            cidr="10.300.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-STALE-001",
        )
        db.add(range_item)
        db.flush()

        now = utcnow()
        # 1. Recent running execution (started 30s ago, active heartbeat 10s ago)
        recent_exec = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=now - timedelta(seconds=30),
            heartbeat_at=now - timedelta(seconds=10),
            trigger_type="manual",
            requested_by="worker-1",
            justification="Execucao ativa recente em andamento.",
        )
        # 2. Old running execution with valid recent heartbeat (started 1h ago, heartbeat 20s ago)
        active_long_exec = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=now - timedelta(hours=1),
            heartbeat_at=now - timedelta(seconds=20),
            trigger_type="manual",
            requested_by="worker-1",
            justification="Execucao longa com heartbeat valido.",
        )
        # 3. Truly stale execution (started 1h ago, heartbeat 10m ago)
        stale_exec = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=now - timedelta(hours=1),
            heartbeat_at=now - timedelta(minutes=10),
            trigger_type="manual",
            requested_by="worker-crashed",
            justification="Execucao verdadeiramente obsoleta.",
        )
        db.add(recent_exec)
        db.add(active_long_exec)
        db.add(stale_exec)
        db.flush()

        stale_engine_run = EngineRun(
            execution_id=stale_exec.id,
            engine="nmap",
            status="running",
            started_at=now - timedelta(minutes=10),
        )
        db.add(stale_engine_run)
        db.commit()
        recent_id = recent_exec.id
        active_long_id = active_long_exec.id
        stale_id = stale_exec.id

    # Worker 2 boots up and runs stale recovery with 300s (5 min) timeout threshold
    with Session() as db:
        recovered_count = recover_stale_executions(db, stale_timeout_seconds=300.0)
        assert recovered_count == 1

        # 1. Recent execution remains untouched ('running')
        recent_persisted = db.get(ScanExecution, recent_id)
        assert recent_persisted is not None
        assert recent_persisted.status == "running"

        # 2. Long running execution with valid heartbeat remains untouched ('running')
        active_persisted = db.get(ScanExecution, active_long_id)
        assert active_persisted is not None
        assert active_persisted.status == "running"

        # 3. Truly stale execution is marked as 'failed' with error summary and timestamp
        stale_persisted = db.get(ScanExecution, stale_id)
        assert stale_persisted is not None
        assert stale_persisted.status == "failed"
        assert stale_persisted.finished_at is not None
        assert "obsoleta" in (stale_persisted.error_summary or "").lower()

        engine_run = db.scalar(select(EngineRun).where(EngineRun.execution_id == stale_id))
        assert engine_run is not None
        assert engine_run.status == "failed"

    engine.dispose()


def test_bounded_engine_retry_and_timeout_limits(tmp_path: Path) -> None:
    from govsec_scanner.engines.nmap import build_nmap_command
    from govsec_scanner.engines.nuclei import build_nuclei_command

    profile = ScannerProfile(
        slug="test-bounds",
        name="Perfil Limites",
        description="Perfil de teste para flags defensivas.",
        tcp_ports="80,443",
        udp_ports="",
        timeout_seconds=10,
        max_parallelism=5,
        rate_limit_per_second=20,
    )
    # Nmap flags must include bounded retries and timeout
    nmap_cmd = build_nmap_command("nmap", "10.0.0.0/24", profile, intensity="low")
    assert "--max-retries" in nmap_cmd
    max_retries_idx = nmap_cmd.index("--max-retries")
    assert nmap_cmd[max_retries_idx + 1] == "1"

    # Nuclei flags must include retries 0 and timeout
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("http://10.0.0.1\n", encoding="utf-8")
    nuclei_cmd = build_nuclei_command("nuclei", targets_file, profile, tmp_path)
    assert "-retries" in nuclei_cmd
    retries_idx = nuclei_cmd.index("-retries")
    assert nuclei_cmd[retries_idx + 1] == "0"


def test_scheduler_due_executions_cron_and_disabled(tmp_path: Path, monkeypatch: object) -> None:
    db_file = tmp_path / "scheduler_test.db"
    engine, Session = _init_test_db(db_file)

    monkeypatch.setattr("govsec_scanner.scheduler.SessionLocal", Session)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        range_item = AuthorizedRange(
            name="Faixa Agendamento",
            cidr="10.400.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-SCHED-001",
        )
        db.add(range_item)
        db.flush()

        past_due = utcnow() - timedelta(minutes=5)
        
        # 1. Active schedule due for execution
        active_schedule = ScanSchedule(
            name="Agendamento Ativo",
            range_id=range_item.id,
            profile_id=profile.id,
            cron_expression="0 * * * *",
            next_run_at=past_due,
            enabled=True,
            justification="Agendamento regular ativo.",
            created_by="admin",
        )
        # 2. Disabled schedule due for execution
        disabled_schedule = ScanSchedule(
            name="Agendamento Desativado",
            range_id=range_item.id,
            profile_id=profile.id,
            cron_expression="0 * * * *",
            next_run_at=past_due,
            enabled=False,
            justification="Agendamento pausado pelo operador.",
            created_by="admin",
        )
        db.add(active_schedule)
        db.add(disabled_schedule)
        db.commit()
        active_id = active_schedule.id
        disabled_id = disabled_schedule.id

    # Run scheduler enqueue step
    enqueued_count = enqueue_due_schedules()
    assert enqueued_count == 1

    with Session() as db:
        active_sched = db.get(ScanSchedule, active_id)
        assert active_sched is not None
        assert active_sched.next_run_at is not None and active_sched.next_run_at.replace(tzinfo=UTC).timestamp() > utcnow().timestamp()

        disabled_sched = db.get(ScanSchedule, disabled_id)
        assert disabled_sched is not None
        # Disabled schedule remains unchanged
        assert disabled_sched.next_run_at.replace(tzinfo=UTC).timestamp() == past_due.timestamp()

        executions = db.scalars(select(ScanExecution)).all()
        assert len(executions) == 1
        assert executions[0].schedule_id == active_id
        assert executions[0].status == "queued"

    # Running enqueue step again immediately should NOT create duplicate executions
    duplicate_count = enqueue_due_schedules()
    assert duplicate_count == 0

    engine.dispose()


def test_partial_failure_preserves_valid_results(tmp_path: Path, monkeypatch: object) -> None:
    db_file = tmp_path / "partial_test.db"
    engine, Session = _init_test_db(db_file)

    async def nmap_mock(*args: object, **kwargs: object) -> list[HostObservation]:
        return [
            HostObservation(
                ip_address="10.50.0.5",
                hostname="host-parcial",
                services=[ServiceObservation(protocol="tcp", port=80, service_name="http")],
            )
        ]

    async def nuclei_mock(*args: object, **kwargs: object):
        raise EngineExecutionError("Nuclei indisponivel durante varredura.")

    monkeypatch.setattr(NmapEngine, "scan", nmap_mock)
    monkeypatch.setattr(NucleiEngine, "scan", nuclei_mock)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "vulnerability"))
        range_item = AuthorizedRange(
            name="Faixa Parcial",
            cidr="10.50.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-PARTIAL-001",
        )
        db.add(range_item)
        db.flush()

        execution = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=utcnow(),
            trigger_type="manual",
            requested_by="tester",
            justification="Teste de preservacao de falhas parciais.",
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id

        settings = Settings(api_key="test-api-key-with-at-least-24-chars", nuclei_templates_dir=tmp_path)
        asyncio.run(execute_scan(db, execution_id, settings))

        updated = db.get(ScanExecution, execution_id)
        assert updated is not None
        assert updated.status == "partially_completed"
        assert "Nuclei indisponivel" in (updated.error_summary or "")

        # Valid Nmap results MUST be preserved despite Nuclei failure
        asset = db.scalar(select(DiscoveredAsset).where(DiscoveredAsset.ip_address == "10.50.0.5"))
        assert asset is not None
        assert asset.hostname == "host-parcial"

        service = db.scalar(select(DiscoveredService).where(DiscoveredService.asset_id == asset.id))
        assert service is not None
        assert service.port == 80

    engine.dispose()


def test_post_claim_failure_marks_execution_failed(tmp_path: Path, monkeypatch: object) -> None:
    db_file = tmp_path / "post_claim_fail_test.db"
    engine, Session = _init_test_db(db_file)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        assert profile is not None

        # Disabled range (fails scope/authorization validation after claim)
        range_item = AuthorizedRange(
            name="Faixa Desativada",
            cidr="10.80.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-DISABLED-001",
            enabled=False,
        )
        db.add(range_item)
        db.flush()

        execution = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=utcnow(),
            trigger_type="manual",
            requested_by="tester",
            justification="Teste de falha no estagio inicial pos-captura.",
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id

        settings = Settings(api_key="test-api-key-with-at-least-24-chars")
        asyncio.run(execute_scan(db, execution_id, settings))

        updated = db.get(ScanExecution, execution_id)
        assert updated is not None
        assert updated.status == "failed"
        assert updated.finished_at is not None
        assert "nao possui autorizacao ativa" in (updated.error_summary or "")

    engine.dispose()


def test_heartbeat_renewal_and_task_cleanup_during_execution(tmp_path: Path, monkeypatch: object) -> None:
    db_file = tmp_path / "hb_test.db"
    engine, Session = _init_test_db(db_file)

    async def delayed_nmap_mock(*args: object, **kwargs: object) -> list[HostObservation]:
        await asyncio.sleep(0.1)
        return []

    monkeypatch.setattr(NmapEngine, "scan", delayed_nmap_mock)

    with Session() as db:
        seed_profiles(db)
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "availability"))
        assert profile is not None
        range_item = AuthorizedRange(
            name="Faixa Heartbeat",
            cidr="10.90.0.0/24",
            address_count=256,
            environment="Teste",
            owner="Dev",
            authorization_reference="AUT-HB-001",
        )
        db.add(range_item)
        db.flush()

        initial_hb = utcnow() - timedelta(seconds=10)
        execution = ScanExecution(
            range_id=range_item.id,
            profile_id=profile.id,
            status="running",
            started_at=utcnow(),
            heartbeat_at=initial_hb,
            trigger_type="manual",
            requested_by="tester",
            justification="Teste de renovacao automatica de heartbeat.",
        )
        db.add(execution)
        db.commit()
        execution_id = execution.id

        # Use valid stale timeout (ge=10.0)
        settings = Settings(api_key="test-api-key-with-at-least-24-chars", worker_stale_timeout_seconds=10.0)

        # Execute scan which runs the heartbeat loop task
        asyncio.run(execute_scan(db, execution_id, settings))

        updated = db.get(ScanExecution, execution_id)
        assert updated is not None
        assert updated.status == "completed"
        assert updated.heartbeat_at is not None
        assert updated.heartbeat_at > initial_hb

        # Confirm active worker recovery DOES NOT recover this execution
        recovered = recover_stale_executions(db, stale_timeout_seconds=300.0)
        assert recovered == 0

    engine.dispose()
