from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import signal
import time
from unittest.mock import patch

import pytest
from sqlalchemy import select

from govsec_scanner.database import Base, SessionLocal, engine
from govsec_scanner.engines.base import EngineExecutionError, HostObservation
from govsec_scanner.engines.nmap import build_nmap_command
from govsec_scanner.healthcheck import check_health
from govsec_scanner.models import (
    AuthorizedRange,
    ScanExecution,
    ScannerProfile,
    ScanSchedule,
    ServiceHeartbeat,
    utcnow,
)
from govsec_scanner.scheduler import enqueue_due_schedules
from govsec_scanner.services import (
    _sanitize_error_message,
    claim_next_execution,
    execute_scan,
    seed_profiles,
    update_service_heartbeat,
)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_profiles(db)
    yield
    Base.metadata.drop_all(bind=engine)


def test_atomic_claim() -> None:
    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Teste",
            cidr="192.168.1.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-001",
            allow_public=True,
        )
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "discovery"))
        assert profile is not None
        db.add(range_obj)
        db.commit()

        exec1 = ScanExecution(
            range_id=range_obj.id,
            profile_id=profile.id,
            status="queued",
            requested_by="admin",
            justification="Justificativa",
        )
        db.add(exec1)
        db.commit()

        claimed_id = claim_next_execution(db)
        assert claimed_id == exec1.id

        updated = db.scalar(select(ScanExecution).where(ScanExecution.id == exec1.id))
        assert updated is not None
        assert updated.status == "running"
        assert updated.started_at is not None
        assert updated.heartbeat_at is not None


def test_concurrent_workers_claim() -> None:
    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Concorrente",
            cidr="10.0.0.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-002",
            allow_public=True,
        )
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "discovery"))
        assert profile is not None
        db.add(range_obj)
        db.commit()

        exec1 = ScanExecution(
            range_id=range_obj.id,
            profile_id=profile.id,
            status="queued",
            requested_by="admin",
            justification="Justificativa",
        )
        db.add(exec1)
        db.commit()

    def worker_claim_attempt() -> str | None:
        with SessionLocal() as db_session:
            return claim_next_execution(db_session)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(worker_claim_attempt) for _ in range(5)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    claimed = [r for r in results if r is not None]
    assert len(claimed) == 1
    assert claimed[0] == exec1.id


def test_scheduler_no_duplicate_execution() -> None:
    now = utcnow()
    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Agendamento",
            cidr="172.16.0.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-003",
            allow_public=True,
        )
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "discovery"))
        assert profile is not None
        db.add(range_obj)
        db.commit()

        schedule = ScanSchedule(
            name="Agendamento Diario",
            range_id=range_obj.id,
            profile_id=profile.id,
            cron_expression="0 0 * * *",
            next_run_at=now,
            justification="Idempotencia test",
            created_by="admin",
        )
        db.add(schedule)
        db.commit()

    count1 = enqueue_due_schedules()
    assert count1 == 1

    count2 = enqueue_due_schedules()
    assert count2 == 0

    with SessionLocal() as db:
        executions = db.scalars(select(ScanExecution)).all()
        assert len(executions) == 1


def test_worker_scheduler_no_migrations() -> None:
    from govsec_scanner.scheduler import main as scheduler_main
    from govsec_scanner.worker import main as worker_main

    with patch("alembic.command.upgrade") as mock_alembic_upgrade:
        with (
            patch("govsec_scanner.worker.check_database_ready", return_value=False),
            pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"),
        ):
            worker_main()

        with (
            patch("govsec_scanner.scheduler.check_database_ready", return_value=False),
            pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"),
        ):
            scheduler_main()

        mock_alembic_upgrade.assert_not_called()


def test_healthcheck_validates_instance_id() -> None:
    with SessionLocal() as db:
        update_service_heartbeat(
            db, "worker", "worker-inst-A", status="healthy", details={"test": True}
        )

    assert check_health("worker", max_staleness_seconds=10, instance_id="worker-inst-A") is True
    assert check_health("worker", max_staleness_seconds=10, instance_id="worker-inst-B") is False


def test_worker_service_heartbeat_during_long_scan() -> None:
    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Scan Longo",
            cidr="192.168.10.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-LONG",
            allow_public=True,
        )
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "discovery"))
        assert profile is not None
        db.add(range_obj)
        db.commit()

        exec1 = ScanExecution(
            range_id=range_obj.id,
            profile_id=profile.id,
            status="running",
            requested_by="admin",
            justification="Long scan test",
            started_at=utcnow(),
        )
        db.add(exec1)
        db.commit()
        execution_id = exec1.id

    async def mock_async_scan(*args: object, **kwargs: object) -> list[HostObservation]:
        await asyncio.sleep(0.5)
        return []

    with (
        patch("govsec_scanner.engines.nmap.NmapEngine.scan", side_effect=mock_async_scan),
        SessionLocal() as db,
    ):
        asyncio.run(
            execute_scan(
                db,
                execution_id,
                hb_interval_override=0.2,
                instance_id="worker-long-test",
            )
        )

    with SessionLocal() as db:
        hb = db.scalar(
            select(ServiceHeartbeat).where(
                ServiceHeartbeat.service_name == "worker",
                ServiceHeartbeat.instance_id == "worker-long-test",
            )
        )
        assert hb is not None
        assert hb.status == "healthy"


def test_failure_logged_without_secrets(caplog: pytest.LogCaptureFixture) -> None:
    msg_with_secret = "Error connecting to db postgresql://user:super_secret_password_123@localhost:5432/db with key test-api-key-12345"
    sanitized = _sanitize_error_message(Exception(msg_with_secret))
    assert "super_secret_password_123" not in sanitized
    assert "test-api-key-12345" not in sanitized

    with caplog.at_level(logging.WARNING):
        log = logging.getLogger("govsec_scanner.worker")
        try:
            raise ValueError(msg_with_secret)
        except ValueError as exc:
            log.warning("Falha formatada: %s", _sanitize_error_message(exc))

    assert "super_secret_password_123" not in caplog.text
    assert "test-api-key-12345" not in caplog.text


def test_nmap_udp_only_without_raw_sockets() -> None:
    profile = ScannerProfile(
        slug="udp_only",
        name="Perfil UDP",
        description="Apenas UDP",
        discovery_enabled=True,
        service_detection_enabled=False,
        vulnerability_detection_enabled=False,
        tcp_ports="",
        udp_ports="53,123",
    )
    with (
        patch("govsec_scanner.engines.nmap._can_use_raw_sockets", return_value=False),
        pytest.raises(EngineExecutionError, match="Varredura UDP via Nmap requer privilegios de raw sockets"),
    ):
        build_nmap_command("nmap", "127.0.0.1", profile, intensity="low")


def test_real_signal_shutdown() -> None:
    import threading

    from govsec_scanner import worker
    from govsec_scanner.worker import _signal_handler

    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Signal",
            cidr="10.2.0.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-SIG",
            allow_public=True,
        )
        profile = db.scalar(select(ScannerProfile).where(ScannerProfile.slug == "discovery"))
        assert profile is not None
        db.add(range_obj)
        db.commit()

        exec1 = ScanExecution(
            range_id=range_obj.id,
            profile_id=profile.id,
            status="queued",
            requested_by="admin",
            justification="Signal test",
        )
        db.add(exec1)
        db.commit()
        exec_id = exec1.id

    async def mock_slow_scan(*args: object, **kwargs: object) -> list[HostObservation]:
        await asyncio.sleep(3.0)
        return []

    worker._shutdown = False
    with (
        patch("govsec_scanner.worker.check_database_ready", return_value=True),
        patch("govsec_scanner.engines.nmap.NmapEngine.scan", side_effect=mock_slow_scan),
    ):
        t = threading.Thread(target=worker.main, daemon=True)
        t.start()

        # Aguarda worker capturar e iniciar execucao
        for _ in range(30):
            time.sleep(0.1)
            with SessionLocal() as db:
                ex = db.scalar(select(ScanExecution).where(ScanExecution.id == exec_id))
                if ex and ex.status == "running":
                    break

        # Dispara manipulador de sinal SIGTERM enquanto o scan ativo esta em andamento
        _signal_handler(signal.SIGTERM, None)
        t.join(timeout=5.0)

    worker._shutdown = False

    with SessionLocal() as db:
        final_exec = db.scalar(select(ScanExecution).where(ScanExecution.id == exec_id))
        assert final_exec is not None
        assert final_exec.status == "failed"
        assert final_exec.status != "completed"
        assert "interrompida" in (final_exec.error_summary or "").lower()
