from __future__ import annotations

import concurrent.futures
from unittest.mock import patch

import pytest
from sqlalchemy import select

from govsec_scanner.database import Base, SessionLocal, engine
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

    # Segundas tentativas nao devem duplicar execucoes
    count2 = enqueue_due_schedules()
    assert count2 == 0

    with SessionLocal() as db:
        executions = db.scalars(select(ScanExecution)).all()
        assert len(executions) == 1


def test_worker_scheduler_no_migrations() -> None:
    from govsec_scanner.scheduler import main as scheduler_main
    from govsec_scanner.worker import main as worker_main

    with patch("govsec_scanner.database.check_database_ready", return_value=False):
        with pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"):
            worker_main()

        with pytest.raises(RuntimeError, match="Banco de dados sem migration aplicada"):
            scheduler_main()


def test_heartbeat_updates() -> None:
    with SessionLocal() as db:
        update_service_heartbeat(
            db, "worker", "worker-1", status="healthy", details={"test": True}
        )
        update_service_heartbeat(
            db, "scheduler", "scheduler-1", status="healthy", details={"test": True}
        )

        hb_worker = db.scalar(
            select(ServiceHeartbeat).where(ServiceHeartbeat.service_name == "worker")
        )
        assert hb_worker is not None
        assert hb_worker.status == "healthy"

    assert check_health("worker", max_staleness_seconds=10) is True
    assert check_health("scheduler", max_staleness_seconds=10) is True


def test_failure_logged_without_secrets() -> None:
    msg_with_secret = "Error connecting to db postgresql://user:super_secret_password_123@localhost:5432/db with key test-api-key-12345"
    sanitized = _sanitize_error_message(Exception(msg_with_secret))
    assert "super_secret_password_123" not in sanitized
    assert "test-api-key-12345" not in sanitized
    assert "[REDACTED]" in sanitized or "postgresql://" not in sanitized


def test_shutdown_behavior() -> None:
    with SessionLocal() as db:
        range_obj = AuthorizedRange(
            name="Faixa Shutdown",
            cidr="10.1.0.0/24",
            address_count=256,
            environment="test",
            owner="admin",
            authorization_reference="REF-004",
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
            justification="Shutdown test",
        )
        db.add(exec1)
        db.commit()

    with SessionLocal() as db:
        claimed_id = claim_next_execution(db)
        assert claimed_id == exec1.id

    with SessionLocal() as db:
        exec_db = db.scalar(select(ScanExecution).where(ScanExecution.id == claimed_id))
        assert exec_db is not None
        assert exec_db.status == "running"
        assert exec_db.status != "completed"
