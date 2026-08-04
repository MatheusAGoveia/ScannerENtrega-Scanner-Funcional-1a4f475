from __future__ import annotations

import logging
import signal
import socket
import time

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, check_database_ready
from govsec_scanner.healthcheck import get_default_instance_id
from govsec_scanner.models import ScanExecution, ScanSchedule, utcnow
from govsec_scanner.services import audit, next_cron_run, seed_profiles, update_service_heartbeat

logger = logging.getLogger("govsec_scanner.scheduler")
_shutdown = False


def _signal_handler(sig: int, _frame: object) -> None:
    global _shutdown
    logger.info("Sinal de encerramento recebido (%s). Finalizando scheduler...", sig)
    _shutdown = True


def enqueue_due_schedules() -> int:
    now = utcnow()
    count = 0
    with SessionLocal.begin() as db:
        statement = (
            select(ScanSchedule)
            .options(
                selectinload(ScanSchedule.authorized_range), selectinload(ScanSchedule.profile)
            )
            .where(
                ScanSchedule.enabled.is_(True),
                ScanSchedule.next_run_at.is_not(None),
                ScanSchedule.next_run_at <= now,
            )
        )
        if db.bind and db.bind.dialect.name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)

        schedules = db.scalars(statement).all()
        for schedule in schedules:
            scheduled_time = schedule.next_run_at

            # Verificacao explicita de idempotencia: se ja existe execucao para esse agendamento e horario
            existing = db.scalar(
                select(ScanExecution.id).where(
                    ScanExecution.schedule_id == schedule.id,
                    ScanExecution.scheduled_run_at == scheduled_time,
                )
            )
            if existing is None:
                running = db.scalar(
                    select(ScanExecution.id).where(
                        ScanExecution.schedule_id == schedule.id,
                        ScanExecution.status.in_(["queued", "running"]),
                    )
                )
                if running is None:
                    try:
                        with db.begin_nested():
                            execution = ScanExecution(
                                schedule_id=schedule.id,
                                scheduled_run_at=scheduled_time,
                                range_id=schedule.range_id,
                                profile_id=schedule.profile_id,
                                trigger_type="scheduled",
                                requested_by="scheduler",
                                justification=schedule.justification,
                            )
                            db.add(execution)
                            db.flush()
                        audit(
                            db,
                            "scan.execution.queued",
                            "scan_execution",
                            "scheduler",
                            resource_id=execution.id,
                            details={
                                "schedule_id": schedule.id,
                                "scheduled_run_at": scheduled_time.isoformat()
                                if scheduled_time
                                else None,
                            },
                        )
                        count += 1
                    except IntegrityError:
                        logger.warning(
                            "Execucao duplicada evitada para agendamento %s em %s",
                            schedule.id,
                            scheduled_time,
                        )

            schedule.last_run_at = now
            schedule.next_run_at = next_cron_run(
                schedule.cron_expression, schedule.timezone_name, now
            )
    return count


def main() -> None:
    global _shutdown
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    settings = get_settings()
    instance_id = get_default_instance_id("scheduler")

    with SessionLocal() as db:
        if not check_database_ready(db):
            logger.error("Banco de dados nao possui a migration correta aplicada. Abortando.")
            raise RuntimeError("Banco de dados sem migration aplicada.")
        seed_profiles(db)
        update_service_heartbeat(
            db,
            "scheduler",
            instance_id,
            status="healthy",
            details={"hostname": socket.gethostname()},
        )

    last_heartbeat = 0.0
    while not _shutdown:
        now = time.time()
        if now - last_heartbeat >= 5.0:
            try:
                with SessionLocal() as db:
                    update_service_heartbeat(
                        db,
                        "scheduler",
                        instance_id,
                        status="healthy",
                        details={"hostname": socket.gethostname()},
                    )
                last_heartbeat = now
            except Exception as exc:
                logger.warning("Falha ao atualizar heartbeat do scheduler: %s", exc)

        try:
            queued = enqueue_due_schedules()
            if queued:
                logger.info("Agendamentos enfileirados: %d", queued)
        except Exception as exc:
            logger.error("Erro ao enfileirar agendamentos: %s", exc)

        # Espera fracionada para responder rapidamente ao sinal de shutdown
        sleep_chunk = 0.5
        slept = 0.0
        while slept < settings.scheduler_poll_seconds and not _shutdown:
            time.sleep(sleep_chunk)
            slept += sleep_chunk

    logger.info("Scheduler %s encerrado graciosamente.", instance_id)
    try:
        with SessionLocal() as db:
            update_service_heartbeat(
                db,
                "scheduler",
                instance_id,
                status="stopped",
                details={"hostname": socket.gethostname()},
            )
    except Exception:
        pass


if __name__ == "__main__":
    main()
