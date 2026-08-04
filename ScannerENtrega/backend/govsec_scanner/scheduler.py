import logging
import time

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, check_database_ready
from govsec_scanner.models import ScanExecution, ScanSchedule, utcnow
from govsec_scanner.services import audit, next_cron_run, seed_profiles


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
        for schedule in db.scalars(statement).all():
            running = db.scalar(
                select(ScanExecution.id).where(
                    ScanExecution.schedule_id == schedule.id,
                    ScanExecution.status.in_(["queued", "running"]),
                )
            )
            if running is None:
                execution = ScanExecution(
                    schedule_id=schedule.id,
                    range_id=schedule.range_id,
                    profile_id=schedule.profile_id,
                    trigger_type="scheduled",
                    requested_by="scheduler",
                    justification=schedule.justification,
                )
                db.add(execution)
                audit(
                    db,
                    "scan.execution.queued",
                    "scan_execution",
                    "scheduler",
                    resource_id=execution.id,
                    details={"schedule_id": schedule.id},
                )
                count += 1
            schedule.last_run_at = now
            schedule.next_run_at = next_cron_run(
                schedule.cron_expression, schedule.timezone_name, now
            )
    return count


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    with SessionLocal() as db:
        if not check_database_ready(db):
            logging.error("Banco de dados nao possui a migration correta aplicada. Abortando.")
            raise RuntimeError("Banco de dados sem migration aplicada.")
        seed_profiles(db)
    while True:
        queued = enqueue_due_schedules()
        if queued:
            logging.info("Agendamentos enfileirados: %d", queued)
        time.sleep(settings.scheduler_poll_seconds)


if __name__ == "__main__":
    main()
