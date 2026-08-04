from __future__ import annotations

import asyncio
import logging
import signal
import socket
import time

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, check_database_ready
from govsec_scanner.healthcheck import get_default_instance_id
from govsec_scanner.services import (
    _sanitize_error_message,
    claim_next_execution,
    execute_scan,
    recover_stale_executions,
    seed_profiles,
    update_service_heartbeat,
)

logger = logging.getLogger("govsec_scanner.worker")
_shutdown = False
_active_task: asyncio.Task[None] | None = None
_loop: asyncio.AbstractEventLoop | None = None


def _signal_handler(sig: int, _frame: object) -> None:
    global _shutdown, _active_task, _loop
    logger.info("Sinal de encerramento recebido (%s). Finalizando worker...", sig)
    _shutdown = True
    if _loop is not None and _active_task is not None and not _active_task.done():
        _loop.call_soon_threadsafe(_active_task.cancel)


async def run_worker() -> None:
    global _shutdown, _active_task, _loop
    _loop = asyncio.get_running_loop()
    settings = get_settings()
    instance_id = get_default_instance_id("worker")

    with SessionLocal() as db:
        if not check_database_ready(db):
            logger.error("Banco de dados nao possui a migration correta aplicada. Abortando.")
            raise RuntimeError("Banco de dados sem migration aplicada.")
        seed_profiles(db)
        recovered = recover_stale_executions(db, settings.worker_stale_timeout_seconds)
        if recovered:
            logger.info("Execucoes obsoletas recuperadas: %d", recovered)
        update_service_heartbeat(
            db,
            "worker",
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
                        "worker",
                        instance_id,
                        status="healthy",
                        details={"hostname": socket.gethostname()},
                    )
                last_heartbeat = now
            except Exception as exc:
                logger.warning("Falha ao atualizar heartbeat do worker: %s", _sanitize_error_message(exc))

        try:
            with SessionLocal() as db:
                execution_id = claim_next_execution(db)
        except Exception as exc:
            logger.error("Erro ao realizar claim de execucao: %s", _sanitize_error_message(exc))
            execution_id = None

        if execution_id is None:
            sleep_chunk = 0.5
            slept = 0.0
            while slept < settings.worker_poll_seconds and not _shutdown:
                await asyncio.sleep(sleep_chunk)
                slept += sleep_chunk
            continue

        logger.info("Execucao %s capturada pelo worker %s.", execution_id, instance_id)
        with SessionLocal() as db:
            _active_task = asyncio.create_task(
                execute_scan(db, execution_id, settings, instance_id=instance_id)
            )
            try:
                await _active_task
            except asyncio.CancelledError:
                logger.warning("Scan %s cancelado por interrupcao do worker.", execution_id)
            except Exception as exc:
                logger.error("Falha durante execucao do scan %s: %s", execution_id, _sanitize_error_message(exc))
            finally:
                _active_task = None

    logger.info("Worker %s encerrado graciosamente.", instance_id)
    try:
        with SessionLocal() as db:
            update_service_heartbeat(
                db,
                "worker",
                instance_id,
                status="stopped",
                details={"hostname": socket.gethostname()},
            )
    except Exception as exc:
        logger.warning("Falha ao registrar parada do worker: %s", _sanitize_error_message(exc))


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    try:
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)
    except ValueError:
        pass
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
