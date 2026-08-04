from __future__ import annotations

import asyncio
import logging
import signal
import socket
import time

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, check_database_ready
from govsec_scanner.services import (
    claim_next_execution,
    execute_scan,
    recover_stale_executions,
    seed_profiles,
    update_service_heartbeat,
)

logger = logging.getLogger("govsec_scanner.worker")
_shutdown = False


def _signal_handler(sig: int, _frame: object) -> None:
    global _shutdown
    logger.info("Sinal de encerramento recebido (%s). Finalizando worker...", sig)
    _shutdown = True


def main() -> None:
    global _shutdown
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    settings = get_settings()
    instance_id = f"worker-{socket.gethostname()}"

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
                logger.warning("Falha ao atualizar heartbeat do worker: %s", exc)

        try:
            with SessionLocal() as db:
                execution_id = claim_next_execution(db)
        except Exception as exc:
            logger.error("Erro ao realizar claim de execucao: %s", exc)
            execution_id = None

        if execution_id is None:
            time.sleep(settings.worker_poll_seconds)
            continue

        logger.info("Execucao %s capturada pelo worker %s.", execution_id, instance_id)
        try:
            with SessionLocal() as db:
                asyncio.run(execute_scan(db, execution_id, settings))
        except Exception as exc:
            logger.error("Falha durante execucao do scan %s: %s", execution_id, exc)

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
    except Exception:
        pass


if __name__ == "__main__":
    main()
