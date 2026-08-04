import asyncio
import logging
import time

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, check_database_ready
from govsec_scanner.services import (
    claim_next_execution,
    execute_scan,
    recover_stale_executions,
    seed_profiles,
)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    with SessionLocal() as db:
        if not check_database_ready(db):
            logging.error("Banco de dados nao possui a migration correta aplicada. Abortando.")
            raise RuntimeError("Banco de dados sem migration aplicada.")
        seed_profiles(db)
        recovered = recover_stale_executions(db, settings.worker_stale_timeout_seconds)
        if recovered:
            logging.info("Execucoes obsoletas recuperadas: %d", recovered)
    while True:
        with SessionLocal() as db:
            execution_id = claim_next_execution(db)
        if execution_id is None:
            time.sleep(settings.worker_poll_seconds)
            continue
        with SessionLocal() as db:
            asyncio.run(execute_scan(db, execution_id, settings))


if __name__ == "__main__":
    main()
