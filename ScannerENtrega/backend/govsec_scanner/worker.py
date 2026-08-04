import asyncio
import logging
import time

from govsec_scanner.config import get_settings
from govsec_scanner.database import SessionLocal, init_database
from govsec_scanner.services import claim_next_execution, execute_scan, seed_profiles


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = get_settings()
    init_database()
    with SessionLocal() as db:
        seed_profiles(db)
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
