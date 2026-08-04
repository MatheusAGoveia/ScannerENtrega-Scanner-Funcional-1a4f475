import logging
import re
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from govsec_scanner.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


def sanitize_db_url(url: str) -> str:
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:[redacted]@", url)


def _engine_kwargs(database_url: str) -> dict[str, object]:
    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs.update({"pool_size": 10, "max_overflow": 20})
    return kwargs


settings = get_settings()
engine = create_engine(settings.database_url, **_engine_kwargs(settings.database_url))
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_database() -> None:
    from pathlib import Path

    from alembic.config import Config

    from alembic import command

    logger.info("Inicializando conexao do banco de dados: %s", sanitize_db_url(settings.database_url))

    backend_dir = Path(__file__).resolve().parent.parent
    alembic_cfg_path = backend_dir / "alembic.ini"

    if alembic_cfg_path.exists():
        cfg = Config(str(alembic_cfg_path))
        cfg.set_main_option("script_location", str(backend_dir / "alembic"))
        cfg.set_main_option("sqlalchemy.url", settings.database_url)
        command.upgrade(cfg, "head")
    else:
        from govsec_scanner import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
