import logging
import re
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, text
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
db_url: str = settings.database_url or ""
engine = create_engine(db_url, **_engine_kwargs(db_url))
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_migration_version(db: Session) -> str | None:
    try:
        result = db.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        return str(result) if result else None
    except Exception:
        return None


def get_expected_migration_head() -> str:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    backend_dir = Path(__file__).resolve().parent.parent
    alembic_cfg_path = backend_dir / "alembic.ini"
    if alembic_cfg_path.exists():
        cfg = Config(str(alembic_cfg_path))
        cfg.set_main_option("script_location", str(backend_dir / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)
        script = ScriptDirectory.from_config(cfg)
        head = script.get_current_head()
        if head:
            return str(head)
    return "001_initial_schema"


def check_database_ready(db: Session) -> bool:
    current = get_current_migration_version(db)
    expected = get_expected_migration_head()
    return current is not None and current == expected
