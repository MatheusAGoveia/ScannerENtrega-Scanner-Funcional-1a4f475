import re
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context
from govsec_scanner import models  # noqa: F401
from govsec_scanner.config import get_settings
from govsec_scanner.database import Base

config = context.config

if config.config_file_name:
    fileConfig(config.config_file_name)

settings = get_settings()

def sanitize_db_url(url: str) -> str:
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:[redacted]@", url)

config.set_main_option("sqlalchemy.url", settings.database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = settings.database_url
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
