"""Alembic environment. The database URL comes from settings (or a caller-provided connection)."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, create_engine, pool

import sieve.db.models  # noqa: F401  (registers every table on Base.metadata)
from sieve.core.config import get_settings
from sieve.db.base import Base

config = context.config
target_metadata = Base.metadata

if config.config_file_name is not None and config.attributes.get("configure_logging", True):
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def _database_url() -> str:
    url: str | None = config.attributes.get("database_url")
    return url or get_settings().database_url.get_secret_value()


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection: Connection | None = config.attributes.get("connection")
    if connection is not None:
        _run(connection)
        return
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        _run(conn)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
