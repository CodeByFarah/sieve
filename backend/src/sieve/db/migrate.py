"""Programmatic access to migrations, for readiness checks, tests and the migrate task."""

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection

SCRIPT_LOCATION = "sieve.db:migrations"


def alembic_config(
    *, database_url: str | None = None, connection: Connection | None = None
) -> Config:
    config = Config()
    config.set_main_option("script_location", SCRIPT_LOCATION)
    config.attributes["configure_logging"] = False
    if database_url is not None:
        config.attributes["database_url"] = database_url
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(connection: Connection) -> str | None:
    return MigrationContext.configure(connection).get_current_revision()


def upgrade_to_head(connection: Connection) -> None:
    command.upgrade(alembic_config(connection=connection), "head")


def downgrade_to_base(connection: Connection) -> None:
    command.downgrade(alembic_config(connection=connection), "base")
