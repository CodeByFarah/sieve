from collections.abc import Iterator

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.engine import URL

from sieve.db.base import Base
from sieve.db.migrate import current_revision, downgrade_to_base, head_revision, upgrade_to_head
from tests.integration.conftest import recreate_database


@pytest.fixture
def scratch_engine(database_url: URL) -> Iterator[Engine]:
    """A separate database, so migrating up and down doesn't disturb other tests."""
    url = database_url.set(database=f"{database_url.database}_migrations")
    recreate_database(url)
    engine = create_engine(url)
    yield engine
    engine.dispose()


def test_upgrade_downgrade_upgrade_round_trip(scratch_engine: Engine) -> None:
    with scratch_engine.begin() as connection:
        upgrade_to_head(connection)
        assert current_revision(connection) == head_revision()
    with scratch_engine.begin() as connection:
        downgrade_to_base(connection)
        tables = set(inspect(connection).get_table_names()) - {"alembic_version"}
        assert tables == set()
    with scratch_engine.begin() as connection:
        upgrade_to_head(connection)
        assert current_revision(connection) == head_revision()


def test_models_and_migrations_agree(engine: Engine) -> None:
    """Fails when a model changes without a matching migration."""
    with engine.connect() as connection:
        diff = compare_metadata(
            MigrationContext.configure(connection, opts={"compare_type": True}), Base.metadata
        )
    assert diff == []
