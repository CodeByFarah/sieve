"""Integration fixtures: a real PostgreSQL database, migrated with the real migrations.

Each test runs inside a transaction that is rolled back afterwards. Sessions created by code
under test join that transaction through savepoints, so even code that calls ``commit()`` leaves
nothing behind.
"""

import os
from collections.abc import Iterator

import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker

from sieve.db.migrate import upgrade_to_head

DEFAULT_TEST_DATABASE_URL = "postgresql+psycopg://sieve:sieve@127.0.0.1:5432/sieve_test"


def resolve_test_database_url() -> URL:
    url = make_url(os.environ.get("SIEVE_TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL))
    if not (url.database or "").endswith("_test"):
        # These fixtures drop and recreate the database. Refuse anything that isn't obviously
        # a throwaway test database.
        raise RuntimeError(f"refusing to use non-test database {url.database!r}")
    return url


def recreate_database(url: URL) -> None:
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{url.database}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{url.database}"'))
    admin.dispose()


@pytest.fixture(scope="session")
def database_url() -> URL:
    return resolve_test_database_url()


@pytest.fixture(scope="session")
def engine(database_url: URL) -> Iterator[Engine]:
    recreate_database(database_url)
    engine = create_engine(database_url)
    with engine.begin() as connection:
        upgrade_to_head(connection)
    yield engine
    engine.dispose()


@pytest.fixture
def connection(engine: Engine) -> Iterator[Connection]:
    with engine.connect() as connection:
        outer = connection.begin()
        try:
            yield connection
        finally:
            outer.rollback()


@pytest.fixture
def session_factory(connection: Connection) -> sessionmaker[Session]:
    return sessionmaker(
        bind=connection,
        join_transaction_mode="create_savepoint",
        expire_on_commit=False,
        autoflush=False,
    )


@pytest.fixture
def session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    with session_factory() as session:
        yield session
