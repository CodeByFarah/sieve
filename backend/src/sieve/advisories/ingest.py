"""Ingestion runs: OSV (bulk export or explicit records), KEV and EPSS.

Every run is recorded in ``ingestion_runs``. A record that cannot be normalised becomes a row in
``ingestion_failures`` (the per-record dead letter) — it is never silently dropped, and one bad
record does not abort the run.
"""

import json
import tempfile
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories import feeds
from sieve.advisories.osv import parse_osv
from sieve.advisories.store import upsert_advisory, upsert_epss, upsert_kev
from sieve.core.http import download
from sieve.core.logging import get_logger
from sieve.db.enums import IngestionStatus
from sieve.db.models import Advisory, IngestionFailure, IngestionRun
from sieve.db.session import transaction
from sieve.worker import queue

log = get_logger(__name__)

OSV_PYPI_EXPORT = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
MAX_EXPORT_BYTES = 512 * 1024 * 1024
BATCH_SIZE = 200
EXCERPT = 2_000

RawRecord = tuple[str, bytes]


@dataclass(frozen=True)
class IngestOutcome:
    run_id: Any
    seen: int
    changed: int
    failed: int
    status: IngestionStatus


def _start(factory: sessionmaker[Session], source: str) -> Any:
    with transaction(factory) as session:
        run = IngestionRun(source=source, status=IngestionStatus.RUNNING)
        session.add(run)
        session.flush()
        return run.id


def _finish(
    factory: sessionmaker[Session],
    run_id: Any,
    *,
    seen: int,
    changed: int,
    failed: int,
    error: str | None,
) -> IngestionStatus:
    if error is not None:
        status = IngestionStatus.FAILED
    elif failed:
        status = IngestionStatus.PARTIAL
    else:
        status = IngestionStatus.SUCCEEDED
    with transaction(factory) as session:
        run = session.get(IngestionRun, run_id)
        assert run is not None  # noqa: S101
        run.status = status
        run.records_seen = seen
        run.records_changed = changed
        run.records_failed = failed
        run.error = error
        run.finished_at = datetime.now(UTC)
    return status


def ingest_osv_records(
    factory: sessionmaker[Session], records: Iterable[RawRecord], *, source: str = "osv"
) -> IngestOutcome:
    run_id = _start(factory, source)
    seen = changed = failed = 0
    error: str | None = None
    iterator: Iterator[RawRecord] = iter(records)
    try:
        while True:
            batch = [record for _, record in zip(range(BATCH_SIZE), iterator, strict=False)]
            if not batch:
                break
            with transaction(factory) as session:
                for record_id, payload in batch:
                    seen += 1
                    try:
                        with session.begin_nested():
                            advisory = parse_osv(json.loads(payload))
                            changed += upsert_advisory(session, advisory).changed
                    except (KeyError, ValueError, TypeError, IntegrityError, DataError) as exc:
                        failed += 1
                        session.add(
                            IngestionFailure(
                                run_id=run_id,
                                source=source,
                                record_id=record_id[:255],
                                error=f"{type(exc).__name__}: {exc}"[:2000],
                                payload_excerpt=payload[:EXCERPT].decode("utf-8", "replace"),
                            )
                        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        _finish(factory, run_id, seen=seen, changed=changed, failed=failed, error=error)
        raise
    status = _finish(factory, run_id, seen=seen, changed=changed, failed=failed, error=None)
    if changed:
        with transaction(factory) as session:
            queue.enqueue(
                session,
                kind="advisories.fanout",
                idempotency_key=f"advisories.fanout:run:{run_id}",
                payload={"run_id": str(run_id)},
                priority=50,
            )
    log.info("ingestion.osv.finished", seen=seen, changed=changed, failed=failed)
    return IngestOutcome(run_id, seen, changed, failed, status)


def iter_osv_zip(path: Path) -> Iterator[RawRecord]:
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.filename.endswith(".json") and info.file_size < 5_000_000:
                yield info.filename, archive.read(info)


def ingest_osv_export(factory: sessionmaker[Session], client: httpx.Client) -> IngestOutcome:
    """Full PyPI export. Cheap to repeat: unchanged records are skipped by content hash."""
    with tempfile.TemporaryDirectory(prefix="sieve-osv-") as tmp:
        archive = Path(tmp) / "all.zip"
        download(client, OSV_PYPI_EXPORT, archive, max_bytes=MAX_EXPORT_BYTES)
        return ingest_osv_records(factory, iter_osv_zip(archive))


def _feed_run(
    factory: sessionmaker[Session], source: str, load: Callable[[Session], int]
) -> IngestOutcome:
    run_id = _start(factory, source)
    try:
        with transaction(factory) as session:
            count = load(session)
    except Exception as exc:
        _finish(factory, run_id, seen=0, changed=0, failed=0, error=f"{type(exc).__name__}: {exc}")
        raise
    status = _finish(factory, run_id, seen=count, changed=count, failed=0, error=None)
    return IngestOutcome(run_id, count, count, 0, status)


def ingest_kev(factory: sessionmaker[Session], client: httpx.Client) -> IngestOutcome:
    records = feeds.fetch_kev(client)
    return _feed_run(factory, "kev", lambda session: upsert_kev(session, records))


def known_cve_ids(session: Session) -> list[str]:
    aliases = select(func.unnest(Advisory.aliases).label("alias")).subquery()
    rows = session.scalars(select(aliases.c.alias).where(aliases.c.alias.like("CVE-%")).distinct())
    return sorted(rows)


def ingest_epss(
    factory: sessionmaker[Session], client: httpx.Client, cve_ids: Iterable[str] | None = None
) -> IngestOutcome:
    if cve_ids is None:
        with factory() as session:
            cve_ids = known_cve_ids(session)
    records = feeds.fetch_epss(client, cve_ids)
    return _feed_run(factory, "epss", lambda session: upsert_epss(session, records))


def load_snapshot(directory: Path) -> Iterator[RawRecord]:
    """Advisory records saved as files (the demo's labelled OSV snapshot, test fixtures)."""
    for path in sorted(directory.glob("*.json")):
        yield path.name, path.read_bytes()
