import json
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.feeds import EpssRecord, KevRecord
from sieve.advisories.ingest import ingest_osv_records, known_cve_ids, load_snapshot
from sieve.advisories.store import upsert_epss, upsert_kev
from sieve.db.enums import IngestionStatus, Severity
from sieve.db.models import (
    Advisory,
    AdvisoryPackage,
    EpssScore,
    IngestionFailure,
    Job,
    KevEntry,
    Package,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "osv"


def count(session: Session, model: type, *where: object) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*where)) or 0  # type: ignore[arg-type]


def test_ingests_records_links_packages_and_enqueues_fanout(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    outcome = ingest_osv_records(session_factory, load_snapshot(FIXTURES))

    assert (outcome.seen, outcome.changed, outcome.failed) == (3, 3, 0)
    assert outcome.status is IngestionStatus.SUCCEEDED
    ghsa = session.scalar(select(Advisory).where(Advisory.source_id == "GHSA-8q59-q68h-6hv4"))
    assert ghsa is not None
    assert ghsa.severity is Severity.CRITICAL
    assert "CVE-2020-14343" in ghsa.aliases
    pyyaml = session.scalar(select(Package).where(Package.name == "pyyaml"))
    assert pyyaml is not None
    assert count(session, AdvisoryPackage, AdvisoryPackage.package_id == pyyaml.id) == 2
    assert count(session, Job, Job.kind == "advisories.fanout") == 1  # one per run


def test_reingesting_unchanged_records_is_a_no_op(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    second = ingest_osv_records(session_factory, load_snapshot(FIXTURES))

    assert (second.seen, second.changed) == (3, 0)
    assert count(session, Advisory) == 3
    assert count(session, Job, Job.kind == "advisories.fanout") == 1  # unchanged run: none


def test_changed_record_updates_and_fans_out_again(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    record = json.loads((FIXTURES / "GHSA-x84v-xcm2-53pg.json").read_text())
    record["summary"] = "updated summary"

    outcome = ingest_osv_records(session_factory, [("updated", json.dumps(record).encode())])

    assert outcome.changed == 1
    advisory = session.scalar(select(Advisory).where(Advisory.source_id == "GHSA-x84v-xcm2-53pg"))
    assert advisory is not None
    assert advisory.summary == "updated summary"
    assert count(session, Job, Job.kind == "advisories.fanout") == 2


def test_bad_records_are_dead_lettered_not_dropped(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    records = [
        ("broken.json", b"{not json"),
        ("incomplete.json", b'{"id": "X-1"}'),
        *load_snapshot(FIXTURES),
    ]
    outcome = ingest_osv_records(session_factory, records)

    assert (outcome.seen, outcome.changed, outcome.failed) == (5, 3, 2)
    assert outcome.status is IngestionStatus.PARTIAL
    failures = session.scalars(select(IngestionFailure).order_by(IngestionFailure.record_id)).all()
    assert [f.record_id for f in failures] == ["broken.json", "incomplete.json"]
    assert failures[0].payload_excerpt == "{not json"


def test_kev_epss_upserts_and_cve_discovery(
    session_factory: sessionmaker[Session], session: Session
) -> None:
    from datetime import date
    from decimal import Decimal

    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    assert known_cve_ids(session) == ["CVE-2018-18074", "CVE-2020-14343"]

    upsert_kev(
        session, [KevRecord("CVE-2020-14343", date(2024, 1, 1), None, False, "PyYAML", "PyYAML")]
    )
    upsert_epss(
        session, [EpssRecord("CVE-2020-14343", Decimal("0.1"), Decimal("0.9"), date(2026, 10, 5))]
    )
    upsert_epss(
        session, [EpssRecord("CVE-2020-14343", Decimal("0.2"), Decimal("0.95"), date(2026, 10, 6))]
    )

    assert count(session, KevEntry) == 1
    epss = session.get(EpssScore, "CVE-2020-14343")
    assert epss is not None
    assert epss.score == Decimal("0.20000")
