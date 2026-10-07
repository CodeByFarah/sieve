"""Persisting normalised advisories and feed data."""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.advisories.feeds import EpssRecord, KevRecord
from sieve.advisories.osv import NormalizedAdvisory
from sieve.db.enums import SymbolKind, SymbolOrigin
from sieve.db.models import (
    Advisory,
    AdvisoryPackage,
    EpssScore,
    KevEntry,
    Package,
    VulnerableSymbol,
)
from sieve.sbom.models import ECOSYSTEM


def ensure_package(session: Session, name: str, ecosystem: str = ECOSYSTEM) -> uuid.UUID:
    inserted: uuid.UUID | None = session.scalar(
        insert(Package)
        .values(id=uuid.uuid4(), ecosystem=ecosystem, name=name)
        .on_conflict_do_nothing(index_elements=[Package.ecosystem, Package.name])
        .returning(Package.id)
    )
    if inserted is not None:
        return inserted
    existing: uuid.UUID | None = session.scalar(
        select(Package.id).where(Package.ecosystem == ecosystem, Package.name == name)
    )
    assert existing is not None  # noqa: S101 - the conflicting row exists
    return existing


@dataclass(frozen=True)
class UpsertResult:
    advisory_id: uuid.UUID
    changed: bool


def upsert_advisory(session: Session, advisory: NormalizedAdvisory) -> UpsertResult:
    """Insert or update. Unchanged content (same hash) is a no-op, so re-ingesting the whole
    database does not trigger re-analysis of every repository."""
    existing = session.scalar(
        select(Advisory).where(
            Advisory.source == advisory.source, Advisory.source_id == advisory.source_id
        )
    )
    if existing is not None and existing.content_hash == advisory.content_hash:
        return UpsertResult(existing.id, changed=False)

    row = existing or Advisory(source=advisory.source, source_id=advisory.source_id)
    row.aliases = advisory.aliases
    row.summary = advisory.summary
    row.details = advisory.details
    row.severity = advisory.severity
    row.cvss_vector = advisory.cvss_vector
    row.cvss_score = advisory.cvss_score
    row.references = advisory.references
    row.published_at = advisory.published_at
    row.modified_at = advisory.modified_at
    row.withdrawn_at = advisory.withdrawn_at
    row.content_hash = advisory.content_hash
    row.raw = advisory.raw
    row.ingested_at = func.now()  # fan-out finds a run's changes by this timestamp
    session.add(row)
    session.flush()

    session.execute(delete(AdvisoryPackage).where(AdvisoryPackage.advisory_id == row.id))
    for affected in advisory.affected:
        package_id = ensure_package(session, affected.name)
        session.add(
            AdvisoryPackage(
                advisory_id=row.id,
                package_id=package_id,
                ranges=affected.ranges,
                versions=affected.versions,
            )
        )
        for symbol in affected.symbols:
            session.execute(
                insert(VulnerableSymbol)
                .values(
                    id=uuid.uuid4(),
                    advisory_id=row.id,
                    package_id=package_id,
                    qualified_name=symbol,
                    kind=SymbolKind.FUNCTION,
                    origin=SymbolOrigin.ADVISORY,
                )
                .on_conflict_do_nothing()
            )
    session.flush()
    return UpsertResult(row.id, changed=True)


def upsert_kev(session: Session, records: Iterable[KevRecord]) -> int:
    count = 0
    for record in records:
        values = {
            "cve_id": record.cve_id,
            "date_added": record.date_added,
            "due_date": record.due_date,
            "known_ransomware_use": record.known_ransomware_use,
            "vendor": record.vendor,
            "product": record.product,
        }
        statement = insert(KevEntry).values(**values)
        session.execute(
            statement.on_conflict_do_update(index_elements=[KevEntry.cve_id], set_=values)
        )
        count += 1
    return count


def upsert_epss(session: Session, records: Iterable[EpssRecord]) -> int:
    count = 0
    for record in records:
        values = {
            "cve_id": record.cve_id,
            "score": record.score,
            "percentile": record.percentile,
            "score_date": record.score_date,
        }
        statement = insert(EpssScore).values(**values)
        session.execute(
            statement.on_conflict_do_update(index_elements=[EpssScore.cve_id], set_=values)
        )
        count += 1
    return count
