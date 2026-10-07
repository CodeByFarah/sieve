"""Generating a VEX document for a repository from its current findings."""

import hashlib
import json
import uuid
from datetime import UTC, datetime
from importlib.metadata import version
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.audit.log import record_event
from sieve.core.errors import NotFoundError, SieveError
from sieve.db.enums import ActorType, Presence, ReviewState, VexFormat, VexStatus
from sieve.db.models import Advisory, Finding, Package, Repository, Scan, VexDocument
from sieve.findings.service import REVIEWED
from sieve.sbom.models import pypi_purl
from sieve.schemas import cyclonedx_errors, openvex_errors
from sieve.storage.artifacts import ArtifactStore
from sieve.vex.documents import Statement, Subject, build_cyclonedx_vex, build_openvex


class VexSchemaViolation(SieveError):
    code = "vex_schema_violation"


def _detail(finding: Finding, status: VexStatus) -> str:
    if status is VexStatus.UNDER_INVESTIGATION:
        if finding.review_state in REVIEWED or finding.review_state is ReviewState.STALE:
            return "A previous review no longer matches the latest analysis; awaiting re-review."
        return f"Not yet reviewed. Sieve's analysis verdict: {finding.verdict or 'pending'}."
    if status is VexStatus.NOT_AFFECTED:
        return (
            "Reviewed: the vulnerable code is not reachable from the application's "
            "analysed execution paths."
        )
    if status is VexStatus.AFFECTED:
        return (
            "Reviewed: a reachable application path terminates at the vulnerable code. "
            "Upgrade the package."
        )
    return "Reviewed: fixed."


def statement_for(finding: Finding, advisory: Advisory, package: Package) -> Statement:
    """Unreviewed findings are always ``under_investigation``: a definitive status needs a human."""
    reviewed = finding.review_state in REVIEWED and finding.vex_status is not None
    status = (
        finding.vex_status if reviewed and finding.vex_status else VexStatus.UNDER_INVESTIGATION
    )
    return Statement(
        vulnerability=advisory.source_id,
        aliases=tuple(advisory.aliases),
        package_purl=pypi_purl(package.name, finding.installed_version),
        status=status,
        justification=finding.vex_justification if status is VexStatus.NOT_AFFECTED else None,
        detail=_detail(finding, status),
        severity=str(advisory.severity),
        cvss_score=advisory.cvss_score,
        cvss_vector=advisory.cvss_vector,
        source_url=f"https://osv.dev/vulnerability/{advisory.source_id}",
    )


def statements_for(session: Session, repository: Repository) -> list[Statement]:
    rows = session.execute(
        select(Finding, Advisory, Package)
        .join(Advisory, Advisory.id == Finding.advisory_id)
        .join(Package, Package.id == Finding.package_id)
        .where(Finding.repository_id == repository.id, Finding.presence == Presence.PRESENT)
    ).all()
    return [statement_for(finding, advisory, package) for finding, advisory, package in rows]


def build_document(
    session: Session, repository: Repository, fmt: VexFormat, *, author: str, tool: str
) -> tuple[dict[str, Any], list[Statement]]:
    """Build and schema-validate a document from the repository's current findings."""
    if repository.latest_scan_id is None:
        raise NotFoundError("repository has no completed scan")
    scan = session.get(Scan, repository.latest_scan_id)
    assert scan is not None  # noqa: S101
    subject = Subject(repository.full_name, scan.commit_sha, author)
    statements = statements_for(session, repository)
    now = datetime.now(UTC)
    if fmt is VexFormat.OPENVEX:
        document = build_openvex(subject, statements, now, tool)
        errors = openvex_errors(document)
    else:
        document = build_cyclonedx_vex(subject, statements, now, tool)
        errors = cyclonedx_errors(document)
    if errors:
        raise VexSchemaViolation(f"generated {fmt} document failed schema validation: {errors[:3]}")
    return document, statements


def generate_vex(
    session: Session,
    *,
    artifacts: ArtifactStore,
    organization_id: uuid.UUID,
    repository_id: uuid.UUID,
    fmt: VexFormat,
    author: str,
    user_id: uuid.UUID | None,
) -> tuple[VexDocument, bytes]:
    repository = session.scalar(
        select(Repository).where(
            Repository.id == repository_id, Repository.organization_id == organization_id
        )
    )
    if repository is None:
        raise NotFoundError("repository not found")
    document, statements = build_document(
        session, repository, fmt, author=author, tool=version("sieve")
    )
    content = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    row_id = uuid.uuid4()
    key = f"org/{organization_id}/vex/{row_id}.{fmt}.json"
    digest = artifacts.put(key, content, "application/json")
    row = VexDocument(
        id=row_id,
        organization_id=organization_id,
        repository_id=repository.id,
        format=fmt,
        artifact_key=key,
        artifact_sha256=bytes.fromhex(digest),
        statement_count=len(statements),
        schema_valid=True,
        generated_by=user_id,
    )
    session.add(row)
    session.flush()
    record_event(
        session,
        action="vex.generated",
        actor_type=ActorType.USER if user_id else ActorType.SYSTEM,
        actor_id=str(user_id) if user_id else None,
        organization_id=organization_id,
        target_type="vex_document",
        target_id=str(row.id),
        data={
            "format": str(fmt),
            "repository": repository.full_name,
            "statements": len(statements),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
    )
    return row, content
