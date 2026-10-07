"""The public demo tenant: a demo organization, the sample repository, and the recorded advisory
snapshot it is scanned against.

    python -m sieve.demo.seed     # idempotent: safe to run on every deploy
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.feeds import parse_epss, parse_kev
from sieve.advisories.ingest import ingest_osv_records, load_snapshot
from sieve.advisories.store import upsert_epss, upsert_kev
from sieve.core.config import Settings, get_settings
from sieve.core.errors import TransientError
from sieve.core.logging import configure_logging, get_logger
from sieve.db.enums import (
    AccountType,
    AnalysisState,
    Presence,
    RepositorySource,
    ReviewState,
    ScanTrigger,
    Verdict,
    VexJustification,
    VexStatus,
)
from sieve.db.models import Advisory, Finding, Organization, Repository, Scan, User
from sieve.db.session import create_db_engine, create_session_factory, transaction
from sieve.reviews.service import ReviewRequest, record_review
from sieve.scans.service import ANALYZER_VERSION, request_scan
from sieve.scans.workspaces import tree_digest

log = get_logger(__name__)

DEMO_ORG_LOGIN = "sieve-demo"
DEMO_REPOSITORY = "sieve-demo/acme-config"
SNAPSHOT_SOURCE = "osv-demo-snapshot"
# The maintainers' reviewer identity on the demo has no GitHub account; -1 can never collide
# with a real GitHub user id.
MAINTAINERS_GITHUB_ID = -1


def ensure_demo_repository(session: Session) -> Repository:
    organization = session.scalar(
        select(Organization).where(Organization.account_type == AccountType.DEMO)
    )
    if organization is None:
        organization = Organization(login=DEMO_ORG_LOGIN, account_type=AccountType.DEMO)
        session.add(organization)
        session.flush()
    repository = session.scalar(
        select(Repository).where(
            Repository.organization_id == organization.id, Repository.full_name == DEMO_REPOSITORY
        )
    )
    if repository is None:
        repository = Repository(
            organization_id=organization.id,
            source=RepositorySource.DEMO,
            full_name=DEMO_REPOSITORY,
            default_branch="main",
        )
        session.add(repository)
        session.flush()
    return repository


def snapshot_manifest(snapshot_dir: Path) -> dict[str, Any]:
    manifest: dict[str, Any] = json.loads((snapshot_dir / "manifest.json").read_text("utf-8"))
    return manifest


def load_demo_snapshot(factory: sessionmaker[Session], snapshot_dir: Path) -> dict[str, Any]:
    outcome = ingest_osv_records(
        factory, load_snapshot(snapshot_dir / "osv"), source=SNAPSHOT_SOURCE
    )
    kev = parse_kev(json.loads((snapshot_dir / "kev.json").read_text("utf-8")))
    epss = parse_epss(json.loads((snapshot_dir / "epss.json").read_text("utf-8")))
    with transaction(factory) as session:
        upsert_kev(session, kev)
        upsert_epss(session, epss)
    return {"advisories_changed": outcome.changed, "kev": len(kev), "epss": len(epss)}


def request_demo_scan(session: Session, settings: Settings, *, bucket: str) -> tuple[Scan, bool]:
    """``bucket`` coalesces demo clicks: every visitor within one bucket shares one real scan."""
    repository = ensure_demo_repository(session)
    commit = tree_digest(settings.demo_app_dir)
    return request_scan(
        session,
        repository,
        commit_sha=commit,
        trigger=ScanTrigger.DEMO,
        ref="main",
        idempotency_key=f"demo:{commit}:{ANALYZER_VERSION}:{bucket}",
        priority=10,
    )


class DemoNotAnalysedYet(TransientError):
    code = "demo_not_analysed"


def _maintainers(session: Session, login: str) -> User:
    user = session.scalar(select(User).where(User.github_user_id == MAINTAINERS_GITHUB_ID))
    if user is None:
        user = User(github_user_id=MAINTAINERS_GITHUB_ID, login=login, name="Sieve maintainers")
        session.add(user)
        session.flush()
    return user


def apply_demo_reviews(session: Session, reviews_file: Path) -> int:
    """Apply the maintainers' recorded decisions to demo findings that are not yet reviewed.
    Raises a transient error (so the job retries) while the demo scan is still running."""
    data: dict[str, Any] = json.loads(reviews_file.read_text("utf-8"))
    repository = ensure_demo_repository(session)
    reviewer = _maintainers(session, data["reviewer"])
    applied = 0
    for decision in data["decisions"]:
        advisory_id = decision["advisory"]
        finding = session.scalar(
            select(Finding)
            .join(Advisory, Advisory.id == Finding.advisory_id)
            .where(
                Finding.repository_id == repository.id,
                Finding.presence == Presence.PRESENT,
                (Advisory.source_id == advisory_id) | Advisory.aliases.any(advisory_id),
            )
        )
        if finding is None:
            continue
        if finding.analysis_state is not AnalysisState.ANALYZED:
            raise DemoNotAnalysedYet(f"demo finding for {advisory_id} not analysed yet")
        if finding.review_state in (ReviewState.ACCEPTED, ReviewState.OVERRIDDEN):
            continue
        justification = decision.get("justification")
        record_review(
            session,
            ReviewRequest(
                finding_id=finding.id,
                organization_id=finding.organization_id,
                reviewer_id=reviewer.id,
                expected_version=finding.version,
                decided_verdict=Verdict(decision["decided_verdict"]),
                vex_status=VexStatus(decision["vex_status"]),
                justification=VexJustification(justification) if justification else None,
                comment=decision.get("comment"),
            ),
        )
        applied += 1
    return applied


def main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, json=settings.log_json)
    engine = create_db_engine(settings)
    factory = create_session_factory(engine)
    loaded = load_demo_snapshot(factory, settings.demo_snapshot_dir)
    with transaction(factory) as session:
        scan, created = request_demo_scan(
            session, settings, bucket=f"seed-{datetime.now(UTC).date()}"
        )
    log.info("demo.seeded", scan_id=str(scan.id), scan_created=created, **loaded)
    engine.dispose()


if __name__ == "__main__":
    main()
