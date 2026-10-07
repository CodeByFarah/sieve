"""The public demo: anyone can run a real scan of the project-owned sample application.

Clicks are coalesced: within one time bucket every visitor shares one real scan (and watches its
real progress), so the demo cannot be used to queue unbounded work. The demo never calls an LLM.
"""

import time

from fastapi import APIRouter, Request
from sqlalchemy import select

from sieve.api.deps import SessionDep
from sieve.api.queries import scan_out
from sieve.api.ratelimit import enforce
from sieve.api.schemas import DemoOut, DemoScanOut
from sieve.core.config import Settings
from sieve.core.errors import NotFoundError
from sieve.db.enums import AccountType
from sieve.db.models import Organization, Repository, Scan
from sieve.demo.seed import DEMO_REPOSITORY, request_demo_scan, snapshot_manifest
from sieve.symbols.registry import curated_provenance

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


@router.get("")
def demo(request: Request, session: SessionDep) -> DemoOut:
    settings: Settings = request.app.state.settings
    row = session.execute(
        select(Repository, Organization)
        .join(Organization, Organization.id == Repository.organization_id)
        .where(
            Organization.account_type == AccountType.DEMO, Repository.full_name == DEMO_REPOSITORY
        )
    ).one_or_none()
    if row is None:
        raise NotFoundError(
            "demo not seeded", public_message="The demo has not been set up on this deployment."
        )
    repository, organization = row
    latest = session.scalar(
        select(Scan)
        .where(Scan.repository_id == repository.id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return DemoOut(
        organization_login=organization.login,
        repository_id=repository.id,
        latest_scan=scan_out(latest) if latest else None,
        snapshot=snapshot_manifest(settings.demo_snapshot_dir),
        symbol_provenance=curated_provenance(),
        ai_enabled=False,
    )


@router.post("/scans", status_code=202)
def run_demo_scan(request: Request, session: SessionDep) -> DemoScanOut:
    settings: Settings = request.app.state.settings
    enforce(request, "demo_scan", limit=6, window_seconds=3600)
    bucket_seconds = max(60, 3600 // settings.demo_scans_per_hour)
    scan, created = request_demo_scan(
        session, settings, bucket=str(int(time.time() // bucket_seconds))
    )
    session.commit()
    return DemoScanOut(scan=scan_out(scan), created=created)
