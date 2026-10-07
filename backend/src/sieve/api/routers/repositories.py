"""Repositories: detail, scans, manual scans, VEX generation and preview."""

import json
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import select

from sieve.api.access import WRITERS, ViewerDep, csrf_protect, repository_for, require_role
from sieve.api.deps import SessionDep
from sieve.api.queries import repository_summaries, scan_out
from sieve.api.ratelimit import enforce
from sieve.api.schemas import PullRequestCheckOut, RepositoryOut, ScanOut, VexDocumentOut, VexIn
from sieve.core.errors import UserError
from sieve.db.enums import ActorType, RepositorySource, ScanTrigger, VexFormat
from sieve.db.models import PullRequestCheck, Scan
from sieve.runtime import tool_version
from sieve.scans.service import request_scan
from sieve.vex.service import build_document, generate_vex

router = APIRouter(prefix="/api/v1/repositories", tags=["repositories"])


@router.get("/{repository_id}")
def repository(repository_id: uuid.UUID, session: SessionDep, viewer: ViewerDep) -> RepositoryOut:
    repo, organization, _ = repository_for(session, viewer, repository_id)
    return next(r for r in repository_summaries(session, [organization.id]) if r.id == repo.id)


@router.get("/{repository_id}/scans")
def scans(
    repository_id: uuid.UUID,
    session: SessionDep,
    viewer: ViewerDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ScanOut]:
    repo, _, _ = repository_for(session, viewer, repository_id)
    rows = session.scalars(
        select(Scan)
        .where(Scan.repository_id == repo.id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    return [scan_out(scan) for scan in rows]


@router.get("/{repository_id}/pull-requests")
def pull_requests(
    repository_id: uuid.UUID, session: SessionDep, viewer: ViewerDep
) -> list[PullRequestCheckOut]:
    repo, _, _ = repository_for(session, viewer, repository_id)
    rows = session.scalars(
        select(PullRequestCheck)
        .where(PullRequestCheck.repository_id == repo.id)
        .order_by(PullRequestCheck.created_at.desc())
        .limit(50)
    ).all()
    return [PullRequestCheckOut.model_validate(row) for row in rows]


@router.post("/{repository_id}/scans", status_code=202, dependencies=[Depends(csrf_protect)])
def rescan(
    repository_id: uuid.UUID, request: Request, session: SessionDep, viewer: ViewerDep
) -> ScanOut:
    user = viewer.require_user()
    repo, _, role = repository_for(session, viewer, repository_id)
    require_role(role, WRITERS)
    enforce(request, "manual_scan", limit=10, window_seconds=600, subject=str(user.id))
    if repo.source is not RepositorySource.GITHUB or repo.latest_scan_id is None:
        raise UserError("rescan needs a GitHub repository with a previous scan")
    latest = session.get(Scan, repo.latest_scan_id)
    assert latest is not None  # noqa: S101
    scan, _ = request_scan(
        session,
        repo,
        commit_sha=latest.commit_sha,
        trigger=ScanTrigger.MANUAL,
        ref=latest.ref,
        idempotency_key=f"manual:{repo.id}:{latest.commit_sha}:{uuid.uuid4()}",
        actor_type=ActorType.USER,
        actor_id=str(user.id),
    )
    session.commit()
    return scan_out(scan)


@router.get("/{repository_id}/vex/preview")
def vex_preview(
    repository_id: uuid.UUID,
    session: SessionDep,
    viewer: ViewerDep,
    fmt: Annotated[VexFormat, Query(alias="format")] = VexFormat.OPENVEX,
) -> dict[str, Any]:
    """The document as it would be generated now. Nothing is stored. Available to every viewer,
    including demo visitors."""
    repo, _, _ = repository_for(session, viewer, repository_id)
    document, _ = build_document(
        session, repo, fmt, author="Sieve (preview, not stored)", tool=tool_version()
    )
    return document


@router.post("/{repository_id}/vex", status_code=201, dependencies=[Depends(csrf_protect)])
def create_vex(
    repository_id: uuid.UUID, body: VexIn, request: Request, session: SessionDep, viewer: ViewerDep
) -> VexDocumentOut:
    user = viewer.require_user()
    repo, organization, role = repository_for(session, viewer, repository_id)
    require_role(role, WRITERS)
    row, _ = generate_vex(
        session,
        artifacts=request.app.state.artifacts,
        organization_id=organization.id,
        repository_id=repo.id,
        fmt=body.format,
        author=user.login,
        user_id=user.id,
    )
    session.commit()
    return VexDocumentOut(
        id=row.id,
        format=row.format,
        repository_id=repo.id,
        repository_full_name=repo.full_name,
        statement_count=row.statement_count,
        sha256=row.artifact_sha256.hex(),
        created_at=row.created_at,
    )


def json_attachment(document: Any, filename: str) -> Response:
    return Response(
        json.dumps(document, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
