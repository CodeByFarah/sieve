"""Advisory ingestion health and VEX document downloads."""

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import func, select

from sieve.api.access import ViewerDep
from sieve.api.deps import SessionDep
from sieve.api.schemas import SourceHealthOut
from sieve.core.errors import NotFoundError
from sieve.db.enums import IngestionStatus
from sieve.db.models import IngestionFailure, IngestionRun, Repository, VexDocument

router = APIRouter(prefix="/api/v1", tags=["system"])

STALE_AFTER = {"osv": timedelta(hours=26), "kev": timedelta(hours=26), "epss": timedelta(hours=50)}


@router.get("/advisories/health")
def advisory_health(session: SessionDep) -> list[SourceHealthOut]:
    """Freshness of each intelligence source. Stale data is reported, never hidden: a scan against
    week-old advisories should say so."""
    now = datetime.now(UTC)
    sources = sorted(
        set(session.scalars(select(IngestionRun.source).distinct())) | set(STALE_AFTER)
    )
    health = []
    for source in sources:
        last = session.scalar(
            select(IngestionRun)
            .where(IngestionRun.source == source)
            .order_by(IngestionRun.started_at.desc())
            .limit(1)
        )
        success = session.scalar(
            select(func.max(IngestionRun.finished_at)).where(
                IngestionRun.source == source,
                IngestionRun.status.in_([IngestionStatus.SUCCEEDED, IngestionStatus.PARTIAL]),
            )
        )
        failures = (
            session.scalar(
                select(func.count())
                .select_from(IngestionFailure)
                .where(IngestionFailure.source == source, IngestionFailure.resolved_at.is_(None))
            )
            or 0
        )
        limit = STALE_AFTER.get(source)
        health.append(
            SourceHealthOut(
                source=source,
                last_run_at=last.started_at if last else None,
                last_status=str(last.status) if last else None,
                last_success_at=success,
                records_seen=last.records_seen if last else None,
                unresolved_failures=failures,
                stale=limit is not None and (success is None or now - success > limit),
            )
        )
    return health


@router.get("/vex/{document_id}/download")
def download_vex(
    document_id: uuid.UUID, request: Request, session: SessionDep, viewer: ViewerDep
) -> Response:
    document = session.get(VexDocument, document_id)
    if document is None or document.organization_id not in viewer.roles:
        raise NotFoundError(f"vex document {document_id} not visible")
    content = request.app.state.artifacts.get(document.artifact_key, document.artifact_sha256.hex())
    repository = session.get(Repository, document.repository_id) if document.repository_id else None
    name = (
        repository.full_name.replace("/", "_") if repository else "sieve"
    ) + f".{document.format}.vex.json"
    return Response(
        content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
