"""Scans: detail, live progress (Server-Sent Events) and SBOM download."""

import asyncio
import hashlib
import json
import uuid
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sieve.api.access import ViewerDep, repository_for
from sieve.api.deps import SessionDep
from sieve.api.schemas import ManifestOut, ScanDetailOut, ScanOut
from sieve.core.errors import NotFoundError
from sieve.db.enums import ScanStatus
from sieve.db.models import Repository, Scan, ScanManifest
from sieve.scans.pipeline import STAGES

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

POLL_SECONDS = 1.0
HEARTBEAT_SECONDS = 15.0
MAX_STREAM_SECONDS = 15 * 60
TERMINAL = frozenset({ScanStatus.SUCCEEDED, ScanStatus.FAILED, ScanStatus.CANCELLED})


def _visible_scan(
    session: Session, viewer: ViewerDep, scan_id: uuid.UUID
) -> tuple[Scan, Repository]:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise NotFoundError(f"scan {scan_id} not visible")
    repository, _, _ = repository_for(session, viewer, scan.repository_id)
    return scan, repository


def _detail(session: Session, scan: Scan, repository: Repository) -> ScanDetailOut:
    manifests = session.scalars(
        select(ScanManifest).where(ScanManifest.scan_id == scan.id).order_by(ScanManifest.path)
    ).all()
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        progress=scan.progress,
        stages=list(STAGES),
        repository_full_name=repository.full_name,
        sbom_available=scan.sbom_key is not None,
        manifests=[ManifestOut.model_validate(m) for m in manifests],
    )


@router.get("/{scan_id}")
def scan_detail(scan_id: uuid.UUID, session: SessionDep, viewer: ViewerDep) -> ScanDetailOut:
    scan, repository = _visible_scan(session, viewer, scan_id)
    return _detail(session, scan, repository)


@router.get("/{scan_id}/events", response_class=StreamingResponse)
async def scan_events(
    scan_id: uuid.UUID, request: Request, session: SessionDep, viewer: ViewerDep
) -> StreamingResponse:
    """Live scan progress. Each event is a read of the scan row — the pipeline's own record —
    so the stream can never show progress that did not happen."""
    _visible_scan(session, viewer, scan_id)  # authorisation, once, before streaming
    factory: sessionmaker[Session] = request.app.state.session_factory

    def load() -> tuple[str, bool]:
        with factory() as fresh:
            scan = fresh.get(Scan, scan_id)
            repository = fresh.get(Repository, scan.repository_id) if scan else None
            assert scan is not None and repository is not None  # noqa: S101
            payload = _detail(fresh, scan, repository).model_dump_json()
            return payload, scan.status in TERMINAL

    async def stream() -> AsyncIterator[str]:
        last_digest = ""
        elapsed = 0.0
        since_beat = 0.0
        while elapsed < MAX_STREAM_SECONDS and not await request.is_disconnected():
            payload, finished = await run_in_threadpool(load)
            digest = hashlib.sha256(payload.encode()).hexdigest()
            if digest != last_digest:
                last_digest = digest
                since_beat = 0.0
                yield f"event: scan\ndata: {payload}\n\n"
            elif since_beat >= HEARTBEAT_SECONDS:
                since_beat = 0.0
                yield ": keep-alive\n\n"
            if finished:
                yield f"event: done\ndata: {json.dumps({'scan_id': str(scan_id)})}\n\n"
                return
            await asyncio.sleep(POLL_SECONDS)
            elapsed += POLL_SECONDS
            since_beat += POLL_SECONDS

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{scan_id}/sbom")
def sbom(scan_id: uuid.UUID, request: Request, session: SessionDep, viewer: ViewerDep) -> Response:
    scan, repository = _visible_scan(session, viewer, scan_id)
    if scan.sbom_key is None or scan.sbom_sha256 is None:
        raise NotFoundError("this scan has no SBOM yet")
    content = request.app.state.artifacts.get(scan.sbom_key, scan.sbom_sha256.hex())
    filename = f"{repository.full_name.replace('/', '_')}-{scan.commit_sha[:12]}.cdx.json"
    return Response(
        content,
        media_type="application/vnd.cyclonedx+json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
