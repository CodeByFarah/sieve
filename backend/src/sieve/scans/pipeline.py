"""The scan pipeline (architecture §4).

Each stage records its start, end and counts on the ``scans`` row in its own transaction, so the
progress a user sees is the pipeline's actual state, and a crash leaves an accurate record of how
far the scan got. Stages are idempotent (upserts keyed by natural keys), so a retried job simply
runs the scan again.
"""

import json
import time
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.store import ensure_package
from sieve.analysis.engine import DependencyPin, EngineResult, ReachabilityEngine
from sieve.analysis.reachability import Outcome, decide
from sieve.audit.log import record_event
from sieve.core.errors import SieveError
from sieve.core.logging import get_logger
from sieve.core.telemetry import SCAN_STAGE_DURATION, SCANS, VERDICTS, tracer
from sieve.core.workspace import Workspace
from sieve.db.enums import AccountType, ActorType, ScanStatus, ScanTrigger
from sieve.db.models import (
    Advisory,
    Dependency,
    Finding,
    Organization,
    Package,
    Repository,
    Scan,
    ScanManifest,
)
from sieve.db.session import transaction
from sieve.findings.matching import match_scan
from sieve.findings.service import apply_outcome, rescore, resolve_missing, upsert_findings
from sieve.sbom.cyclonedx import SbomSubject, build_cyclonedx
from sieve.sbom.inventory import SKIP_DIRS, build_inventory
from sieve.sbom.models import Inventory
from sieve.scans.pull_requests import PullRequestFlow
from sieve.scans.service import ANALYZER_VERSION
from sieve.scans.workspaces import WorkspaceProvider
from sieve.schemas import cyclonedx_errors
from sieve.storage.artifacts import ArtifactStore
from sieve.symbols.registry import as_inputs, record_verification, seed_curated_symbols, symbols_for

log = get_logger(__name__)

STAGES = (
    "fetch",
    "inventory",
    "sbom",
    "match",
    "symbols",
    "callgraph",
    "reachability",
    "score",
    "report",
)
SNIPPET_CONTEXT = 3


class SbomInvalid(SieveError):
    code = "sbom_invalid"


@dataclass
class PipelineDeps:
    session_factory: sessionmaker[Session]
    workspaces: Callable[[Repository], WorkspaceProvider]
    engine: ReachabilityEngine
    artifacts: ArtifactStore
    tool_version: str
    on_symbols_missing: Callable[[Session, Finding], None] | None = None


@dataclass(frozen=True)
class _FindingKey:
    finding_id: uuid.UUID
    group_advisory_ids: tuple[uuid.UUID, ...]
    package_id: uuid.UUID
    package_name: str
    version: str | None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _snippet(root: Path, path: str, line: int) -> dict[str, Any] | None:
    text = Workspace(root).read_text(path) if line > 0 else None
    if text is None:
        return None
    lines = text.splitlines()
    start = max(1, line - SNIPPET_CONTEXT)
    end = min(len(lines), line + SNIPPET_CONTEXT)
    return {
        "start": start,
        "highlight": line,
        "lines": [text[:300] for text in lines[start - 1 : end]],
    }


def _latest_created(session: Session, repository: Repository) -> datetime:
    """A slow, older scan finishing late must not replace a newer scan as the repository's
    latest."""
    if repository.latest_scan_id is None:
        return datetime.min.replace(tzinfo=UTC)
    current = session.get(Scan, repository.latest_scan_id)
    return current.created_at if current else datetime.min.replace(tzinfo=UTC)


def attach_snippets(outcome: Outcome, app_root: Path, source_roots: dict[str, Path]) -> None:
    """Evidence shows code, not just names: the calling line in application code, and the
    definition of each dependency function on the path."""
    for path in outcome.paths:
        for step in path["steps"]:
            if step["package"] is None:
                anchor = step["call"]["line"] if step["call"] else step["line"]
                step["snippet"] = _snippet(app_root, step["file"], anchor)
            elif step["package"] in source_roots and step["kind"] != "module":
                step["snippet"] = _snippet(
                    source_roots[step["package"]], step["file"], step["line"]
                )


class ScanPipeline:
    def __init__(self, deps: PipelineDeps) -> None:
        self.deps = deps

    # ------------------------------------------------------------------ progress

    def _update(self, scan_id: uuid.UUID, mutate: Callable[[Scan], None]) -> None:
        with transaction(self.deps.session_factory) as session:
            scan = session.get(Scan, scan_id, with_for_update=True)
            assert scan is not None  # noqa: S101
            mutate(scan)

    @contextmanager
    def _stage(self, scan_id: uuid.UUID, name: str) -> Iterator[dict[str, Any]]:
        started = time.perf_counter()
        counts: dict[str, Any] = {}

        def begin(scan: Scan) -> None:
            scan.stage = name
            scan.progress = {**scan.progress, name: {"status": "running", "started_at": _now()}}

        self._update(scan_id, begin)
        try:
            with tracer.start_as_current_span(f"scan.{name}", attributes={"scan.id": str(scan_id)}):
                yield counts
        except BaseException:
            self._update(
                scan_id,
                lambda scan: setattr(
                    scan,
                    "progress",
                    {
                        **scan.progress,
                        name: {**scan.progress[name], "status": "failed", "finished_at": _now()},
                    },
                ),
            )
            raise

        def finish(scan: Scan) -> None:
            entry = {
                **scan.progress[name],
                "status": "done",
                "finished_at": _now(),
                "duration_seconds": round(time.perf_counter() - started, 3),
                "counts": counts,
            }
            scan.progress = {**scan.progress, name: entry}

        self._update(scan_id, finish)
        SCAN_STAGE_DURATION.record(time.perf_counter() - started, {"stage": name})

    # ------------------------------------------------------------------ run

    def run(self, scan_id: uuid.UUID) -> None:
        with transaction(self.deps.session_factory) as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise SieveError(f"scan {scan_id} does not exist")
            if scan.status is ScanStatus.SUCCEEDED:
                return  # duplicate delivery of an already-finished job
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(UTC)
            scan.progress = {}
            scan.error_code = scan.error_message = None
        try:
            self._execute(scan_id)
        except SieveError as exc:
            self._failed(scan_id, exc.code, exc.public_message, retrying=exc.retryable)
            raise
        except Exception:
            self._failed(
                scan_id, "internal_error", SieveError.default_public_message, retrying=False
            )
            raise

    def _failed(self, scan_id: uuid.UUID, code: str, message: str, *, retrying: bool) -> None:
        def mark(scan: Scan) -> None:
            scan.status = ScanStatus.QUEUED if retrying else ScanStatus.FAILED
            scan.error_code = code
            scan.error_message = message
            if not retrying:
                scan.finished_at = datetime.now(UTC)

        self._update(scan_id, mark)
        SCANS.add(1, {"status": "retrying" if retrying else "failed", "error_code": code})
        with transaction(self.deps.session_factory) as session:
            scan = session.get(Scan, scan_id)
            assert scan is not None  # noqa: S101
            record_event(
                session,
                action="scan.retrying" if retrying else "scan.failed",
                actor_type=ActorType.SYSTEM,
                organization_id=scan.organization_id,
                target_type="scan",
                target_id=str(scan_id),
                data={"error_code": code},
            )

    def _execute(self, scan_id: uuid.UUID) -> None:
        factory = self.deps.session_factory
        with factory() as session:
            scan = session.get(Scan, scan_id)
            repository = session.get(Repository, scan.repository_id) if scan else None
            assert scan is not None and repository is not None  # noqa: S101
            organization = session.get(Organization, repository.organization_id)
            # The public demo never spends model budget, whatever triggered the scan.
            ask_model = (
                organization is not None and organization.account_type is not AccountType.DEMO
            )
            session.expunge_all()

        with self.deps.workspaces(repository).checkout(repository, scan) as root:
            workspace = Workspace(root)
            with self._stage(scan_id, "fetch") as counts:
                counts["files"] = sum(1 for _ in workspace.iter_files(skip_dirs=SKIP_DIRS))

            with self._stage(scan_id, "inventory") as counts:
                inventory = build_inventory(workspace)
                self._persist_inventory(scan, inventory)
                counts.update(
                    manifests=len(inventory.manifests),
                    unsupported_manifests=sum(
                        1 for m in inventory.manifests if m.status != "parsed"
                    ),
                    dependencies=len(inventory.dependencies),
                    pinned=inventory.pinned_count,
                )

            with self._stage(scan_id, "sbom") as counts:
                counts["components"] = self._sbom(scan, repository, inventory)

            if scan.trigger is ScanTrigger.PULL_REQUEST:
                # A PR scan must not change the repository's findings: evaluate in memory and
                # record only the check summary.
                PullRequestFlow(self, scan, workspace, inventory).run()
                return

            with self._stage(scan_id, "match") as counts:
                keys, resolved = self._match(scan)
                counts.update(findings=len(keys), resolved=resolved)

            with self._stage(scan_id, "symbols") as counts:
                counts.update(self._symbols(keys, ask_model=ask_model))

            result = self.callgraph(scan_id, workspace, inventory)

            with self._stage(scan_id, "reachability") as counts:
                verdicts = self._reachability(scan, keys, result, root)
                counts.update(verdicts)

        with self._stage(scan_id, "score") as counts:
            counts["scored"] = self._score(keys)

        with self._stage(scan_id, "report") as counts:
            counts.update(verdicts)
        # Last, and outside the stage: anyone who sees "succeeded" must also see every stage closed.
        self._report(scan_id, verdicts, len(keys))

    # ------------------------------------------------------------------ stages

    def stage(self, scan_id: uuid.UUID, name: str) -> AbstractContextManager[dict[str, Any]]:
        return self._stage(scan_id, name)

    def callgraph(
        self, scan_id: uuid.UUID, workspace: Workspace, inventory: Inventory
    ) -> EngineResult:
        with self._stage(scan_id, "callgraph") as counts:
            pins = [DependencyPin(d.name, d.version) for d in inventory.dependencies]
            result = self.deps.engine.analyze(workspace, pins)
            counts.update(
                app_modules=result.stats.app_modules,
                excluded_files=result.stats.app_files_excluded,
                dependency_modules=result.stats.dependency_modules,
                distributions_indexed=result.stats.distributions_indexed,
                distributions_unavailable=result.stats.distributions_unavailable,
                nodes=result.stats.nodes,
                edges=result.stats.edges,
                unresolved_calls=result.stats.unresolved_calls,
                timings=result.stats.timings,
            )
        return result

    def _persist_inventory(self, scan: Scan, inventory: Inventory) -> None:
        with transaction(self.deps.session_factory) as session:
            for manifest in inventory.manifests:
                session.add(
                    ScanManifest(
                        scan_id=scan.id,
                        path=manifest.path[:1024],
                        format=manifest.format,
                        status=manifest.status,
                        detail=manifest.detail,
                    )
                )
            for dependency in inventory.dependencies:
                session.add(
                    Dependency(
                        scan_id=scan.id,
                        package_id=ensure_package(session, dependency.name),
                        version=dependency.version,
                        constraint_spec=dependency.constraint,
                        is_direct=dependency.is_direct,
                        manifest_path=dependency.manifest_path[:1024],
                        purl=dependency.purl,
                    )
                )

    def _sbom(self, scan: Scan, repository: Repository, inventory: Inventory) -> int:
        subject = SbomSubject(repository.full_name, scan.commit_sha, self.deps.tool_version)
        content = build_cyclonedx(inventory, subject, scan.created_at)
        errors = cyclonedx_errors(json.loads(content))
        if errors:
            raise SbomInvalid(f"generated SBOM failed schema validation: {errors[:3]}")
        key = f"org/{scan.organization_id}/scans/{scan.id}/sbom.cdx.json"
        digest = self.deps.artifacts.put(key, content, "application/vnd.cyclonedx+json")

        def store(row: Scan) -> None:
            row.sbom_key = key
            row.sbom_sha256 = bytes.fromhex(digest)

        self._update(scan.id, store)
        return len(inventory.dependencies)

    def _match(self, scan: Scan) -> tuple[list[_FindingKey], int]:
        with transaction(self.deps.session_factory) as session:
            fresh = session.get(Scan, scan.id)
            assert fresh is not None  # noqa: S101
            matches = match_scan(session, scan.id)
            ids = upsert_findings(session, fresh, matches)
            resolved = resolve_missing(session, fresh, ids)
            names = dict(session.execute(select(Package.id, Package.name)).all())
            keys = [
                _FindingKey(
                    finding_id,
                    m.group_advisory_ids,
                    m.dependency.package_id,
                    names[m.dependency.package_id],
                    m.dependency.version,
                )
                for finding_id, m in zip(ids, matches, strict=True)
            ]
        return keys, resolved

    def _symbols(self, keys: list[_FindingKey], *, ask_model: bool) -> dict[str, int]:
        with transaction(self.deps.session_factory) as session:
            seed_curated_symbols(session)
            with_symbols = 0
            for key in keys:
                if symbols_for(session, key.group_advisory_ids, key.package_id):
                    with_symbols += 1
                elif ask_model and self.deps.on_symbols_missing is not None:
                    finding = session.get(Finding, key.finding_id)
                    assert finding is not None  # noqa: S101
                    self.deps.on_symbols_missing(session, finding)
        return {"with_symbols": with_symbols, "without_symbols": len(keys) - with_symbols}

    def _reachability(
        self, scan: Scan, keys: list[_FindingKey], result: EngineResult, root: Path
    ) -> dict[str, int]:
        verdicts: Counter[str] = Counter()
        with transaction(self.deps.session_factory) as session:
            fresh = session.get(Scan, scan.id)
            assert fresh is not None  # noqa: S101
            for key in keys:
                rows = symbols_for(session, key.group_advisory_ids, key.package_id)
                outcome = decide(result.context, key.package_name, as_inputs(rows))
                attach_snippets(outcome, root, result.source_roots)
                record_verification(rows, outcome.symbols, key.package_name, key.version)
                finding = session.get(Finding, key.finding_id)
                assert finding is not None  # noqa: S101
                apply_outcome(
                    session,
                    finding,
                    fresh,
                    outcome,
                    analyzer_version=ANALYZER_VERSION,
                    stats={"engine": result.stats.timings, "symbols": len(rows)},
                )
                verdicts[str(outcome.verdict)] += 1
        return dict(verdicts)

    def _score(self, keys: list[_FindingKey]) -> int:
        with transaction(self.deps.session_factory) as session:
            for key in keys:
                finding = session.get(Finding, key.finding_id)
                assert finding is not None  # noqa: S101
                advisory = session.get(Advisory, finding.advisory_id)
                assert advisory is not None  # noqa: S101
                rescore(session, finding, advisory)
        return len(keys)

    def _report(self, scan_id: uuid.UUID, verdicts: dict[str, int], findings: int) -> None:
        with transaction(self.deps.session_factory) as session:
            scan = session.get(Scan, scan_id, with_for_update=True)
            assert scan is not None  # noqa: S101
            repository = session.get(Repository, scan.repository_id)
            assert repository is not None  # noqa: S101
            scan.status = ScanStatus.SUCCEEDED
            scan.finished_at = datetime.now(UTC)
            scan.stats = {"findings": findings, "verdicts": verdicts}
            if scan.created_at >= _latest_created(session, repository):
                repository.latest_scan_id = scan.id
            record_event(
                session,
                action="scan.completed",
                actor_type=ActorType.SYSTEM,
                organization_id=scan.organization_id,
                target_type="scan",
                target_id=str(scan.id),
                data={"findings": findings, "verdicts": verdicts},
            )
        SCANS.add(1, {"status": "succeeded"})
        for verdict, count in verdicts.items():
            VERDICTS.add(count, {"verdict": verdict})
        log.info("scan.completed", scan_id=str(scan_id), findings=findings, verdicts=verdicts)
