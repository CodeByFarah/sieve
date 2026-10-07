"""End to end on a real database: request → pipeline → findings → review → VEX → rescan."""

import dataclasses
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from sieve.advisories.fanout import fan_out
from sieve.advisories.ingest import ingest_osv_records, load_snapshot
from sieve.analysis.engine import ReachabilityEngine
from sieve.analysis.sandbox import InProcessIndexer
from sieve.audit.log import verify_chain
from sieve.core.errors import ConflictError
from sieve.db.enums import (
    AccountType,
    Confidence,
    Presence,
    RepositorySource,
    ReviewState,
    ScanStatus,
    ScanTrigger,
    Verdict,
    VexFormat,
    VexJustification,
    VexStatus,
)
from sieve.db.models import (
    AnalysisResult,
    Finding,
    Organization,
    ReachabilityPath,
    Repository,
    Scan,
    User,
)
from sieve.db.session import transaction
from sieve.reviews.service import InvalidReview, ReviewRequest, record_review
from sieve.scans.pipeline import STAGES, PipelineDeps, ScanPipeline
from sieve.scans.service import request_scan
from sieve.scans.workspaces import DirectoryWorkspaces, WorkspaceProvider
from sieve.schemas import cyclonedx_errors, openvex_errors
from sieve.storage.artifacts import FilesystemArtifactStore
from sieve.vex.service import generate_vex
from tests.unit.test_reachability import YAML_DIST, FakeSources, write_tree

FIXTURES = Path(__file__).parent.parent / "fixtures" / "osv"

REQUESTS_DIST = {
    "requests/__init__.py": "from .api import get\n",
    "requests/api.py": "from .sessions import Session\n\ndef get(url):\n    return Session().request('GET', url)\n",
    "requests/sessions.py": (
        "class SessionRedirectMixin:\n"
        "    def rebuild_auth(self, prepared, response):\n        return prepared\n\n"
        "class Session(SessionRedirectMixin):\n"
        "    def request(self, method, url):\n        return url\n"
    ),
}
APP = {
    "requirements.txt": "PyYAML==5.3\nrequests==2.19.1\n",
    "svc/__init__.py": "",
    "svc/web.py": (
        "import requests\nimport yaml\n\n"
        "def upload(body):\n    return yaml.load(body)\n\n"
        "def ping(url):\n    return requests.get(url)\n"
    ),
}


@pytest.fixture
def repository(session: Session) -> Repository:
    organization = Organization(login="acme", account_type=AccountType.DEMO)
    session.add(organization)
    session.flush()
    repo = Repository(
        organization_id=organization.id,
        source=RepositorySource.DEMO,
        full_name="acme/svc",
        default_branch="main",
    )
    session.add(repo)
    session.commit()
    return repo


@pytest.fixture
def reviewer(session: Session) -> User:
    user = User(github_user_id=1, login="alex")
    session.add(user)
    session.commit()
    return user


def make_pipeline(
    factory: sessionmaker[Session], tmp_path: Path, app: dict[str, str]
) -> tuple[ScanPipeline, FilesystemArtifactStore]:
    root = write_tree(tmp_path / "app", app)
    workspaces = DirectoryWorkspaces(root)
    artifacts = FilesystemArtifactStore(tmp_path / "artifacts")
    sources = FakeSources(tmp_path / "dists", {"pyyaml": YAML_DIST, "requests": REQUESTS_DIST})
    select_provider: Callable[[Repository], WorkspaceProvider] = lambda _repo: workspaces  # noqa: E731
    deps = PipelineDeps(
        session_factory=factory,
        workspaces=select_provider,
        engine=ReachabilityEngine(sources, InProcessIndexer()),
        artifacts=artifacts,
        tool_version="test",
    )
    return ScanPipeline(deps), artifacts


def scan_once(
    factory: sessionmaker[Session], pipeline: ScanPipeline, repository: Repository, sha: str
) -> Scan:
    with transaction(factory) as session:
        repo = session.get(Repository, repository.id)
        assert repo is not None
        scan, _ = request_scan(session, repo, commit_sha=sha, trigger=ScanTrigger.MANUAL)
    pipeline.run(scan.id)
    with factory() as session:
        result = session.get(Scan, scan.id)
        assert result is not None
        return result


def findings_by_package(session: Session, repository: Repository) -> dict[str, Finding]:
    from sieve.db.models import Package

    rows = session.execute(
        select(Package.name, Finding)
        .join(Finding, Finding.package_id == Package.id)
        .where(Finding.repository_id == repository.id)
    ).all()
    return {name: finding for name, finding in rows}  # noqa: C416 - Row tuples


def test_full_workflow(
    session_factory: sessionmaker[Session],
    session: Session,
    repository: Repository,
    reviewer: User,
    tmp_path: Path,
) -> None:
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    pipeline, artifacts = make_pipeline(session_factory, tmp_path, APP)

    scan = scan_once(session_factory, pipeline, repository, "a" * 40)

    # Scan: every stage ran and recorded itself.
    assert scan.status is ScanStatus.SUCCEEDED
    assert [scan.progress[stage]["status"] for stage in STAGES] == ["done"] * len(STAGES)
    assert scan.progress["inventory"]["counts"]["dependencies"] == 2
    assert scan.stats["verdicts"] == {"reachable": 1, "not_reached": 1}
    sbom = json.loads(artifacts.get(scan.sbom_key or "", (scan.sbom_sha256 or b"").hex()))
    assert cyclonedx_errors(sbom) == []

    # Findings: GHSA and PYSEC records of the same PyYAML vulnerability became one finding.
    session.expire_all()
    findings = findings_by_package(session, repository)
    assert set(findings) == {"pyyaml", "requests"}
    pyyaml, requests_finding = findings["pyyaml"], findings["requests"]
    assert pyyaml.verdict is Verdict.REACHABLE
    assert pyyaml.confidence is Confidence.HIGH
    assert pyyaml.risk_score is not None
    assert pyyaml.risk_breakdown["reachability"]["factor"] == "1.0"
    assert requests_finding.verdict is Verdict.NOT_REACHED

    analysis = session.get(AnalysisResult, pyyaml.latest_analysis_id)
    assert analysis is not None
    path = session.scalars(
        select(ReachabilityPath).where(ReachabilityPath.analysis_result_id == analysis.id)
    ).one()
    first = path.steps[0]
    assert first["symbol"] == "svc.web.upload"
    assert first["snippet"]["highlight"] == 5
    assert "yaml.load(body)" in "\n".join(first["snippet"]["lines"])

    # Review: optimistic locking and VEX consistency rules.
    request = ReviewRequest(
        finding_id=pyyaml.id,
        organization_id=pyyaml.organization_id,
        reviewer_id=reviewer.id,
        expected_version=pyyaml.version,
        decided_verdict=Verdict.REACHABLE,
        vex_status=VexStatus.AFFECTED,
        justification=None,
        comment="Confirmed: uploads are parsed with FullLoader.",
    )
    with pytest.raises(ConflictError):
        record_review(
            session, ReviewRequest(**{**request.__dict__, "expected_version": pyyaml.version - 1})
        )
    with pytest.raises(InvalidReview):
        record_review(
            session,
            ReviewRequest(**{**request.__dict__, "vex_status": VexStatus.NOT_AFFECTED}),
        )
    record_review(session, request)
    record_review(
        session,
        ReviewRequest(
            finding_id=requests_finding.id,
            organization_id=requests_finding.organization_id,
            reviewer_id=reviewer.id,
            expected_version=requests_finding.version,
            decided_verdict=Verdict.NOT_REACHED,
            vex_status=VexStatus.NOT_AFFECTED,
            justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
            comment=None,
        ),
    )
    session.commit()
    assert pyyaml.review_state is ReviewState.ACCEPTED

    # VEX: both formats validate against the official schemas.
    for fmt, validate in (
        (VexFormat.OPENVEX, openvex_errors),
        (VexFormat.CYCLONEDX, cyclonedx_errors),
    ):
        _, content = generate_vex(
            session,
            artifacts=artifacts,
            organization_id=repository.organization_id,
            repository_id=repository.id,
            fmt=fmt,
            author="alex",
            user_id=reviewer.id,
        )
        assert validate(json.loads(content)) == []
    openvex = json.loads(
        generate_vex(
            session,
            artifacts=artifacts,
            organization_id=repository.organization_id,
            repository_id=repository.id,
            fmt=VexFormat.OPENVEX,
            author="alex",
            user_id=reviewer.id,
        )[1]
    )
    statuses = {s["vulnerability"]["name"]: s["status"] for s in openvex["statements"]}
    assert statuses == {"GHSA-8q59-q68h-6hv4": "affected", "GHSA-x84v-xcm2-53pg": "not_affected"}

    # Audit chain intact after the whole workflow.
    assert verify_chain(session, repository.organization_id).valid


def test_repeated_request_is_one_scan_and_removed_dependency_resolves(
    session_factory: sessionmaker[Session], session: Session, repository: Repository, tmp_path: Path
) -> None:
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    pipeline, _ = make_pipeline(session_factory, tmp_path / "one", APP)
    first = scan_once(session_factory, pipeline, repository, "b" * 40)
    with transaction(session_factory) as tx:
        repo = tx.get(Repository, repository.id)
        assert repo is not None
        again, created = request_scan(tx, repo, commit_sha="b" * 40, trigger=ScanTrigger.MANUAL)
    assert (again.id, created) == (first.id, False)

    without_requests = {**APP, "requirements.txt": "PyYAML==5.3\n"}
    pipeline_two, _ = make_pipeline(session_factory, tmp_path / "two", without_requests)
    scan_once(session_factory, pipeline_two, repository, "c" * 40)

    session.expire_all()
    findings = findings_by_package(session, repository)
    assert findings["requests"].presence is Presence.RESOLVED
    assert findings["pyyaml"].presence is Presence.PRESENT


def test_advisory_change_fans_out_one_rescan_per_repository(
    session_factory: sessionmaker[Session], session: Session, repository: Repository, tmp_path: Path
) -> None:
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    pipeline, _ = make_pipeline(session_factory, tmp_path, APP)
    scan_once(session_factory, pipeline, repository, "d" * 40)

    changed = []
    for name in ("GHSA-8q59-q68h-6hv4", "GHSA-x84v-xcm2-53pg"):
        record = json.loads((FIXTURES / f"{name}.json").read_text())
        record["summary"] = "updated"
        changed.append((name, json.dumps(record).encode()))
    outcome = ingest_osv_records(session_factory, changed)

    with transaction(session_factory) as tx:
        created = fan_out(tx, outcome.run_id)
    with transaction(session_factory) as tx:
        duplicate = fan_out(tx, outcome.run_id)

    assert len(created) == 1, "two changed advisories, one repository → one rescan"
    assert duplicate == []
    advisory_scans = session.scalar(
        select(func.count()).select_from(Scan).where(Scan.trigger == ScanTrigger.ADVISORY)
    )
    assert advisory_scans == 1


@pytest.mark.parametrize(
    ("account_type", "expected_requests"),
    [(AccountType.DEMO, 0), (AccountType.ORGANIZATION, 2)],
    ids=["demo-never-asks-the-model", "customers-do"],
)
def test_missing_symbols_reach_the_model_only_for_customer_organizations(
    session_factory: sessionmaker[Session],
    session: Session,
    repository: Repository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    account_type: AccountType,
    expected_requests: int,
) -> None:
    organization = session.get(Organization, repository.organization_id)
    assert organization is not None
    organization.account_type = account_type
    session.commit()
    ingest_osv_records(session_factory, load_snapshot(FIXTURES))
    monkeypatch.setattr("sieve.scans.pipeline.symbols_for", lambda *_args: [])
    requested: list[Finding] = []
    pipeline, _ = make_pipeline(session_factory, tmp_path, APP)
    pipeline.deps = dataclasses.replace(
        pipeline.deps, on_symbols_missing=lambda _session, finding: requested.append(finding)
    )

    scan = scan_once(session_factory, pipeline, repository, "e" * 40)

    assert scan.status is ScanStatus.SUCCEEDED
    assert len(requested) == expected_requests
