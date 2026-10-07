"""API response and request models. These are the contract: the frontend's TypeScript types are
generated from the OpenAPI document they produce."""

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from sieve.db.enums import (
    Confidence,
    Presence,
    ReviewState,
    Role,
    ScanStatus,
    ScanTrigger,
    Severity,
    SymbolKind,
    SymbolOrigin,
    SymbolVerification,
    Verdict,
    VexFormat,
    VexJustification,
    VexStatus,
)


class Model(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(Model):
    id: uuid.UUID
    login: str
    name: str | None
    avatar_url: str | None


class OrganizationOut(Model):
    id: uuid.UUID
    login: str
    account_type: str
    role: Role


class MeOut(Model):
    user: UserOut | None
    organizations: list[OrganizationOut]
    github_login_enabled: bool
    github_install_url: str | None


class ScanOut(Model):
    id: uuid.UUID
    repository_id: uuid.UUID
    commit_sha: str
    ref: str | None
    trigger: ScanTrigger
    status: ScanStatus
    stage: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    stats: dict[str, Any]
    error_code: str | None
    error_message: str | None


class ManifestOut(Model):
    path: str
    format: str
    status: str
    detail: str | None


class ScanDetailOut(ScanOut):
    progress: dict[str, Any]
    stages: list[str]
    repository_full_name: str
    sbom_available: bool
    manifests: list[ManifestOut]


class VerdictCounts(Model):
    total: int = 0
    reachable: int = 0
    needs_review: int = 0
    not_reached: int = 0
    pending: int = 0
    kev: int = 0


class RepositoryOut(Model):
    id: uuid.UUID
    full_name: str
    source: str
    default_branch: str
    is_private: bool
    latest_scan: ScanOut | None
    counts: VerdictCounts
    health: Literal["healthy", "attention", "failing", "pending"]


class FindingItemOut(Model):
    id: uuid.UUID
    advisory_id: str
    aliases: list[str]
    summary: str | None
    package: str
    installed_version: str | None
    severity: Severity
    cvss_score: Decimal | None
    verdict: Verdict | None
    effective_verdict: Verdict | None
    confidence: Confidence | None
    review_state: ReviewState
    risk_score: Decimal | None
    kev: bool
    epss_percentile: Decimal | None
    presence: Presence
    repository_id: uuid.UUID
    repository_full_name: str
    first_seen_at: datetime


class FindingPage(Model):
    items: list[FindingItemOut]
    total: int
    next_cursor: str | None


class AuditEventOut(Model):
    seq: int
    action: str
    actor_type: str
    actor_login: str | None
    target_type: str | None
    target_id: str | None
    data: dict[str, Any]
    correlation_id: str | None
    occurred_at: datetime


class AdvisoryOut(Model):
    id: str
    aliases: list[str]
    summary: str | None
    details: str | None
    severity: Severity
    cvss_vector: str | None
    cvss_score: Decimal | None
    references: list[dict[str, str]]
    published_at: datetime | None
    modified_at: datetime
    url: str


class ExploitationOut(Model):
    kev: dict[str, Any] | None
    epss: dict[str, Any] | None


class PathOut(Model):
    rank: int
    entrypoint_kind: str
    steps: list[dict[str, Any]]


class AnalysisOut(Model):
    id: uuid.UUID
    verdict: Verdict
    confidence: Confidence
    reasons: list[dict[str, Any]]
    symbols: list[dict[str, Any]]
    analyzer_version: str
    created_at: datetime
    scan_id: uuid.UUID
    paths: list[PathOut]


class AIExtractionOut(Model):
    provider: str
    model: str
    prompt_version: str
    status: str
    created_at: datetime
    latency_ms: int | None
    output: dict[str, Any] | None


class SymbolOut(Model):
    qualified_name: str
    kind: SymbolKind
    origin: SymbolOrigin
    verification: SymbolVerification
    verification_detail: dict[str, Any]
    ai_extraction: AIExtractionOut | None


class ReviewOut(Model):
    id: uuid.UUID
    reviewer_login: str
    previous_verdict: Verdict | None
    decided_verdict: Verdict
    vex_status: VexStatus
    justification: VexJustification | None
    comment: str | None
    analysis_result_id: uuid.UUID | None
    created_at: datetime


class FindingDetailOut(FindingItemOut):
    version: int
    analysis_state: str
    decided_verdict: Verdict | None
    vex_status: VexStatus | None
    vex_justification: VexJustification | None
    advisory: AdvisoryOut
    risk_breakdown: dict[str, Any]
    exploitation: ExploitationOut
    analysis: AnalysisOut | None
    symbols: list[SymbolOut]
    symbol_provenance: str
    reviews: list[ReviewOut]
    timeline: list[AuditEventOut]
    vex_preview: dict[str, Any]
    can_review: bool


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    decided_verdict: Verdict
    vex_status: VexStatus
    justification: VexJustification | None = None
    comment: str | None = Field(default=None, max_length=4000)


class SeverityBreakdown(Model):
    severity: Severity
    reachable: int
    needs_review: int
    not_reached: int


class OverviewOut(Model):
    organization: OrganizationOut
    totals: VerdictCounts
    severity: list[SeverityBreakdown]
    kev_findings: list[FindingItemOut]
    top_findings: list[FindingItemOut]
    repositories: list[RepositoryOut]
    activity: list[AuditEventOut]


class VexIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: VexFormat


class VexDocumentOut(Model):
    id: uuid.UUID
    format: VexFormat
    repository_id: uuid.UUID | None
    repository_full_name: str | None
    statement_count: int
    sha256: str
    created_at: datetime


class PolicyOut(Model):
    version: int
    rules: dict[str, Any]
    created_at: datetime
    history: list[dict[str, Any]]
    can_edit: bool


class PolicyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: dict[str, Any]


class SearchOut(Model):
    repositories: list[RepositoryOut]
    findings: list[FindingItemOut]
    packages: list[dict[str, Any]]


class SourceHealthOut(Model):
    source: str
    last_run_at: datetime | None
    last_status: str | None
    last_success_at: datetime | None
    records_seen: int | None
    unresolved_failures: int
    stale: bool


class DemoOut(Model):
    organization_login: str
    repository_id: uuid.UUID
    latest_scan: ScanOut | None
    snapshot: dict[str, Any]
    symbol_provenance: str
    ai_enabled: bool


class DemoScanOut(Model):
    scan: ScanOut
    created: bool


class PullRequestCheckOut(Model):
    pr_number: int
    head_sha: str
    conclusion: str | None
    summary: dict[str, Any]
    created_at: datetime
