"""All ORM models. Importing this package registers every table on ``Base.metadata``."""

from sieve.db.models.advisories import (
    Advisory,
    AdvisoryPackage,
    EpssScore,
    IngestionFailure,
    IngestionRun,
    KevEntry,
)
from sieve.db.models.audit import AuditEvent
from sieve.db.models.findings import (
    AnalysisResult,
    Finding,
    ReachabilityPath,
    ReviewDecision,
    VexDocument,
)
from sieve.db.models.github import GitHubInstallation, WebhookDelivery
from sieve.db.models.identity import Membership, Organization, User, UserSession
from sieve.db.models.jobs import Job
from sieve.db.models.policy import Policy, PolicyVersion, PullRequestCheck
from sieve.db.models.repositories import Dependency, Package, Repository, Scan, ScanManifest
from sieve.db.models.symbols import AIExtraction, VulnerableSymbol

__all__ = [
    "AIExtraction",
    "Advisory",
    "AdvisoryPackage",
    "AnalysisResult",
    "AuditEvent",
    "Dependency",
    "EpssScore",
    "Finding",
    "GitHubInstallation",
    "IngestionFailure",
    "IngestionRun",
    "Job",
    "KevEntry",
    "Membership",
    "Organization",
    "Package",
    "Policy",
    "PolicyVersion",
    "PullRequestCheck",
    "ReachabilityPath",
    "Repository",
    "ReviewDecision",
    "Scan",
    "ScanManifest",
    "User",
    "UserSession",
    "VexDocument",
    "VulnerableSymbol",
    "WebhookDelivery",
]
