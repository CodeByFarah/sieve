"""Persisted vocabularies.

Stored as text with a CHECK constraint (see ``sieve.db.base.enum_column``) rather than native
PostgreSQL enums, so adding a value is an ordinary constraint change in a migration.
"""

from enum import StrEnum


class AccountType(StrEnum):
    USER = "user"
    ORGANIZATION = "organization"
    DEMO = "demo"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class RepositorySource(StrEnum):
    GITHUB = "github"
    DEMO = "demo"


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    ADVISORY = "advisory"
    SCHEDULE = "schedule"
    DEMO = "demo"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ManifestStatus(StrEnum):
    PARSED = "parsed"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class IngestionStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class AIExtractionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    SCHEMA_INVALID = "schema_invalid"
    PROVIDER_ERROR = "provider_error"
    REFUSED = "refused"


class SymbolKind(StrEnum):
    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"


class SymbolOrigin(StrEnum):
    ADVISORY = "advisory"
    AI = "ai"
    CURATED = "curated"
    REVIEWER = "reviewer"


class SymbolVerification(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNVERIFIED = "unverified"


class Presence(StrEnum):
    PRESENT = "present"
    RESOLVED = "resolved"


class AnalysisState(StrEnum):
    PENDING = "pending"
    ANALYZING = "analyzing"
    ANALYZED = "analyzed"
    FAILED = "failed"


class Verdict(StrEnum):
    REACHABLE = "reachable"
    NOT_REACHED = "not_reached"
    NEEDS_REVIEW = "needs_review"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ReviewState(StrEnum):
    UNREVIEWED = "unreviewed"
    ACCEPTED = "accepted"
    OVERRIDDEN = "overridden"
    STALE = "stale"


class VexStatus(StrEnum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(StrEnum):
    """OpenVEX justification values for ``not_affected`` statements."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


class VexFormat(StrEnum):
    OPENVEX = "openvex"
    CYCLONEDX = "cyclonedx"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    DEAD = "dead"


class ActorType(StrEnum):
    USER = "user"
    SYSTEM = "system"
    GITHUB = "github"
