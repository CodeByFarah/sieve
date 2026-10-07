"""OSV schema → Sieve's normalised advisory model."""

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

from sieve.db.enums import Severity
from sieve.sbom.models import ECOSYSTEM, normalize_name

SOURCE = "osv"
MAX_SUMMARY = 1_000
MAX_DETAILS = 20_000
MAX_REFERENCES = 100

_FIX_COMMIT = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/commit/(?P<sha>[0-9a-f]{7,40})/?$"
)
_DATABASE_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


@dataclass(frozen=True)
class AffectedPackage:
    name: str
    ranges: list[dict[str, Any]]
    versions: list[str]
    symbols: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FixCommit:
    owner: str
    repo: str
    sha: str


@dataclass(frozen=True)
class NormalizedAdvisory:
    source: str
    source_id: str
    aliases: list[str]
    summary: str | None
    details: str | None
    severity: Severity
    cvss_vector: str | None
    cvss_score: Decimal | None
    references: list[dict[str, str]]
    published_at: datetime | None
    modified_at: datetime
    withdrawn_at: datetime | None
    affected: list[AffectedPackage]
    raw: dict[str, Any]
    content_hash: bytes

    @property
    def cve_ids(self) -> list[str]:
        return sorted(i for i in [self.source_id, *self.aliases] if i.startswith("CVE-"))

    def fix_commits(self) -> list[FixCommit]:
        return fix_commits(self.references)


def severity_from_score(score: Decimal) -> Severity:
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _cvss(entries: list[Mapping[str, Any]]) -> tuple[str | None, Decimal | None]:
    """Prefer CVSS v3 (what EPSS, KEV and most tooling quote), then v4."""
    by_type = {entry.get("type"): entry.get("score") for entry in entries}
    for kind, parser in (("CVSS_V3", CVSS3), ("CVSS_V4", CVSS4)):
        vector = by_type.get(kind)
        if not isinstance(vector, str):
            continue
        try:
            calculated = parser(vector)
        except (CVSSError, ValueError, KeyError):
            continue
        score = calculated.base_score
        return vector, Decimal(str(score))
    return None, None


def _symbols(affected: Mapping[str, Any]) -> list[str]:
    imports = (affected.get("ecosystem_specific") or {}).get("imports") or []
    symbols = []
    for entry in imports:
        path = entry.get("path")
        for symbol in entry.get("symbols", []):
            if isinstance(path, str) and isinstance(symbol, str):
                symbols.append(f"{path}.{symbol}")
    return sorted(set(symbols))


def _timestamp(value: Any) -> datetime | None:
    return datetime.fromisoformat(value) if isinstance(value, str) else None


def fix_commits(references: list[dict[str, str]]) -> list[FixCommit]:
    commits = []
    for reference in references:
        match = _FIX_COMMIT.match(reference.get("url", ""))
        if match and reference.get("type") in ("FIX", "WEB", "PACKAGE"):
            commits.append(FixCommit(match["owner"], match["repo"], match["sha"]))
    return list(dict.fromkeys(commits))


def parse_osv(record: Mapping[str, Any]) -> NormalizedAdvisory:
    """Raises ``KeyError``/``ValueError``/``TypeError`` for records that cannot be normalised;
    the ingester records those as failures rather than dropping them."""
    source_id = str(record["id"])
    modified_at = _timestamp(record["modified"])
    if modified_at is None:
        raise ValueError("modified timestamp missing")

    vector, score = _cvss(record.get("severity", []))
    database_severity = str((record.get("database_specific") or {}).get("severity", "")).upper()
    if score is not None:
        severity = severity_from_score(score)
    else:
        severity = _DATABASE_SEVERITY.get(database_severity, Severity.UNKNOWN)

    references = [
        {"type": str(ref.get("type", "WEB")), "url": ref["url"]}
        for ref in record.get("references", [])
        if isinstance(ref.get("url"), str) and ref["url"].startswith("https://")
    ][:MAX_REFERENCES]

    # A record may list the same package in several entries (e.g. one per release line);
    # they are merged so each package appears once.
    merged: dict[str, AffectedPackage] = {}
    for entry in record.get("affected", []):
        if entry.get("package", {}).get("ecosystem") != ECOSYSTEM:
            continue
        name = normalize_name(entry["package"]["name"])
        ranges = [r for r in entry.get("ranges", []) if r.get("type") in ("ECOSYSTEM", "SEMVER")]
        versions = [str(v) for v in entry.get("versions", [])]
        previous = merged.get(name)
        if previous is not None:
            ranges = previous.ranges + ranges
            versions = list(dict.fromkeys(previous.versions + versions))
        symbols = sorted(set(_symbols(entry)) | set(previous.symbols if previous else []))
        merged[name] = AffectedPackage(name, ranges, versions, symbols)
    affected = list(merged.values())

    summary = record.get("summary")
    details = record.get("details")
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return NormalizedAdvisory(
        source=SOURCE,
        source_id=source_id,
        aliases=sorted({str(a) for a in record.get("aliases", [])} - {source_id}),
        summary=summary[:MAX_SUMMARY] if isinstance(summary, str) else None,
        details=details[:MAX_DETAILS] if isinstance(details, str) else None,
        severity=severity,
        cvss_vector=vector,
        cvss_score=score,
        references=references,
        published_at=_timestamp(record.get("published")),
        modified_at=modified_at,
        withdrawn_at=_timestamp(record.get("withdrawn")),
        affected=affected,
        raw=json.loads(canonical),
        content_hash=hashlib.sha256(canonical.encode()).digest(),
    )


def preference(source_id: str) -> int:
    """Lower is preferred when several records describe the same vulnerability: GHSA records
    carry reviewed severity, PYSEC records come next, anything else last."""
    if source_id.startswith("GHSA-"):
        return 0
    if source_id.startswith("PYSEC-"):
        return 1
    return 2
