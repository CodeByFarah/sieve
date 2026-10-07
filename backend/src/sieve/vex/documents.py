"""Pure document builders. Statements come from reviewed findings only; anything unreviewed is
``under_investigation`` — Sieve never publishes a definitive VEX status a human has not approved."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sieve.db.enums import VexJustification, VexStatus

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# CycloneDX has its own vocabulary; the mapping below is lossy where the vocabularies differ.
CYCLONEDX_STATE = {
    VexStatus.NOT_AFFECTED: "not_affected",
    VexStatus.AFFECTED: "exploitable",
    VexStatus.FIXED: "resolved",
    VexStatus.UNDER_INVESTIGATION: "in_triage",
}
CYCLONEDX_JUSTIFICATION = {
    VexJustification.COMPONENT_NOT_PRESENT: "code_not_present",
    VexJustification.VULNERABLE_CODE_NOT_PRESENT: "code_not_present",
    VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "code_not_reachable",
    VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "protected_at_runtime",
    VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST: "protected_by_mitigating_control",
}


@dataclass(frozen=True)
class Statement:
    vulnerability: str
    aliases: tuple[str, ...]
    package_purl: str
    status: VexStatus
    justification: VexJustification | None
    detail: str
    severity: str
    cvss_score: Decimal | None
    cvss_vector: str | None
    source_url: str


@dataclass(frozen=True)
class Subject:
    repository: str
    commit_sha: str
    author: str

    @property
    def purl(self) -> str:
        return f"pkg:github/{self.repository}@{self.commit_sha}"


def _iso(timestamp: datetime) -> str:
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _document_id(subject: Subject, statements: list[Statement], timestamp: datetime) -> str:
    material = json.dumps(
        [
            subject.purl,
            _iso(timestamp),
            [(s.vulnerability, s.package_purl, str(s.status)) for s in statements],
        ]
    )
    return hashlib.sha256(material.encode()).hexdigest()[:32]


def build_openvex(
    subject: Subject, statements: list[Statement], timestamp: datetime, tool_version: str
) -> dict[str, Any]:
    rendered = []
    for statement in sorted(statements, key=lambda s: (s.vulnerability, s.package_purl)):
        item: dict[str, Any] = {
            "vulnerability": {"name": statement.vulnerability, "aliases": list(statement.aliases)},
            "products": [{"@id": subject.purl, "subcomponents": [{"@id": statement.package_purl}]}],
            "status": str(statement.status),
        }
        if statement.status is VexStatus.NOT_AFFECTED:
            item["justification"] = str(statement.justification)
            item["impact_statement"] = statement.detail
        elif statement.status is VexStatus.AFFECTED:
            item["action_statement"] = statement.detail
        else:
            item["status_notes"] = statement.detail
        rendered.append(item)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"https://sieve.dev/vex/{_document_id(subject, statements, timestamp)}",
        "author": subject.author,
        "timestamp": _iso(timestamp),
        "version": 1,
        "tooling": f"sieve/{tool_version}",
        "statements": rendered,
    }


def build_cyclonedx_vex(
    subject: Subject, statements: list[Statement], timestamp: datetime, tool_version: str
) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    vulnerabilities = []
    for statement in sorted(statements, key=lambda s: (s.vulnerability, s.package_purl)):
        name, _, version = statement.package_purl.removeprefix("pkg:pypi/").partition("@")
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": statement.package_purl,
            "name": name,
            "purl": statement.package_purl,
        }
        if version:
            component["version"] = version
        components[statement.package_purl] = component
        analysis: dict[str, Any] = {
            "state": CYCLONEDX_STATE[statement.status],
            "detail": statement.detail,
        }
        if statement.justification is not None:
            analysis["justification"] = CYCLONEDX_JUSTIFICATION[statement.justification]
        vulnerability: dict[str, Any] = {
            "bom-ref": f"{statement.vulnerability}:{statement.package_purl}",
            "id": statement.vulnerability,
            "source": {"name": "OSV", "url": statement.source_url},
            "references": [
                {
                    "id": alias,
                    "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{alias}"},
                }
                for alias in statement.aliases
            ],
            "affects": [{"ref": statement.package_purl}],
            "analysis": analysis,
        }
        if statement.cvss_score is not None and statement.cvss_vector:
            method = "CVSSv4" if statement.cvss_vector.startswith("CVSS:4") else "CVSSv31"
            vulnerability["ratings"] = [
                {
                    "score": float(statement.cvss_score),
                    "severity": statement.severity,
                    "method": method,
                    "vector": statement.cvss_vector,
                }
            ]
        vulnerabilities.append(vulnerability)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.UUID(_document_id(subject, statements, timestamp))}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(timestamp),
            "tools": {
                "components": [{"type": "application", "name": "sieve", "version": tool_version}]
            },
            "component": {
                "type": "application",
                "bom-ref": subject.purl,
                "name": subject.repository,
                "version": subject.commit_sha,
                "purl": subject.purl,
            },
        },
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }
