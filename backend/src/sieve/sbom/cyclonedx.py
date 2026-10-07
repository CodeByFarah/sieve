"""Deterministic CycloneDX 1.6 JSON.

Same inputs → byte-identical output: components are sorted, keys are sorted, the serial number is
derived from the content, and the timestamp is supplied by the caller (the scan's start time).
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sieve.sbom.models import Inventory

SPEC_VERSION = "1.6"
_SERIAL_NAMESPACE = uuid.UUID("6f0b5c3e-6b7e-4c55-9d3b-2c1f6e8a9a10")


@dataclass(frozen=True)
class SbomSubject:
    repository: str  # "owner/name"
    commit_sha: str
    tool_version: str

    @property
    def purl(self) -> str:
        return f"pkg:github/{self.repository}@{self.commit_sha}"


def build_cyclonedx(inventory: Inventory, subject: SbomSubject, timestamp: datetime) -> bytes:
    components = []
    direct_refs = []
    for dependency in sorted(inventory.dependencies, key=lambda d: d.purl):
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": dependency.purl,
            "name": dependency.name,
            "purl": dependency.purl,
            "properties": [
                {"name": "sieve:direct", "value": str(dependency.is_direct).lower()},
                {"name": "sieve:manifest", "value": dependency.manifest_path},
            ],
        }
        if dependency.version is not None:
            component["version"] = dependency.version
        else:
            component["properties"].append(
                {"name": "sieve:unpinned-constraint", "value": dependency.constraint or "*"}
            )
        components.append(component)
        if dependency.is_direct:
            direct_refs.append(dependency.purl)

    body: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {"type": "application", "name": "sieve", "version": subject.tool_version}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": subject.purl,
                "name": subject.repository,
                "version": subject.commit_sha,
                "purl": subject.purl,
            },
        },
        "components": components,
        "dependencies": [{"ref": subject.purl, "dependsOn": sorted(direct_refs)}]
        + [{"ref": component["bom-ref"], "dependsOn": []} for component in components],
    }
    content_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    body["serialNumber"] = f"urn:uuid:{uuid.uuid5(_SERIAL_NAMESPACE, content_hash)}"
    return (json.dumps(body, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
