from dataclasses import dataclass, field
from urllib.parse import quote

from packaging.utils import canonicalize_name

from sieve.db.enums import ManifestStatus

ECOSYSTEM = "PyPI"


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: ``PyYAML`` and ``pyyaml`` and ``py_yaml`` are the same project."""
    return str(canonicalize_name(name))


def pypi_purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{normalize_name(name)}"
    return f"{base}@{quote(version, safe='.-_~!')}" if version else base


@dataclass(frozen=True)
class DeclaredDependency:
    name: str  # normalised
    version: str | None  # None: not pinned; Sieve never resolves a version
    constraint: str | None
    is_direct: bool
    manifest_path: str

    @property
    def purl(self) -> str:
        return pypi_purl(self.name, self.version)


@dataclass
class ManifestReport:
    path: str
    format: str
    status: ManifestStatus
    detail: str | None = None
    dependencies: list[DeclaredDependency] = field(default_factory=list)


@dataclass
class Inventory:
    manifests: list[ManifestReport]
    dependencies: list[DeclaredDependency]

    @property
    def pinned_count(self) -> int:
        return sum(1 for dependency in self.dependencies if dependency.version is not None)
