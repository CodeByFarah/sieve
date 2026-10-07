"""Find every dependency manifest in a workspace and merge what they declare."""

import posixpath
import re
from collections import defaultdict

from sieve.core.workspace import Workspace
from sieve.db.enums import ManifestStatus
from sieve.sbom.lockfiles import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
    parse_uv_lock,
)
from sieve.sbom.models import DeclaredDependency, Inventory, ManifestReport
from sieve.sbom.requirements import parse_requirements

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        "__pycache__",
        "site-packages",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
    }
)

_REQUIREMENTS_NAME = re.compile(r"^requirements[\w.-]*\.(txt|in)$", re.IGNORECASE)
LOCKFILES = ("poetry.lock", "uv.lock", "Pipfile.lock")

UNSUPPORTED = {
    "setup.py": "setup.py is never executed; declare dependencies in pyproject.toml or a lockfile",
    "setup.cfg": "setup.cfg install_requires is not parsed yet; commit a lockfile",
    "environment.yml": "conda environments are not supported (PyPI only)",
    "environment.yaml": "conda environments are not supported (PyPI only)",
    "pdm.lock": "pdm.lock is not supported yet",
}


def _is_requirements(path: str) -> bool:
    name = posixpath.basename(path)
    in_requirements_dir = posixpath.basename(posixpath.dirname(path)) == "requirements"
    return bool(_REQUIREMENTS_NAME.match(name)) or (
        in_requirements_dir and name.endswith((".txt", ".in"))
    )


def _relevant(path: str) -> bool:
    name = posixpath.basename(path)
    return (
        name in LOCKFILES
        or name in ("pyproject.toml", "Pipfile")
        or name in UNSUPPORTED
        or _is_requirements(path)
    )


def _scan_directory(workspace: Workspace, directory: str, names: set[str]) -> list[ManifestReport]:
    def path_of(name: str) -> str:
        return posixpath.join(directory, name) if directory else name

    def read(name: str) -> str | None:
        return workspace.read_text(path_of(name)) if name in names else None

    reports: list[ManifestReport] = []
    has_lock = any(lock in names for lock in LOCKFILES)

    for name in sorted(names):
        path = path_of(name)
        text = workspace.read_text(path)
        if name in UNSUPPORTED:
            reports.append(
                ManifestReport(path, name, ManifestStatus.UNSUPPORTED, UNSUPPORTED[name])
            )
        elif text is None:
            reports.append(
                ManifestReport(path, name, ManifestStatus.ERROR, "file too large or unreadable")
            )
        elif name == "poetry.lock":
            reports.append(parse_poetry_lock(path, text, read("pyproject.toml")))
        elif name == "uv.lock":
            reports.append(parse_uv_lock(path, text))
        elif name == "Pipfile.lock":
            reports.append(parse_pipfile_lock(path, text, read("Pipfile")))
        elif name in ("pyproject.toml", "Pipfile"):
            if has_lock:
                reports.append(
                    ManifestReport(
                        path, name, ManifestStatus.PARSED, "versions taken from the lockfile"
                    )
                )
            elif name == "pyproject.toml":
                reports.append(parse_pyproject(path, text))
            else:
                reports.append(
                    ManifestReport(
                        path, name, ManifestStatus.UNSUPPORTED, "Pipfile without Pipfile.lock"
                    )
                )
        elif _is_requirements(path):
            stem, extension = posixpath.splitext(name)
            if extension == ".in" and f"{stem}.txt" in names:
                continue  # the compiled .txt next to it is the source of truth
            reports.append(parse_requirements(path, workspace.read_text))
    return reports


def merge_dependencies(declared: list[DeclaredDependency]) -> list[DeclaredDependency]:
    """One entry per (name, version). An unpinned entry is dropped when the same package is
    pinned elsewhere in the repository (the pin is what gets installed)."""
    pinned_names = {dependency.name for dependency in declared if dependency.version is not None}
    merged: dict[tuple[str, str | None], DeclaredDependency] = {}
    for dependency in sorted(declared, key=lambda d: (d.name, d.version or "", d.manifest_path)):
        if dependency.version is None and dependency.name in pinned_names:
            continue
        key = (dependency.name, dependency.version)
        existing = merged.get(key)
        if existing is None:
            merged[key] = dependency
        elif dependency.is_direct and not existing.is_direct:
            merged[key] = DeclaredDependency(
                existing.name, existing.version, existing.constraint, True, existing.manifest_path
            )
    return list(merged.values())


def build_inventory(workspace: Workspace) -> Inventory:
    by_directory: dict[str, set[str]] = defaultdict(set)
    for path in workspace.iter_files(skip_dirs=SKIP_DIRS):
        if _relevant(path):
            by_directory[posixpath.dirname(path)].add(posixpath.basename(path))

    manifests: list[ManifestReport] = []
    for directory in sorted(by_directory):
        manifests.extend(_scan_directory(workspace, directory, by_directory[directory]))

    declared = [dependency for manifest in manifests for dependency in manifest.dependencies]
    return Inventory(manifests=manifests, dependencies=merge_dependencies(declared))
