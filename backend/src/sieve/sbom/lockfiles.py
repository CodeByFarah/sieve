"""Lockfile and pyproject parsers: poetry.lock, uv.lock, Pipfile.lock, pyproject.toml."""

import json
import re
import tomllib
from collections.abc import Iterable, Mapping
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from sieve.db.enums import ManifestStatus
from sieve.sbom.models import DeclaredDependency, ManifestReport, normalize_name
from sieve.sbom.requirements import exact_pin

_POETRY_EXACT = re.compile(r"^\d+(\.\d+)*([a-zA-Z0-9.+-]*)$")


def _error(path: str, fmt: str, message: str) -> ManifestReport:
    return ManifestReport(path, fmt, ManifestStatus.ERROR, message)


def _requirement_names(specs: Iterable[Any]) -> set[str]:
    names: set[str] = set()
    for spec in specs:
        if not isinstance(spec, str):
            continue  # PEP 735 {include-group = ...} entries
        try:
            names.add(normalize_name(Requirement(spec).name))
        except InvalidRequirement:
            continue
    return names


def direct_names_from_pyproject(text: str | None) -> set[str]:
    """Names the project declares directly, from every dependency table we know of."""
    if text is None:
        return set()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    project = data.get("project", {})
    names = _requirement_names(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        names |= _requirement_names(group)
    for group in data.get("dependency-groups", {}).values():
        names |= _requirement_names(group)
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [group.get("dependencies", {}) for group in poetry.get("group", {}).values()]
    for table in tables:
        names |= {normalize_name(name) for name in table if name.lower() != "python"}
    return names


def _locked(
    path: str, fmt: str, packages: Iterable[tuple[str, str]], direct: set[str]
) -> ManifestReport:
    dependencies = [
        DeclaredDependency(
            name=normalize_name(name),
            version=version,
            constraint=f"=={version}",
            is_direct=normalize_name(name) in direct,
            manifest_path=path,
        )
        for name, version in packages
    ]
    return ManifestReport(path, fmt, ManifestStatus.PARSED, None, dependencies)


def parse_poetry_lock(path: str, text: str, pyproject: str | None) -> ManifestReport:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return _error(path, "poetry.lock", f"invalid TOML: {exc}")
    packages = [
        (package["name"], str(package["version"]))
        for package in data.get("package", [])
        if "name" in package and "version" in package
    ]
    return _locked(path, "poetry.lock", packages, direct_names_from_pyproject(pyproject))


def parse_uv_lock(path: str, text: str) -> ManifestReport:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return _error(path, "uv.lock", f"invalid TOML: {exc}")
    packages: list[tuple[str, str]] = []
    direct: set[str] = set()
    for package in data.get("package", []):
        source = package.get("source", {})
        if "editable" in source or "virtual" in source:
            # The project itself: its dependencies are the direct ones.
            direct |= {normalize_name(dep["name"]) for dep in package.get("dependencies", [])}
            for group in package.get("dev-dependencies", {}).values():
                direct |= {normalize_name(dep["name"]) for dep in group}
            continue
        if "name" in package and "version" in package:
            packages.append((package["name"], str(package["version"])))
    return _locked(path, "uv.lock", packages, direct)


def parse_pipfile_lock(path: str, text: str, pipfile: str | None) -> ManifestReport:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return _error(path, "Pipfile.lock", f"invalid JSON: {exc}")
    direct: set[str] = set()
    if pipfile is not None:
        try:
            spec = tomllib.loads(pipfile)
            for table in ("packages", "dev-packages"):
                direct |= {normalize_name(name) for name in spec.get(table, {})}
        except tomllib.TOMLDecodeError:
            pass
    packages: list[tuple[str, str]] = []
    for section in ("default", "develop"):
        entries: Mapping[str, Any] = data.get(section, {})
        for name, entry in entries.items():
            version = entry.get("version", "") if isinstance(entry, dict) else ""
            if version.startswith("=="):
                packages.append((name, version[2:]))
    return _locked(path, "Pipfile.lock", packages, direct)


def _poetry_constraint(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("version")
    return value if isinstance(value, str) else None


def parse_pyproject(path: str, text: str) -> ManifestReport:
    """A pyproject.toml with no lockfile beside it: declared constraints, rarely exact pins."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return _error(path, "pyproject.toml", f"invalid TOML: {exc}")
    dependencies: list[DeclaredDependency] = []
    project = data.get("project", {})
    specs = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)
    for spec in specs:
        try:
            requirement = Requirement(spec)
        except InvalidRequirement:
            continue
        dependencies.append(
            DeclaredDependency(
                name=normalize_name(requirement.name),
                version=exact_pin(requirement),
                constraint=str(requirement.specifier) or None,
                is_direct=True,
                manifest_path=path,
            )
        )
    for name, value in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        constraint = _poetry_constraint(value)
        pinned = constraint if constraint and _POETRY_EXACT.match(constraint) else None
        dependencies.append(
            DeclaredDependency(normalize_name(name), pinned, constraint, True, path)
        )
    detail = None
    if any(dependency.version is None for dependency in dependencies):
        detail = "no lockfile: unpinned dependencies are reported as needs_review, never resolved"
    return ManifestReport(path, "pyproject.toml", ManifestStatus.PARSED, detail, dependencies)
