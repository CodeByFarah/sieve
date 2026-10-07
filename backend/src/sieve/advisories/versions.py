"""Is a PyPI version affected by an OSV ``affected`` entry?

Implements the OSV range evaluation for ``ECOSYSTEM`` ranges with PEP 440 ordering (the same
ordering pip uses). An explicit ``versions`` list match is authoritative on its own.
"""

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_EVENT_ORDER = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}


class Affectedness(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"  # unparseable versions or unpinned dependency


def _parse(value: str) -> Version | None:
    if value == "0":
        return Version("0")
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _in_range(version: Version, events: Sequence[Mapping[str, str]]) -> bool | None:
    parsed: list[tuple[Version, str]] = []
    for event in events:
        for kind, value in event.items():
            if kind not in _EVENT_ORDER:
                continue
            point = _parse(value)
            if point is None:
                return None
            parsed.append((point, kind))
    parsed.sort(key=lambda item: (item[0], _EVENT_ORDER[item[1]]))

    affected = False
    for point, kind in parsed:
        if kind == "introduced" and version >= point:
            affected = True
        elif kind in ("fixed", "limit") and version >= point:
            affected = False
        elif kind == "last_affected" and version > point:
            affected = False
    return affected


def version_affected(
    version: str, ranges: Sequence[Mapping[str, Any]], versions: Sequence[str]
) -> Affectedness:
    if version in versions:
        return Affectedness.AFFECTED
    installed = _parse(version)
    if installed is None:
        return Affectedness.UNKNOWN
    if any(_parse(listed) == installed for listed in versions):
        return Affectedness.AFFECTED
    unknown = False
    for range_ in ranges:
        if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        result = _in_range(installed, range_.get("events", []))
        if result is None:
            unknown = True
        elif result:
            return Affectedness.AFFECTED
    return Affectedness.UNKNOWN if unknown else Affectedness.NOT_AFFECTED


def constraint_may_be_affected(
    constraint: str | None, ranges: Sequence[Mapping[str, Any]], versions: Sequence[str]
) -> bool:
    """For an unpinned dependency: could *some* version allowed by the constraint be affected?

    Without resolution we cannot know which version is installed, so this answers conservatively:
    any listed affected version inside the constraint, or (without a version list) any range at all.
    """
    try:
        specifier = SpecifierSet(constraint or "")
    except InvalidSpecifier:
        return True
    if versions:
        return any(specifier.contains(listed, prereleases=True) for listed in versions)
    return bool(ranges)
