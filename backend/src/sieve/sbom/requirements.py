"""pip requirements files (``requirements*.txt`` / ``*.in``).

Supported: ``name[extras]==version ; markers``, ``--hash`` options, ``-r`` includes (inside the
workspace only), comments and line continuations, pip-compile ``# via`` annotations.
Not supported (reported, never fetched): URLs, local paths, VCS and editable requirements.
"""

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass

from packaging.requirements import InvalidRequirement, Requirement

from sieve.db.enums import ManifestStatus
from sieve.sbom.models import DeclaredDependency, ManifestReport, normalize_name

FORMAT = "requirements.txt"
MAX_INCLUDE_DEPTH = 5

_INCLUDE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(?P<path>\S+)$")
_OPTION = re.compile(r"^-{1,2}[A-Za-z]")
_INLINE_OPTION = re.compile(r"\s--(?:hash|config-settings|global-option)[=\s]\S+")
_COMMENT = re.compile(r"(^|\s)#.*$")
# pip-compile: "# via flask" or "# via" followed by "#   flask" lines.
_VIA_START = re.compile(r"^#\s*via\b\s*(?P<parent>.*)$")
_VIA_CONTINUATION = re.compile(r"^#\s+(?P<parent>\S.*)$")

ReadFile = Callable[[str], str | None]


@dataclass
class _Line:
    text: str
    via: list[str]


def exact_pin(requirement: Requirement) -> str | None:
    """The pinned version if the specifier pins exactly one version, else ``None``."""
    specifiers = list(requirement.specifier)
    if (
        len(specifiers) == 1
        and specifiers[0].operator in ("==", "===")
        and "*" not in specifiers[0].version
    ):
        return specifiers[0].version
    return None


def _logical_lines(text: str) -> list[_Line]:
    """Join continuations; attach pip-compile ``# via`` annotations to the preceding requirement."""
    lines: list[_Line] = []
    buffer = ""
    in_via_block = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if buffer:
            stripped = buffer + " " + stripped
            buffer = ""
        if stripped.endswith("\\"):
            buffer = stripped[:-1].strip()
            continue
        if stripped.startswith("#"):
            via_start = _VIA_START.match(stripped)
            continuation = _VIA_CONTINUATION.match(stripped)
            if lines and via_start:
                in_via_block = True
                if via_start["parent"]:
                    lines[-1].via.append(via_start["parent"].strip())
            elif lines and in_via_block and continuation:
                lines[-1].via.append(continuation["parent"].strip())
            else:
                in_via_block = False
            continue
        in_via_block = False
        content = _COMMENT.sub("", stripped).strip()
        if content:
            lines.append(_Line(content, []))
    return lines


def _is_direct(via: list[str]) -> bool:
    # Without pip-compile annotations every listed requirement is something the author chose.
    return not via or any(parent.startswith(("-r", "-c")) for parent in via)


def parse_requirements(
    path: str, read_file: ReadFile, *, _depth: int = 0, _seen: frozenset[str] = frozenset()
) -> ManifestReport:
    text = read_file(path)
    if text is None:
        return ManifestReport(path, FORMAT, ManifestStatus.ERROR, "file could not be read")

    dependencies: list[DeclaredDependency] = []
    skipped: list[str] = []
    for line in _logical_lines(text):
        content = _INLINE_OPTION.sub("", " " + line.text).strip()
        include = _INCLUDE.match(content)
        if include:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), include["path"]))
            if _depth >= MAX_INCLUDE_DEPTH or target in _seen or target == path:
                skipped.append(f"include {include['path']} (cycle or too deep)")
                continue
            nested = parse_requirements(target, read_file, _depth=_depth + 1, _seen=_seen | {path})
            if nested.detail:
                skipped.append(f"include {include['path']}: {nested.detail}")
            dependencies.extend(nested.dependencies)
            continue
        if _OPTION.match(content):
            if content.startswith(("-e", "--editable")):
                skipped.append("editable requirement")
            continue  # index URLs, constraints files, and other pip options
        if "://" in content or content.startswith((".", "/", "\\")) or " @ " in content:
            skipped.append(f"non-index requirement {content[:80]!r}")
            continue
        try:
            requirement = Requirement(content)
        except InvalidRequirement:
            skipped.append(f"unparseable line {content[:80]!r}")
            continue
        constraint = str(requirement.specifier) or None
        dependencies.append(
            DeclaredDependency(
                name=normalize_name(requirement.name),
                version=exact_pin(requirement),
                constraint=constraint,
                is_direct=_is_direct(line.via),
                manifest_path=path,
            )
        )

    detail = "; ".join(skipped) if skipped else None
    return ManifestReport(path, FORMAT, ManifestStatus.PARSED, detail, dependencies)
