"""Which files are Python modules, and what are they called when imported?"""

import keyword
import re
from dataclasses import dataclass
from pathlib import Path

from sieve.core.workspace import Workspace
from sieve.sbom.inventory import SKIP_DIRS

# Test suites and docs are not part of what runs in production; analysing them would turn
# "a test calls yaml.load" into a reachable finding. Excluded files are counted and reported.
NON_PRODUCTION_DIRS = frozenset({"tests", "test", "testing", "docs", "examples", "benchmarks"})
_NON_PRODUCTION_FILE = re.compile(r"^(test_.*|.*_test|conftest|setup|noxfile|fabfile)\.py$")


@dataclass(frozen=True)
class SourceFile:
    module: str
    path: str  # POSIX path relative to the root it was discovered in
    is_package: bool


def module_name(relative: str) -> tuple[str, bool] | None:
    """``pkg/sub/__init__.py`` → (``pkg.sub``, True). ``None`` if not importable by that path."""
    if not relative.endswith(".py"):
        return None
    parts = relative[:-3].split("/")
    is_package = parts[-1] == "__init__"
    if is_package:
        parts = parts[:-1]
    if not parts or not all(part.isidentifier() and not keyword.iskeyword(part) for part in parts):
        return None
    return ".".join(parts), is_package


def discover_app_sources(workspace: Workspace) -> tuple[list[SourceFile], int]:
    """Application modules, with ``src/`` layouts mapped to their import names.

    Returns the files and the number of Python files excluded as tests or tooling.
    """
    files = [
        path
        for path in workspace.iter_files(skip_dirs=SKIP_DIRS | NON_PRODUCTION_DIRS)
        if path.endswith(".py")
    ]
    src_layout = any(path.startswith("src/") for path in files)
    sources: list[SourceFile] = []
    excluded = 0
    for path in files:
        if _NON_PRODUCTION_FILE.match(path.rsplit("/", 1)[-1]):
            excluded += 1
            continue
        import_path = path.removeprefix("src/") if src_layout else path
        named = module_name(import_path)
        if named is not None:
            sources.append(SourceFile(named[0], path, named[1]))
    return sources, excluded


def discover_dist_sources(root: Path, *, max_files: int = 50_000) -> list[SourceFile]:
    workspace = Workspace(root, max_files=max_files)
    sources = []
    for path in workspace.iter_files(skip_dirs=SKIP_DIRS | NON_PRODUCTION_DIRS):
        if _NON_PRODUCTION_FILE.match(path.rsplit("/", 1)[-1]):
            continue  # setup.py and tests shipped inside sdists are not importable package code
        named = module_name(path)
        if named is not None:
            sources.append(SourceFile(named[0], path, named[1]))
    return sources
