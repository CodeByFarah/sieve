"""Builds the analysis context for one repository snapshot.

1. Index the application's own modules.
2. Fetch every pinned dependency's published source (cached by artifact digest) to learn which
   import names each distribution provides.
3. Starting from the application's imports, index only the distributions that are actually
   imported, following their imports transitively. Distributions never imported are never parsed.
4. Build one call graph over everything indexed.
"""

import json
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from sieve.analysis.discovery import SourceFile, discover_app_sources, discover_dist_sources
from sieve.analysis.model import INDEX_FORMAT_VERSION, ModuleSummary
from sieve.analysis.program import APP_OWNER, Program, build_program
from sieve.analysis.reachability import AnalysisContext, PackageState
from sieve.analysis.sandbox import AnalysisBudgetExceeded, Indexer
from sieve.core.errors import SieveError
from sieve.core.logging import get_logger
from sieve.core.workspace import Workspace
from sieve.packages.pypi import FetchedSource
from sieve.sbom.models import normalize_name

log = get_logger(__name__)

STDLIB = frozenset(sys.stdlib_module_names)

# Import names that differ from the distribution name. Only used when a distribution's files
# are unavailable (unpinned or failed fetch); otherwise the real file listing is used.
IMPORT_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml", "_yaml"),
    "pillow": ("PIL",),
    "beautifulsoup4": ("bs4",),
    "pyjwt": ("jwt",),
    "python-dateutil": ("dateutil",),
    "scikit-learn": ("sklearn",),
    "opencv-python": ("cv2",),
    "pycryptodome": ("Crypto",),
    "pyopenssl": ("OpenSSL",),
    "setuptools": ("setuptools", "pkg_resources"),
    "attrs": ("attr", "attrs"),
    "python-multipart": ("multipart",),
    "protobuf": ("google",),
}


class SourceProvider(Protocol):
    def fetch(self, name: str, version: str) -> FetchedSource: ...


@dataclass(frozen=True)
class DependencyPin:
    name: str
    version: str | None


@dataclass(frozen=True)
class EngineLimits:
    max_modules: int = 40_000


@dataclass
class EngineStats:
    app_modules: int = 0
    app_files_excluded: int = 0
    dependency_modules: int = 0
    distributions_indexed: int = 0
    distributions_unavailable: int = 0
    parse_failures: int = 0
    nodes: int = 0
    edges: int = 0
    unresolved_calls: int = 0
    timings: dict[str, float] = field(default_factory=dict)


@dataclass
class EngineResult:
    context: AnalysisContext
    stats: EngineStats
    unavailable: dict[str, str]  # distribution → reason
    source_roots: dict[str, Path] = field(default_factory=dict)  # distribution → extracted source

    @property
    def program(self) -> Program:
        return self.context.program


def _top_levels(summaries: list[ModuleSummary]) -> set[str]:
    return {summary.name.split(".")[0] for summary in summaries}


def _imported_tops(summaries: list[ModuleSummary]) -> set[str]:
    return {entry.module.split(".")[0] for summary in summaries for entry in summary.imports}


class ReachabilityEngine:
    def __init__(
        self,
        sources: SourceProvider,
        indexer: Indexer,
        *,
        index_cache: Path | None = None,
        limits: EngineLimits = EngineLimits(),
    ) -> None:
        self.sources = sources
        self.indexer = indexer
        self.index_cache = index_cache
        self.limits = limits

    def _index_distribution(
        self, fetched: FetchedSource, files: list[SourceFile]
    ) -> list[ModuleSummary]:
        cache_file = (
            self.index_cache / f"{fetched.cache_key}-v{INDEX_FORMAT_VERSION}.json"
            if self.index_cache
            else None
        )
        if cache_file is not None and cache_file.exists():
            return [
                ModuleSummary.from_dict(item) for item in json.loads(cache_file.read_text("utf-8"))
            ]
        summaries = self.indexer.index(fetched.root, files)
        if cache_file is not None:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps([s.to_dict() for s in summaries]), encoding="utf-8")
        return summaries

    def analyze(self, workspace: Workspace, dependencies: list[DependencyPin]) -> EngineResult:
        stats = EngineStats()
        started = time.perf_counter()

        app_files, stats.app_files_excluded = discover_app_sources(workspace)
        app_summaries = self.indexer.index(workspace.root, app_files)
        stats.app_modules = len(app_summaries)
        stats.timings["index_app_seconds"] = round(time.perf_counter() - started, 3)

        # Learn which import names each pinned distribution provides.
        fetch_started = time.perf_counter()
        states: dict[str, PackageState] = {}
        fetched: dict[str, tuple[FetchedSource, list[SourceFile]]] = {}
        providers: dict[str, list[str]] = defaultdict(list)
        unavailable: dict[str, str] = {}
        for dependency in dependencies:
            name = normalize_name(dependency.name)
            if dependency.version is None:
                states[name] = PackageState.UNPINNED
                for top in IMPORT_NAME_HINTS.get(name, (name.replace("-", "_"),)):
                    providers[top].append(name)
                continue
            try:
                source = self.sources.fetch(name, dependency.version)
                files = discover_dist_sources(source.root)
            except SieveError as exc:
                states[name] = PackageState.UNAVAILABLE
                unavailable[name] = f"{exc.code}: {exc.message}"
                for top in IMPORT_NAME_HINTS.get(name, (name.replace("-", "_"),)):
                    providers[top].append(name)
                continue
            states[name] = PackageState.NOT_IMPORTED
            fetched[name] = (source, files)
            for top in {f.module.split(".")[0] for f in files}:
                providers[top].append(name)
        stats.distributions_unavailable = len(unavailable)
        stats.timings["fetch_sources_seconds"] = round(time.perf_counter() - fetch_started, 3)

        # Follow imports from the application outwards; index only what is imported.
        index_started = time.perf_counter()
        all_summaries: list[tuple[ModuleSummary, str]] = [(s, APP_OWNER) for s in app_summaries]
        package_modules: dict[str, set[str]] = {}
        own_tops = _top_levels(app_summaries)
        string_tops = {text.split(".")[0] for s in app_summaries for text in s.string_refs}
        queue = deque(sorted((_imported_tops(app_summaries) | string_tops) - own_tops - STDLIB))
        visited: set[str] = set()
        budget_exceeded = False
        while queue:
            top = queue.popleft()
            if top in visited:
                continue
            visited.add(top)
            for dist in providers.get(top, []):
                if dist not in fetched or states[dist] is PackageState.LOADED:
                    continue
                source, files = fetched[dist]
                if stats.dependency_modules + len(files) > self.limits.max_modules:
                    budget_exceeded = True
                    log.warning("analysis.module_budget_exceeded", distribution=dist)
                    continue
                try:
                    summaries = self._index_distribution(source, files)
                except AnalysisBudgetExceeded:
                    budget_exceeded = True
                    continue
                states[dist] = PackageState.LOADED
                stats.distributions_indexed += 1
                stats.dependency_modules += len(summaries)
                package_modules[dist] = {s.name for s in summaries}
                all_summaries.extend((s, dist) for s in summaries)
                queue.extend(sorted(_imported_tops(summaries) - STDLIB - visited))
        stats.timings["index_dependencies_seconds"] = round(time.perf_counter() - index_started, 3)

        graph_started = time.perf_counter()
        program = build_program(all_summaries)
        context = AnalysisContext.build(
            program, states, package_modules, budget_exceeded=budget_exceeded
        )
        stats.timings["call_graph_seconds"] = round(time.perf_counter() - graph_started, 3)
        stats.parse_failures = sum(1 for s, _ in all_summaries if s.parse_error)
        stats.nodes = len(program.nodes)
        stats.edges = program.edge_count
        stats.unresolved_calls = len(program.unresolved)
        stats.timings["total_seconds"] = round(time.perf_counter() - started, 3)
        roots = {name: source.root for name, (source, _) in fetched.items()}
        return EngineResult(context, stats, unavailable, roots)
