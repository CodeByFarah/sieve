"""Path search and the verdict rules (architecture §5.2).

The rules are deliberately asymmetric. ``reachable`` needs a concrete path over resolved edges.
``not_reached`` needs positive evidence that no path exists: the package is never imported, or the
vulnerable symbols are verified in the installed source, the traversal completed, and nothing
dynamic that is reachable could target them. Everything else is ``needs_review`` with a reason.
"""

import heapq
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sieve.analysis.model import MODULE_NODE_PREFIX, DynamicKind, RootKind, module_node
from sieve.analysis.program import (
    ALL_EDGES,
    APP_OWNER,
    STRONG_EDGES,
    DefTarget,
    Edge,
    EdgeKind,
    ModuleTarget,
    Program,
)
from sieve.db.enums import Confidence, SymbolOrigin, Verdict

ENTRYPOINT_KINDS = (RootKind.HTTP_ROUTE, RootKind.CLI_COMMAND, RootKind.TASK, RootKind.MAIN)
TRUSTED_ORIGINS = frozenset({SymbolOrigin.ADVISORY, SymbolOrigin.CURATED, SymbolOrigin.REVIEWER})
MAX_PATHS = 3
MAX_LOCATIONS = 5


class PackageState(StrEnum):
    LOADED = "loaded"
    NOT_IMPORTED = "not_imported"
    UNPINNED = "unpinned"
    UNAVAILABLE = "unavailable"


class ReasonCode(StrEnum):
    PATH_FOUND = "path_found"
    PACKAGE_NOT_IMPORTED = "package_not_imported"
    NO_PATH = "no_path"
    VERSION_UNPINNED = "version_unpinned"
    SOURCE_UNAVAILABLE = "package_source_unavailable"
    INCOMPLETE_IMPORT_GRAPH = "incomplete_import_graph"
    NO_VERIFIED_SYMBOLS = "no_verified_symbols"
    REFERENCE_ONLY = "reference_only"
    DYNAMIC_DISPATCH = "dynamic_dispatch"
    DYNAMIC_IMPORT = "dynamic_import"
    DYNAMIC_ATTRIBUTE = "dynamic_attribute"
    PARSE_FAILURE = "parse_failure"
    BUDGET_EXCEEDED = "budget_exceeded"


@dataclass(frozen=True)
class Root:
    node: str
    kind: str


@dataclass(frozen=True)
class SymbolInput:
    qualified_name: str
    origin: SymbolOrigin


@dataclass
class Outcome:
    verdict: Verdict
    confidence: Confidence
    reasons: list[dict[str, Any]]
    paths: list[dict[str, Any]] = field(default_factory=list)
    symbols: list[dict[str, Any]] = field(default_factory=list)


def _priority(kind: str) -> int:
    return (
        ENTRYPOINT_KINDS.index(RootKind(kind))
        if kind in ENTRYPOINT_KINDS
        else len(ENTRYPOINT_KINDS)
    )


def app_roots(program: Program) -> list[Root]:
    """Every module body and function of application code (tests excluded at discovery).

    Treating all application functions as roots is conservative: a function nothing appears to
    call may still be invoked by a framework, a callback registry or reflection.
    """
    roots = []
    for node in program.nodes.values():
        if node.owner != APP_OWNER:
            continue
        if node.kind == "module":
            roots.append(Root(node.id, RootKind.MAIN if node.root == "main" else RootKind.MODULE))
        elif node.kind in ("function", "method"):
            roots.append(Root(node.id, node.root or RootKind.FUNCTION))
    return sorted(roots, key=lambda root: (_priority(root.kind), root.node))


def _bfs(program: Program, sources: Iterable[str], kinds: frozenset[str]) -> dict[str, Edge | None]:
    parent: dict[str, Edge | None] = {}
    queue: deque[str] = deque()
    for source in sources:
        if source not in parent:
            parent[source] = None
            queue.append(source)
    while queue:
        node = queue.popleft()
        for edge in program.edges.get(node, ()):
            if edge.kind in kinds and edge.target not in parent:
                parent[edge.target] = edge
                queue.append(edge.target)
    return parent


def reachable_nodes(program: Program, roots: list[Root]) -> set[str]:
    return set(_bfs(program, (root.node for root in roots), ALL_EDGES))


# Path *selection* among possible paths (never used for the verdict itself): an uncertain hop
# into a package the caller's package imports is more plausible than one between unrelated
# packages. Costs are (uncertainty, hops), compared lexicographically.
_PLAUSIBLE_HOP = 1
_IMPLAUSIBLE_HOP = 4


def _uncertainty(program: Program, edge: Edge) -> int:
    if edge.kind in STRONG_EDGES:
        return 0
    source_owner = program.owner_of(edge.source)
    target_owner = program.owner_of(edge.target)
    if source_owner == target_owner or target_owner in program.owner_imports.get(
        source_owner or "", ()
    ):
        return _PLAUSIBLE_HOP
    return _IMPLAUSIBLE_HOP


def _weighted(
    program: Program, sources: Iterable[str], kinds: frozenset[str]
) -> dict[str, Edge | None]:
    parent: dict[str, Edge | None] = {}
    best: dict[str, tuple[int, int]] = {}
    heap: list[tuple[int, int, int, str]] = []
    counter = 0
    for source in sources:
        if source not in best:
            best[source] = (0, 0)
            parent[source] = None
            heapq.heappush(heap, (0, 0, counter, source))
            counter += 1
    while heap:
        uncertain, hops, _, node = heapq.heappop(heap)
        if (uncertain, hops) > best[node]:
            continue
        for edge in program.edges.get(node, ()):
            if edge.kind not in kinds:
                continue
            cost = (uncertain + _uncertainty(program, edge), hops + 1)
            if edge.target not in best or cost < best[edge.target]:
                best[edge.target] = cost
                parent[edge.target] = edge
                counter += 1
                heapq.heappush(heap, (*cost, counter, edge.target))
    return parent


def _path(parent: dict[str, Edge | None], target: str) -> list[Edge]:
    edges: list[Edge] = []
    node = target
    while (edge := parent[node]) is not None:
        edges.append(edge)
        node = edge.source
    return list(reversed(edges))


def _display(node_id: str) -> str:
    if node_id.startswith(MODULE_NODE_PREFIX):
        return f"import {node_id.removeprefix(MODULE_NODE_PREFIX)}"
    return node_id


def to_steps(program: Program, edges: list[Edge], start: str) -> list[dict[str, Any]]:
    nodes = [start, *(edge.target for edge in edges)]
    steps = []
    for index, node_id in enumerate(nodes):
        node = program.nodes[node_id]
        leaving = edges[index] if index < len(edges) else None
        steps.append(
            {
                "symbol": _display(node_id),
                "node": node_id,
                "kind": node.kind,
                "package": None if node.owner == APP_OWNER else node.owner,
                "file": node.path,
                "line": node.line,
                "call": None
                if leaving is None
                else {
                    "file": leaving.path,
                    "line": leaving.line,
                    "col": leaving.col,
                    "edge": leaving.kind,
                },
            }
        )
    return steps


def find_paths(
    program: Program, roots: list[Root], targets: set[str], kinds: frozenset[str]
) -> list[dict[str, Any]]:
    """Shortest paths to the targets, preferring ones that start at a real entry point."""
    entry = [root for root in roots if root.kind in ENTRYPOINT_KINDS]
    root_kind = {root.node: root.kind for root in roots}
    for tier in (entry, roots):
        if not tier:
            continue
        search = _bfs if kinds <= STRONG_EDGES else _weighted
        parent = search(program, (root.node for root in tier), kinds)
        hits = sorted(target for target in targets if target in parent)
        if not hits:
            continue
        paths = []
        for target in hits[:MAX_PATHS]:
            edges = _path(parent, target)
            start = edges[0].source if edges else target
            paths.append(
                {
                    "entrypoint_kind": root_kind.get(start, RootKind.FUNCTION),
                    "edge_kinds": sorted({edge.kind for edge in edges}),
                    "steps": to_steps(program, edges, start),
                }
            )
        return paths
    return []


@dataclass
class AnalysisContext:
    program: Program
    roots: list[Root]
    reachable: set[str]
    package_states: dict[str, PackageState]
    package_modules: dict[str, set[str]]
    budget_exceeded: bool = False

    @classmethod
    def build(
        cls,
        program: Program,
        package_states: dict[str, PackageState],
        package_modules: dict[str, set[str]],
        *,
        budget_exceeded: bool = False,
    ) -> "AnalysisContext":
        roots = app_roots(program)
        return cls(
            program,
            roots,
            reachable_nodes(program, roots),
            package_states,
            package_modules,
            budget_exceeded,
        )

    def reachable_dynamic(self, kind: DynamicKind) -> list[dict[str, Any]]:
        return [
            {
                "file": path,
                "line": site.line,
                "detail": site.detail,
                "owner": self.program.owner_of(source),
            }
            for source, site, path in self.program.dynamic
            if site.kind is kind and source in self.reachable
        ]

    def incomplete_imports(self) -> list[str]:
        return sorted(
            name
            for name, state in self.package_states.items()
            if state in (PackageState.UNPINNED, PackageState.UNAVAILABLE)
        )


def _reason(
    code: ReasonCode, message: str, locations: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    reason: dict[str, Any] = {"code": str(code), "message": message}
    if locations:
        reason["locations"] = locations[:MAX_LOCATIONS]
        reason["location_count"] = len(locations)
    return reason


def _needs_review(reasons: list[dict[str, Any]], **extra: Any) -> Outcome:
    return Outcome(Verdict.NEEDS_REVIEW, Confidence.LOW, reasons, **extra)


@dataclass(frozen=True)
class _ResolvedSymbols:
    targets: set[str]
    short_names: set[str]
    report: list[dict[str, Any]]
    origins: set[SymbolOrigin]
    modules: set[str]


def _resolve_symbols(
    ctx: AnalysisContext, package: str, symbols: list[SymbolInput]
) -> _ResolvedSymbols:
    resolver = ctx.program.resolver
    own_modules = ctx.package_modules.get(package, set())
    targets: set[str] = set()
    short_names: set[str] = set()
    report: list[dict[str, Any]] = []
    origins: set[SymbolOrigin] = set()
    modules: set[str] = set()
    for symbol in symbols:
        target = resolver.resolve(symbol.qualified_name)
        entry: dict[str, Any] = {"requested": symbol.qualified_name, "origin": str(symbol.origin)}
        if isinstance(target, DefTarget) and target.module in own_modules:
            node = ctx.program.nodes.get(target.qualname)
            entry |= {
                "status": "found",
                "canonical": target.qualname,
                "kind": target.definition.kind,
                "file": node.path if node else None,
                "line": target.definition.line,
            }
            targets.add(target.qualname)
            short_names.add(target.qualname.rsplit(".", 1)[-1])
            modules.add(target.module)
            if target.definition.kind == "class":
                members = resolver.class_members(target.qualname)
                targets.update(members)
                short_names.update(member.rsplit(".", 1)[-1] for member in members)
            origins.add(symbol.origin)
        elif isinstance(target, ModuleTarget) and target.module in own_modules:
            entry |= {"status": "found", "canonical": target.module, "kind": "module"}
            targets.add(module_node(target.module))
            modules.add(target.module)
            origins.add(symbol.origin)
        else:
            entry["status"] = "not_found"
        report.append(entry)
    return _ResolvedSymbols(targets, short_names, report, origins, modules)


def decide(ctx: AnalysisContext, package: str, symbols: list[SymbolInput]) -> Outcome:
    state = ctx.package_states.get(package, PackageState.NOT_IMPORTED)

    if state is PackageState.UNPINNED:
        return _needs_review(
            [
                _reason(
                    ReasonCode.VERSION_UNPINNED,
                    (
                        "The installed version is not pinned in a lockfile, so "
                        "the exact code cannot be analysed."
                    ),
                )
            ]
        )
    if state is PackageState.UNAVAILABLE:
        return _needs_review(
            [
                _reason(
                    ReasonCode.SOURCE_UNAVAILABLE,
                    "The package's published source could not be obtained for analysis.",
                )
            ]
        )
    if state is PackageState.NOT_IMPORTED:
        return _not_imported(ctx, package)

    resolved = _resolve_symbols(ctx, package, symbols)
    if ctx.budget_exceeded:
        return _needs_review(
            [
                _reason(
                    ReasonCode.BUDGET_EXCEEDED,
                    "Analysis stopped at its resource limits before completing.",
                )
            ],
            symbols=resolved.report,
        )
    if not resolved.targets:
        context_paths = find_paths(
            ctx.program,
            ctx.roots,
            {module_node(m) for m in ctx.package_modules.get(package, set())},
            STRONG_EDGES,
        )[:1]
        message = (
            "The package is imported, but no vulnerable function is known for this advisory."
            if not symbols
            else (
                "None of the advisory's vulnerable symbols exist in the installed version's source."
            )
        )
        return _needs_review(
            [_reason(ReasonCode.NO_VERIFIED_SYMBOLS, message)],
            paths=context_paths,
            symbols=resolved.report,
        )

    strong = find_paths(ctx.program, ctx.roots, resolved.targets, STRONG_EDGES)
    if strong:
        uses_inference = any(EdgeKind.METHOD in path["edge_kinds"] for path in strong[:1])
        trusted = resolved.origins <= TRUSTED_ORIGINS
        confidence = Confidence.HIGH if trusted and not uses_inference else Confidence.MEDIUM
        return Outcome(
            Verdict.REACHABLE,
            confidence,
            [
                _reason(
                    ReasonCode.PATH_FOUND,
                    "A static call path leads from application code to a vulnerable symbol.",
                )
            ],
            paths=strong,
            symbols=resolved.report,
        )

    possible = find_paths(ctx.program, ctx.roots, resolved.targets, ALL_EDGES)
    if possible:
        kinds = set(possible[0]["edge_kinds"])
        if EdgeKind.NAME_MATCH in kinds:
            reason = _reason(
                ReasonCode.DYNAMIC_DISPATCH,
                "A path exists only through calls whose target is not statically known "
                "(an object of unknown type calls a method with the vulnerable method's name).",
            )
        elif EdgeKind.REFERENCE in kinds:
            reason = _reason(
                ReasonCode.REFERENCE_ONLY,
                "A vulnerable function is referenced as a value (for example registered as a "
                "callback or filter) on a reachable path, but no direct call was found.",
            )
        else:
            reason = _reason(
                ReasonCode.DYNAMIC_IMPORT,
                "The vulnerable module is reachable only through a module name that application "
                "code passes as a string.",
            )
        return _needs_review([reason], paths=possible, symbols=resolved.report)

    blockers = _blockers(ctx, package, resolved)
    if blockers:
        return _needs_review(blockers, symbols=resolved.report)

    trusted = resolved.origins <= TRUSTED_ORIGINS
    return Outcome(
        Verdict.NOT_REACHED,
        Confidence.HIGH if trusted else Confidence.MEDIUM,
        [
            _reason(
                ReasonCode.NO_PATH,
                (
                    "The vulnerable symbols exist in the installed version, the package is "
                    "imported, and no call path from application code reaches them."
                ),
            )
        ],
        symbols=resolved.report,
    )


def _not_imported(ctx: AnalysisContext, package: str) -> Outcome:
    incomplete = ctx.incomplete_imports()
    if incomplete:
        return _needs_review(
            [
                _reason(
                    ReasonCode.INCOMPLETE_IMPORT_GRAPH,
                    (
                        f"Not imported by analysed code, but these imported dependencies could not "
                        f"be analysed and might import it: {', '.join(incomplete)}."
                    ),
                )
            ]
        )
    dynamic = ctx.reachable_dynamic(DynamicKind.IMPORT)
    in_app = [site for site in dynamic if site["owner"] == APP_OWNER]
    if in_app:
        return _needs_review(
            [
                _reason(
                    ReasonCode.DYNAMIC_IMPORT,
                    (
                        "Not imported statically, but application code "
                        "imports modules by computed name."
                    ),
                    in_app,
                )
            ]
        )
    message = (
        f"No module of {package} is imported by the application or by any dependency it imports."
    )
    if dynamic:
        # Documented assumption: a dependency's computed imports (e.g. Flask's import_string)
        # load names the application supplies; dotted names in application strings are already
        # followed as potential imports. Lower confidence because the assumption is unverified.
        return Outcome(
            Verdict.NOT_REACHED,
            Confidence.MEDIUM,
            [
                _reason(ReasonCode.PACKAGE_NOT_IMPORTED, message),
                _reason(
                    ReasonCode.DYNAMIC_IMPORT,
                    (
                        "Imported dependencies also import modules by computed name; Sieve "
                        "assumes those names come from the application and found none naming "
                        "this package."
                    ),
                    dynamic,
                ),
            ],
        )
    return Outcome(
        Verdict.NOT_REACHED, Confidence.HIGH, [_reason(ReasonCode.PACKAGE_NOT_IMPORTED, message)]
    )


def _blockers(
    ctx: AnalysisContext, package: str, resolved: _ResolvedSymbols
) -> list[dict[str, Any]]:
    program = ctx.program
    own_tops = {module.split(".")[0] for module in ctx.package_modules.get(package, set())}
    blockers = []

    failed = sorted(
        summary.path
        for name, summary in program.modules.items()
        if summary.parse_error and (program.owners.get(name) in (APP_OWNER, package))
    )
    if failed:
        blockers.append(
            _reason(
                ReasonCode.PARSE_FAILURE,
                "Some relevant source files could not be parsed.",
                [{"file": f} for f in failed],
            )
        )

    escaped = any(
        edge.source in ctx.reachable
        for module in resolved.modules
        for edge in program.escaped_modules.get(module, [])
    )
    # Method symbols are already covered by name-match edges; module-level functions can only
    # be hit by an unknown receiver if their module object escapes, or via an unresolvable
    # dotted call into the package.
    dispatch = [
        {"file": call.path, "line": call.line, "detail": call.attr}
        for call in program.unresolved
        if call.source in ctx.reachable
        and call.attr in resolved.short_names
        and (escaped or (call.ref is not None and call.ref.split(".")[0] in own_tops))
    ]
    if dispatch:
        blockers.append(
            _reason(
                ReasonCode.DYNAMIC_DISPATCH,
                "Reachable calls with statically unknown targets use the vulnerable symbol's name.",
                dispatch,
            )
        )

    attribute_access = [
        site
        for site in ctx.reachable_dynamic(DynamicKind.GETATTR)
        if site["detail"] and site["detail"].split(".")[0] in own_tops
    ]
    if attribute_access:
        blockers.append(
            _reason(
                ReasonCode.DYNAMIC_ATTRIBUTE,
                "Reachable code looks up attributes of the package by computed name.",
                attribute_access,
            )
        )
    return blockers
