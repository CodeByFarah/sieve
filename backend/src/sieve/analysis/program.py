"""Cross-module name resolution and the call graph.

Nodes are functions, methods, classes and module bodies (``module:<name>``), identified by their
fully-qualified name. Edges carry the call-site location and how the edge was established.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from sieve.analysis.model import (
    CallKind,
    Definition,
    DynamicSite,
    ModuleSummary,
    RawCall,
    module_node,
)

APP_OWNER = "<app>"
MAX_RESOLUTION_DEPTH = 25


class EdgeKind:
    CALL = "call"
    METHOD = "method"
    IMPORT = "import"
    REFERENCE = "reference"
    # Over-approximations for code we cannot resolve statically. They never support a
    # `reachable` verdict, but they do prevent a `not_reached` one.
    NAME_MATCH = "name_match"  # unknown receiver: obj.send() may be any method named send
    DYNAMIC_IMPORT = "dynamic_import"  # dotted name in an application string literal


STRONG_EDGES = frozenset({EdgeKind.CALL, EdgeKind.METHOD, EdgeKind.IMPORT})
ALL_EDGES = STRONG_EDGES | {EdgeKind.REFERENCE, EdgeKind.NAME_MATCH, EdgeKind.DYNAMIC_IMPORT}


@dataclass(frozen=True)
class Node:
    id: str
    kind: str  # "module" | "function" | "method" | "class"
    module: str
    owner: str  # distribution name, or APP_OWNER
    path: str
    line: int
    root: str | None = None


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str
    path: str
    line: int
    col: int


@dataclass(frozen=True)
class UnresolvedCall:
    source: str
    attr: str | None
    path: str
    line: int
    ref: str | None = None  # set when the call named indexed code we could not resolve


@dataclass(frozen=True)
class ModuleTarget:
    module: str


@dataclass(frozen=True)
class DefTarget:
    qualname: str
    definition: Definition
    module: str


@dataclass(frozen=True)
class InstanceTarget:
    class_qualname: str


Target = ModuleTarget | DefTarget | InstanceTarget


class Resolver:
    def __init__(self, modules: dict[str, ModuleSummary]) -> None:
        self.modules = modules
        self.definitions: dict[str, DefTarget] = {}
        for summary in modules.values():
            for local, definition in summary.definitions.items():
                qualname = f"{summary.name}.{local}"
                self.definitions[qualname] = DefTarget(qualname, definition, summary.name)
        self._top_levels = frozenset(name.split(".")[0] for name in modules)
        self._cache: dict[str, Target | None] = {}

    def known_top_level(self, ref: str) -> bool:
        """Whether a reference points into indexed code (as opposed to stdlib or unindexed)."""
        return ref.split(".")[0] in self._top_levels

    def resolve(self, ref: str, depth: int = 0) -> Target | None:
        if depth == 0 and ref in self._cache:
            return self._cache[ref]
        result = self._resolve(ref, depth)
        if depth == 0:
            self._cache[ref] = result
        return result

    def _resolve(self, ref: str, depth: int) -> Target | None:
        if depth > MAX_RESOLUTION_DEPTH:
            return None
        if ref in self.definitions:
            return self.definitions[ref]
        parts = ref.split(".")
        for split in range(len(parts), 0, -1):
            module = ".".join(parts[:split])
            if module in self.modules:
                return self._resolve_in(module, parts[split:], depth)
        return None

    def _resolve_in(self, module: str, rest: list[str], depth: int) -> Target | None:
        if not rest:
            return ModuleTarget(module)
        summary = self.modules[module]
        head, tail = rest[0], rest[1:]
        definition = summary.definitions.get(head)
        if definition is not None:
            target = self.definitions[f"{module}.{head}"]
            if not tail:
                return target
            if definition.kind == "class":
                return self._member(target.qualname, tail, depth)
            return None
        if head in summary.aliases:
            return self.resolve(".".join([summary.aliases[head], *tail]), depth + 1)
        if head in summary.instances:
            cls = self.resolve(summary.instances[head], depth + 1)
            if isinstance(cls, DefTarget) and cls.definition.kind == "class":
                return (
                    InstanceTarget(cls.qualname)
                    if not tail
                    else self._member(cls.qualname, tail, depth)
                )
            return None
        submodule = f"{module}.{head}"
        if submodule in self.modules:
            return self._resolve_in(submodule, tail, depth)
        for star in summary.star_imports:
            found = self.resolve(".".join([star, head, *tail]), depth + 1)
            if found is not None:
                return found
        return None

    def _member(self, class_qualname: str, tail: list[str], depth: int) -> Target | None:
        found = self.lookup_member(class_qualname, tail[0])
        if found is None or len(tail) == 1:
            return found
        if found.definition.kind == "class":
            return self._member(found.qualname, tail[1:], depth + 1)
        return None

    def lookup_member(
        self, class_qualname: str, attr: str, seen: frozenset[str] = frozenset()
    ) -> DefTarget | None:
        """Method resolution along the base classes (depth-first, left to right)."""
        if class_qualname in seen or len(seen) > MAX_RESOLUTION_DEPTH:
            return None
        own = self.definitions.get(f"{class_qualname}.{attr}")
        if own is not None:
            return own
        cls = self.definitions.get(class_qualname)
        if cls is None:
            return None
        for base_ref in cls.definition.bases:
            base = self.resolve(base_ref)
            if isinstance(base, DefTarget) and base.definition.kind == "class":
                found = self.lookup_member(base.qualname, attr, seen | {class_qualname})
                if found is not None:
                    return found
        return None

    def class_members(self, class_qualname: str) -> list[str]:
        prefix = f"{class_qualname}."
        return [q for q in self.definitions if q.startswith(prefix)]


@dataclass
class Program:
    modules: dict[str, ModuleSummary]
    owners: dict[str, str]
    resolver: Resolver
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[str, list[Edge]] = field(default_factory=lambda: defaultdict(list))
    unresolved: list[UnresolvedCall] = field(default_factory=list)
    dynamic: list[tuple[str, DynamicSite, str]] = field(default_factory=list)
    escaped_modules: dict[str, list[Edge]] = field(default_factory=lambda: defaultdict(list))
    owner_imports: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    external_calls: int = 0

    def owner_of(self, node_id: str) -> str | None:
        node = self.nodes.get(node_id)
        return node.owner if node else None

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self.edges.values())


def _node_id(summary: ModuleSummary, scope: str) -> str:
    return f"{summary.name}.{scope}" if scope else module_node(summary.name)


class _Builder:
    def __init__(self, program: Program) -> None:
        self.p = program
        self.r = program.resolver
        self.methods_by_name: dict[str, list[str]] = defaultdict(list)
        for qualname, target in self.r.definitions.items():
            if target.definition.kind == "method":
                self.methods_by_name[qualname.rsplit(".", 1)[-1]].append(qualname)

    def unresolved(
        self,
        summary: ModuleSummary,
        source: str,
        call: RawCall,
        attr: str | None,
        ref: str | None = None,
    ) -> None:
        self.p.unresolved.append(UnresolvedCall(source, attr, summary.path, call.line, ref))
        if attr is None or (attr.startswith("__") and attr.endswith("__")):
            return  # protocol methods would match nearly every class; documented limitation
        for candidate in self.methods_by_name.get(attr, ()):
            self.edge(source, candidate, EdgeKind.NAME_MATCH, summary, call.line, call.col)

    def string_import_edges(self, summary: ModuleSummary) -> None:
        source = module_node(summary.name)
        for text in summary.string_refs:
            parts = text.split(":")[0].split(".")
            for end in range(len(parts), 0, -1):
                module = ".".join(parts[:end])
                if module in self.p.modules:
                    self.edge(source, module_node(module), EdgeKind.DYNAMIC_IMPORT, summary, 1, 0)
                    break

    def add_nodes(self, summary: ModuleSummary, owner: str) -> None:
        self.p.nodes[module_node(summary.name)] = Node(
            module_node(summary.name),
            "module",
            summary.name,
            owner,
            summary.path,
            1,
            "main" if summary.has_main_guard else None,
        )
        for local, definition in summary.definitions.items():
            qualname = f"{summary.name}.{local}"
            self.p.nodes[qualname] = Node(
                qualname,
                definition.kind,
                summary.name,
                owner,
                summary.path,
                definition.line,
                str(definition.root) if definition.root else None,
            )

    def edge(
        self, source: str, target: str, kind: str, summary: ModuleSummary, line: int, col: int
    ) -> None:
        if target in self.p.nodes and source in self.p.nodes:
            self.p.edges[source].append(Edge(source, target, kind, summary.path, line, col))

    def import_edges(self, summary: ModuleSummary) -> None:
        for entry in summary.imports:
            source = _node_id(summary, entry.scope)
            parts = entry.module.split(".")
            # Importing a.b.c runs a/__init__, a/b/__init__ and a/b/c, in that order.
            for end in range(1, len(parts) + 1):
                module = ".".join(parts[:end])
                if module in self.p.modules:
                    self.edge(source, module_node(module), EdgeKind.IMPORT, summary, entry.line, 0)

    def call_edges(self, summary: ModuleSummary) -> None:
        for call in summary.calls:
            source = _node_id(summary, call.scope)
            if call.kind is CallKind.UNRESOLVED:
                self.unresolved(summary, source, call, call.attr)
            elif call.kind is CallKind.METHOD:
                self._method(summary, source, call)
            else:
                self._named(summary, source, call)
        for site in summary.dynamic:
            self.p.dynamic.append((_node_id(summary, site.scope), site, summary.path))

    def _target_edges(
        self, summary: ModuleSummary, source: str, target: DefTarget, kind: str, call: RawCall
    ) -> None:
        self.edge(source, target.qualname, kind, summary, call.line, call.col)
        if target.definition.kind == "class" and kind != EdgeKind.REFERENCE:
            init = self.r.lookup_member(target.qualname, "__init__")
            if init is not None:
                self.edge(source, init.qualname, kind, summary, call.line, call.col)

    def _named(self, summary: ModuleSummary, source: str, call: RawCall) -> None:
        assert call.ref is not None  # noqa: S101 - CALL and REFERENCE always carry a ref
        target = self.r.resolve(call.ref)
        kind = EdgeKind.REFERENCE if call.kind is CallKind.REFERENCE else EdgeKind.CALL
        if isinstance(target, DefTarget):
            self._target_edges(summary, source, target, kind, call)
        elif isinstance(target, ModuleTarget):
            if call.kind is CallKind.REFERENCE:
                self.p.escaped_modules[target.module].append(
                    Edge(
                        source, module_node(target.module), kind, summary.path, call.line, call.col
                    )
                )
        elif isinstance(target, InstanceTarget):
            dunder = self.r.lookup_member(target.class_qualname, "__call__")
            if dunder is not None and call.kind is CallKind.CALL:
                self.edge(source, dunder.qualname, EdgeKind.METHOD, summary, call.line, call.col)
        elif call.kind is CallKind.CALL:
            if self.r.known_top_level(call.ref):
                # Into code we have, but not to anything we could name: treat as dynamic.
                self.unresolved(summary, source, call, call.ref.rsplit(".", 1)[-1], call.ref)
            else:
                self.p.external_calls += 1

    def _method(self, summary: ModuleSummary, source: str, call: RawCall) -> None:
        assert call.receiver is not None and call.attr is not None  # noqa: S101
        if call.receiver.startswith("super:"):
            self._super(summary, source, call, call.receiver.removeprefix("super:"))
            return
        receiver = self.r.resolve(call.receiver)
        if isinstance(receiver, DefTarget) and receiver.definition.kind == "class":
            member = self.r.lookup_member(receiver.qualname, call.attr)
            if member is not None:
                self._target_edges(summary, source, member, EdgeKind.METHOD, call)
                return
        elif receiver is None and not self.r.known_top_level(call.receiver):
            self.p.external_calls += 1  # e.g. a stdlib object: cannot reach indexed packages
            return
        self.unresolved(summary, source, call, call.attr)

    def _super(
        self, summary: ModuleSummary, source: str, call: RawCall, class_qualname: str
    ) -> None:
        assert call.attr is not None  # noqa: S101
        cls = self.r.definitions.get(class_qualname)
        for base_ref in cls.definition.bases if cls else ():
            base = self.r.resolve(base_ref)
            if isinstance(base, DefTarget) and base.definition.kind == "class":
                member = self.r.lookup_member(base.qualname, call.attr)
                if member is not None:
                    self._target_edges(summary, source, member, EdgeKind.METHOD, call)
                    return
            elif base is None and not self.r.known_top_level(base_ref):
                self.p.external_calls += 1  # e.g. super().__init__() into Exception
                return
        self.unresolved(summary, source, call, call.attr)


def build_program(summaries: Iterable[tuple[ModuleSummary, str]]) -> Program:
    pairs = list(summaries)
    modules = {summary.name: summary for summary, _ in pairs}
    program = Program(
        modules=modules,
        owners={summary.name: owner for summary, owner in pairs},
        resolver=Resolver(modules),
    )
    builder = _Builder(program)
    for summary, owner in pairs:
        builder.add_nodes(summary, owner)
    for summary, owner in pairs:
        builder.import_edges(summary)
        builder.call_edges(summary)
        if owner == APP_OWNER:
            builder.string_import_edges(summary)
    # Which packages import which: used to rank possible paths by plausibility.
    for edges in program.edges.values():
        for edge in edges:
            if edge.kind == EdgeKind.IMPORT:
                source_owner = program.owner_of(edge.source)
                target_owner = program.owner_of(edge.target)
                if source_owner and target_owner and source_owner != target_owner:
                    program.owner_imports[source_owner].add(target_owner)
    return program
