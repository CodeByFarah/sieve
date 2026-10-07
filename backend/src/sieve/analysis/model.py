"""Per-module facts extracted by the indexer.

A ``ModuleSummary`` is everything the call graph needs from one source file, with names already
resolved *within* the module (imports, aliases, local scopes). Cross-module resolution happens
later in ``program.py``. Summaries are cached as JSON — never pickle, because cached artifacts may
live in shared storage and must not be able to execute code when loaded.
"""

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

INDEX_FORMAT_VERSION = 2
MODULE_NODE_PREFIX = "module:"


def module_node(module: str) -> str:
    return f"{MODULE_NODE_PREFIX}{module}"


class CallKind(StrEnum):
    CALL = "call"  # callee named through imports/aliases/attributes: yaml.load(...), helper(...)
    METHOD = "method"  # receiver type inferred: self.x(), Foo().x(), obj.x() where obj = Foo()
    REFERENCE = "reference"  # function used as a value: callbacks, registries, decorators
    UNRESOLVED = "unresolved"  # dynamic: unknown receiver, callable variable


class RootKind(StrEnum):
    HTTP_ROUTE = "http_route"
    CLI_COMMAND = "cli_command"
    TASK = "task"
    MAIN = "main"
    FUNCTION = "app_function"
    MODULE = "module_import"


class DynamicKind(StrEnum):
    IMPORT = "dynamic_import"  # importlib.import_module(var), __import__(var)
    GETATTR = "dynamic_getattr"  # getattr(module, var)
    EXEC = "exec"  # eval / exec / compile


@dataclass(frozen=True)
class RawCall:
    scope: str  # local qualified name of the calling function; "" is the module body
    kind: CallKind
    line: int
    col: int
    ref: str | None = None
    receiver: str | None = None
    attr: str | None = None


@dataclass(frozen=True)
class RawImport:
    scope: str
    module: str
    line: int
    optional: bool = False  # "from x import y": x.y may be an attribute rather than a module


@dataclass(frozen=True)
class Definition:
    local: str  # "func", "Class", "Class.method", "outer.inner"
    kind: str  # "function" | "method" | "class"
    line: int
    end_line: int
    root: RootKind | None = None
    bases: tuple[str, ...] = ()


@dataclass(frozen=True)
class DynamicSite:
    scope: str
    kind: DynamicKind
    line: int
    detail: str | None = None


@dataclass
class ModuleSummary:
    name: str
    path: str
    is_package: bool
    parse_error: str | None = None
    definitions: dict[str, Definition] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    instances: dict[str, str] = field(default_factory=dict)
    class_attributes: dict[str, dict[str, str]] = field(default_factory=dict)
    calls: list[RawCall] = field(default_factory=list)
    imports: list[RawImport] = field(default_factory=list)
    star_imports: list[str] = field(default_factory=list)
    dynamic: list[DynamicSite] = field(default_factory=list)
    string_refs: list[str] = field(default_factory=list)
    has_main_guard: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleSummary":
        return cls(
            name=data["name"],
            path=data["path"],
            is_package=data["is_package"],
            parse_error=data["parse_error"],
            definitions={
                key: Definition(
                    local=value["local"],
                    kind=value["kind"],
                    line=value["line"],
                    end_line=value["end_line"],
                    root=RootKind(value["root"]) if value["root"] else None,
                    bases=tuple(value["bases"]),
                )
                for key, value in data["definitions"].items()
            },
            aliases=dict(data["aliases"]),
            instances=dict(data["instances"]),
            class_attributes={k: dict(v) for k, v in data["class_attributes"].items()},
            calls=[RawCall(**{**call, "kind": CallKind(call["kind"])}) for call in data["calls"]],
            imports=[RawImport(**entry) for entry in data["imports"]],
            star_imports=list(data["star_imports"]),
            dynamic=[
                DynamicSite(**{**site, "kind": DynamicKind(site["kind"])})
                for site in data["dynamic"]
            ],
            string_refs=list(data["string_refs"]),
            has_main_guard=data["has_main_guard"],
        )
