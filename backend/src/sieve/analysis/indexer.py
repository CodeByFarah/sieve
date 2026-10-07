"""Single-module indexing: ``ast`` → ``ModuleSummary``.

Resolution inside a module follows Python's scoping closely enough for call-graph purposes:
function scopes see enclosing function scopes and module globals but not class bodies; module
globals are collected in a pre-pass so a function may call something defined further down.
Anything the indexer cannot name precisely is recorded as UNRESOLVED (with the attribute name, if
any) or as a dynamic site — never silently dropped, because unresolved calls are what keeps the
verdict honest.
"""

import ast
import builtins
import re
import warnings
from dataclasses import dataclass

from sieve.analysis.model import (
    CallKind,
    Definition,
    DynamicKind,
    DynamicSite,
    ModuleSummary,
    RawCall,
    RawImport,
    RootKind,
)

_BUILTINS = frozenset(dir(builtins))
_HTTP_DECORATORS = frozenset(
    {"route", "get", "post", "put", "patch", "delete", "head", "options", "websocket", "api_route"}
)
_CLI_DECORATORS = frozenset({"command", "group"})
_TASK_DECORATORS = frozenset({"task", "shared_task", "periodic_task"})
_DYNAMIC_IMPORTERS = frozenset({"importlib.import_module", "importlib.__import__"})
_DOTTED_NAME = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+(:[A-Za-z_]\w*)?$")


@dataclass(frozen=True)
class _Binding:
    kind: str  # "ref" | "instance" | "self" | "unknown"
    value: str | None = None


class _Scope:
    def __init__(self, local: str, kind: str, cls: str | None = None) -> None:
        self.local = local  # "" for the module
        self.kind = kind  # "module" | "class" | "function"
        self.cls = cls  # local qualname of the class whose method this is
        self.names: dict[str, _Binding] = {}


def _root_kind(decorators: list[ast.expr]) -> RootKind | None:
    for decorator in decorators:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
        if name in _HTTP_DECORATORS and isinstance(decorator, ast.Call):
            return RootKind.HTTP_ROUTE
        if name in _CLI_DECORATORS:
            return RootKind.CLI_COMMAND
        if name in _TASK_DECORATORS:
            return RootKind.TASK
    return None


def _decorator_names(decorators: list[ast.expr]) -> set[str]:
    return {d.id for d in decorators if isinstance(d, ast.Name)}


def _literal_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_main_guard(test: ast.expr) -> bool:
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.comparators) == 1
        and _literal_str(test.comparators[0]) == "__main__"
    )


class ModuleIndexer(ast.NodeVisitor):
    def __init__(self, module: str, path: str, is_package: bool) -> None:
        self.module = module
        self.package = module if is_package else module.rpartition(".")[0]
        self.summary = ModuleSummary(name=module, path=path, is_package=is_package)
        self.scopes: list[_Scope] = [_Scope("", "module")]
        self.consumed: set[int] = set()

    # ----------------------------------------------------------------- scope helpers

    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def _caller(self) -> str:
        """Code in a class body runs when the enclosing scope runs."""
        for scope in reversed(self.scopes):
            if scope.kind != "class":
                return scope.local
        return ""

    def _prefix(self) -> str:
        return f"{self.scope.local}." if self.scope.local else ""

    def _bind(self, name: str, binding: _Binding) -> None:
        self.scope.names[name] = binding
        if self.scope.kind == "module":
            self.summary.aliases.pop(name, None)
            self.summary.instances.pop(name, None)
            if binding.kind == "ref" and binding.value:
                self.summary.aliases[name] = binding.value
            elif binding.kind == "instance" and binding.value:
                self.summary.instances[name] = binding.value

    def _lookup(self, name: str) -> _Binding | None:
        if name in self.scope.names:
            return self.scope.names[name]
        for scope in reversed(self.scopes[:-1]):
            if scope.kind == "class":
                continue
            if name in scope.names:
                return scope.names[name]
        return None

    def _absolute(self, module: str | None, level: int) -> str | None:
        if level == 0:
            return module
        base = self.package.split(".") if self.package else []
        if level - 1 > len(base):
            return None
        base = base[: len(base) - (level - 1)]
        if module:
            base += module.split(".")
        return ".".join(base) or None

    def _global(self, local: str) -> str:
        return f"{self.module}.{local}"

    # ----------------------------------------------------------------- expressions

    def ref(self, expr: ast.expr) -> str | None:
        """Absolute dotted reference an expression denotes, if it can be named statically."""
        if isinstance(expr, ast.Name):
            binding = self._lookup(expr.id)
            if binding is not None and binding.kind == "ref":
                return binding.value
            if binding is None and expr.id not in _BUILTINS and self.summary.star_imports:
                # Possibly provided by `from x import *`; the resolver searches star imports.
                return self._global(expr.id)
            return None
        if isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name):
                binding = self._lookup(expr.value.id)
                if binding is not None and binding.kind == "self" and binding.value:
                    return f"{self._global(binding.value)}.{expr.attr}"
                if binding is not None and binding.kind == "instance" and binding.value:
                    # A bound method (`decode = _jwt_global_obj.decode`) names the class member.
                    return f"{binding.value}.{expr.attr}"
            base = self.ref(expr.value)
            return f"{base}.{expr.attr}" if base else None
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "getattr"
            and self._lookup("getattr") is None
            and len(expr.args) >= 2
        ):
            name = _literal_str(expr.args[1])
            base = self.ref(expr.args[0])
            if name and base:
                return f"{base}.{name}"
        return None

    def receiver_type(self, expr: ast.expr) -> str | None:
        """Class reference of the object an expression evaluates to, when inferable."""
        if isinstance(expr, ast.Name):
            binding = self._lookup(expr.id)
            if binding is None:
                return None
            if binding.kind == "instance":
                return binding.value
            if binding.kind == "self" and binding.value:
                return self._global(binding.value)
            return None
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            binding = self._lookup(expr.value.id)
            if binding is not None and binding.kind == "self" and binding.value:
                return self.summary.class_attributes.get(binding.value, {}).get(expr.attr)
            return None
        if isinstance(expr, ast.Call):
            return self.ref(expr.func)  # a call to a class yields an instance of it
        return None

    def _instance_binding(self, value: ast.expr) -> _Binding:
        if isinstance(value, ast.Call):
            callee = self.ref(value.func)
            if callee:
                return _Binding("instance", callee)
        reference = self.ref(value)
        if reference:
            return _Binding("ref", reference)
        receiver = self.receiver_type(value)
        if receiver and not isinstance(value, ast.Call):
            return _Binding("instance", receiver)
        return _Binding("unknown")

    def _consume_chain(self, expr: ast.expr) -> None:
        while isinstance(expr, ast.Attribute):
            self.consumed.add(id(expr))
            expr = expr.value
        if isinstance(expr, ast.Name):
            self.consumed.add(id(expr))

    def _record(self, kind: CallKind, node: ast.AST, **fields: str | None) -> None:
        self.summary.calls.append(
            RawCall(
                scope=self._caller(),
                kind=kind,
                line=getattr(node, "lineno", 0),
                col=getattr(node, "col_offset", 0),
                **fields,
            )
        )

    def _dynamic(self, kind: DynamicKind, node: ast.AST, detail: str | None = None) -> None:
        self.summary.dynamic.append(
            DynamicSite(self._caller(), kind, getattr(node, "lineno", 0), detail)
        )

    # ----------------------------------------------------------------- pre-pass

    def prepass(self, statements: list[ast.stmt]) -> None:
        """Bind module-level names before visiting function bodies."""
        for statement in statements:
            if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                self._bind(statement.name, _Binding("ref", self._global(statement.name)))
            elif isinstance(statement, ast.Import | ast.ImportFrom):
                self._bind_import(statement, record=False)
            elif isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name):
                    self._bind(target.id, self._instance_binding(statement.value))
            elif isinstance(statement, ast.If | ast.Try | ast.With):
                for block in ("body", "orelse", "finalbody"):
                    self.prepass(getattr(statement, block, []))
                for handler in getattr(statement, "handlers", []):
                    self.prepass(handler.body)

    # ----------------------------------------------------------------- statements

    def _bind_import(self, node: ast.Import | ast.ImportFrom, *, record: bool) -> None:
        line = node.lineno
        if isinstance(node, ast.Import):
            for alias in node.names:
                if record:
                    self.summary.imports.append(RawImport(self._caller(), alias.name, line))
                if alias.asname:
                    self._bind(alias.asname, _Binding("ref", alias.name))
                else:
                    head = alias.name.split(".")[0]
                    self._bind(head, _Binding("ref", head))
            return
        base = self._absolute(node.module, node.level)
        if base is None:
            return
        if record:
            self.summary.imports.append(RawImport(self._caller(), base, line))
        for alias in node.names:
            if alias.name == "*":
                if self.scope.kind == "module" and base not in self.summary.star_imports:
                    self.summary.star_imports.append(base)
                continue
            target = f"{base}.{alias.name}"
            if record:
                self.summary.imports.append(RawImport(self._caller(), target, line, optional=True))
            self._bind(alias.asname or alias.name, _Binding("ref", target))

    def visit_Import(self, node: ast.Import) -> None:
        self._bind_import(node, record=True)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self._bind_import(node, record=True)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in [*node.args.defaults, *[d for d in node.args.kw_defaults if d]]:
            self.visit(default)
        for annotation in self._annotations(node.args):
            self.consumed.add(id(annotation))
        local = self._prefix() + node.name
        in_class = self.scope.kind == "class"
        self.summary.definitions[local] = Definition(
            local=local,
            kind="method" if in_class else "function",
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            root=_root_kind(node.decorator_list),
        )
        self._bind(node.name, _Binding("ref", self._global(local)))

        function_scope = _Scope(local, "function", self.scope.local if in_class else None)
        positional = [*node.args.posonlyargs, *node.args.args]
        decorators = _decorator_names(node.decorator_list)
        for index, argument in enumerate([*positional, *node.args.kwonlyargs]):
            binding = _Binding("unknown")
            if in_class and index == 0 and "staticmethod" not in decorators:
                binding = _Binding("self", self.scope.local)
            elif argument.annotation is not None:
                annotated = self.ref(argument.annotation)
                if annotated:
                    binding = _Binding("instance", annotated)
            function_scope.names[argument.arg] = binding
        for extra in (node.args.vararg, node.args.kwarg):
            if extra is not None:
                function_scope.names[extra.arg] = _Binding("unknown")

        self.scopes.append(function_scope)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    @staticmethod
    def _annotations(arguments: ast.arguments) -> list[ast.expr]:
        every = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
        every += [a for a in (arguments.vararg, arguments.kwarg) if a is not None]
        return [a.annotation for a in every if a.annotation is not None]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for default in [*node.args.defaults, *[d for d in node.args.kw_defaults if d]]:
            self.visit(default)
        scope = _Scope(self._caller(), "function")
        for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
            scope.names[argument.arg] = _Binding("unknown")
        self.scopes.append(scope)
        self.visit(node.body)
        self.scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in [*node.bases, *(k.value for k in node.keywords)]:
            self.visit(base)
        local = self._prefix() + node.name
        bases = tuple(b for b in (self.ref(base) for base in node.bases) if b)
        self.summary.definitions[local] = Definition(
            local=local,
            kind="class",
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            root=_root_kind(node.decorator_list),
            bases=bases,
        )
        self._bind(node.name, _Binding("ref", self._global(local)))
        self._collect_attribute_types(local, node)
        self.scopes.append(_Scope(local, "class"))
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()

    def _collect_attribute_types(self, class_local: str, node: ast.ClassDef) -> None:
        """``self.x = Foo(...)`` anywhere in the class, and ``x: Foo`` in its body."""
        types = self.summary.class_attributes.setdefault(class_local, {})
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                annotated = self.ref(statement.annotation)
                if annotated:
                    types[statement.target.id] = annotated
            if not isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for inner in ast.walk(statement):
                if not (isinstance(inner, ast.Assign) and isinstance(inner.value, ast.Call)):
                    continue
                for target in inner.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id in ("self", "cls")
                    ):
                        callee = self.ref(inner.value.func)
                        if callee:
                            types.setdefault(target.attr, callee)

    def _bind_targets(self, target: ast.expr, binding: _Binding) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, binding)
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._bind_targets(element, _Binding("unknown"))
        elif isinstance(target, ast.Starred):
            self._bind_targets(target.value, _Binding("unknown"))

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            if not isinstance(target, ast.Name):
                self.visit(target)
        binding = (
            self._instance_binding(node.value) if len(node.targets) == 1 else _Binding("unknown")
        )
        for target in node.targets:
            self._bind_targets(target, binding)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.consumed.add(id(node.annotation))
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            annotated = self.ref(node.annotation)
            if annotated:
                self._bind(node.target.id, _Binding("instance", annotated))
            elif node.value is not None:
                self._bind(node.target.id, self._instance_binding(node.value))
        else:
            self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                binding = (
                    self._instance_binding(item.context_expr)
                    if isinstance(item.context_expr, ast.Call)
                    else _Binding("unknown")
                )
                self._bind_targets(item.optional_vars, binding)
        for statement in node.body:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_with(node)

    def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._bind_targets(node.target, _Binding("unknown"))
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node)

    def visit_If(self, node: ast.If) -> None:
        if self.scope.kind == "module" and _is_main_guard(node.test):
            self.summary.has_main_guard = True
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._bind(node.name, _Binding("unknown"))
        for statement in node.body:
            self.visit(statement)

    # ----------------------------------------------------------------- calls & references

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and self._lookup(func.id) is None and func.id in _BUILTINS:
            self._builtin_call(func.id, node)
        else:
            callee = self.ref(func)
            if callee in _DYNAMIC_IMPORTERS:
                self._dynamic_import(node)
            elif isinstance(func, ast.Attribute):
                self._attribute_call(func, node)
            elif callee:
                self._record(CallKind.CALL, node, ref=callee)
            else:
                self._record(CallKind.UNRESOLVED, node)
        self._consume_chain(func)
        self.generic_visit(node)

    def _enclosing_class(self) -> str | None:
        for scope in reversed(self.scopes):
            if scope.kind == "function" and scope.cls is not None:
                return scope.cls
        return None

    def _attribute_call(self, func: ast.Attribute, node: ast.Call) -> None:
        value = func.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "super"
            and self._lookup("super") is None
        ):
            cls = self._enclosing_class()
            if cls is not None:
                # super().m(): resolved along the base classes of the enclosing class.
                self._record(
                    CallKind.METHOD, node, receiver=f"super:{self._global(cls)}", attr=func.attr
                )
                return
        if isinstance(func.value, ast.Name):
            binding = self._lookup(func.value.id)
            if binding is not None and binding.kind == "self" and binding.value:
                self._record(
                    CallKind.METHOD, node, receiver=self._global(binding.value), attr=func.attr
                )
                return
        # A known receiver type (obj = Foo(); self.x = Foo(); Foo().m()) beats a dotted name,
        # which for `self.attr.m()` would otherwise point at a class attribute, not a method.
        receiver = self.receiver_type(func.value)
        if receiver:
            self._record(CallKind.METHOD, node, receiver=receiver, attr=func.attr)
            return
        callee = self.ref(func)
        if callee:
            self._record(CallKind.CALL, node, ref=callee)
        else:
            self._record(CallKind.UNRESOLVED, node, attr=func.attr)

    def _builtin_call(self, name: str, node: ast.Call) -> None:
        if name == "getattr" and len(node.args) >= 2 and _literal_str(node.args[1]) is None:
            target = self.ref(node.args[0])
            if target:
                self._dynamic(DynamicKind.GETATTR, node, target)
        elif name == "__import__":
            self._dynamic_import(node)
        elif name in ("eval", "exec", "compile"):
            self._dynamic(DynamicKind.EXEC, node)

    def _dynamic_import(self, node: ast.Call) -> None:
        target = _literal_str(node.args[0]) if node.args else None
        if target and not target.startswith("."):
            self.summary.imports.append(RawImport(self._caller(), target, node.lineno))
        else:
            self._dynamic(DynamicKind.IMPORT, node)

    def _reference(self, node: ast.Name | ast.Attribute) -> None:
        if id(node) in self.consumed or not isinstance(node.ctx, ast.Load):
            return
        reference = self.ref(node)
        if reference:
            self._record(CallKind.REFERENCE, node, ref=reference)

    def visit_Name(self, node: ast.Name) -> None:
        self._reference(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Dotted names in string literals ("myapp.config.Production", "PIL.Image") may be
        # imported by a framework's import_string(); the engine treats them as potential imports.
        if (
            isinstance(node.value, str)
            and len(node.value) < 200
            and _DOTTED_NAME.match(node.value)
            and node.value not in self.summary.string_refs
        ):
            self.summary.string_refs.append(node.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self._reference(node)
        if id(node) not in self.consumed:
            self._consume_chain(node.value)
        self.generic_visit(node)


def index_module(module: str, path: str, source: str | bytes, is_package: bool) -> ModuleSummary:
    """Never raises for bad input: syntax errors and pathological nesting become ``parse_error``."""
    try:
        with warnings.catch_warnings():
            # Old packages are full of invalid escape sequences; they are not our problem.
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            tree = ast.parse(source, filename=path)
        indexer = ModuleIndexer(module, path, is_package)
        indexer.prepass(tree.body)
        for statement in tree.body:
            indexer.visit(statement)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        return ModuleSummary(
            name=module,
            path=path,
            is_package=is_package,
            parse_error=f"{type(exc).__name__}: {exc}"[:500],
        )
    return indexer.summary
