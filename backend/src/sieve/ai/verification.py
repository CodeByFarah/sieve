"""Deterministic verification of proposed symbols against the package's real source.

A candidate is accepted only if:
1. it resolves to a definition (or module) inside the package at the vulnerable version;
2. its kind matches what the model claimed;
3. when a fix diff is available, it is a function the fix touched, or it directly calls one.
"""

from dataclasses import dataclass

from sieve.ai.diffs import Touched
from sieve.ai.guardrails import Candidate
from sieve.analysis.discovery import discover_dist_sources
from sieve.analysis.engine import SourceProvider
from sieve.analysis.program import DefTarget, ModuleTarget, Program, build_program
from sieve.analysis.sandbox import Indexer


@dataclass(frozen=True)
class Verified:
    name: str
    claimed_kind: str
    accepted: bool
    reason: str
    canonical: str | None = None
    kind: str | None = None
    file: str | None = None
    line: int | None = None
    diff_match: bool | None = None


@dataclass
class PackageSource:
    program: Program
    modules: set[str]


def load_package(
    sources: SourceProvider, indexer: Indexer, name: str, version: str
) -> PackageSource:
    fetched = sources.fetch(name, version)
    summaries = indexer.index(fetched.root, discover_dist_sources(fetched.root))
    return PackageSource(build_program([(s, name) for s in summaries]), {s.name for s in summaries})


def canonical(package: PackageSource, name: str) -> str | None:
    target = package.program.resolver.resolve(name)
    if isinstance(target, DefTarget) and target.module in package.modules:
        return target.qualname
    if isinstance(target, ModuleTarget) and target.module in package.modules:
        return target.module
    return None


def _found(
    candidate: Candidate,
    target: DefTarget,
    package: PackageSource,
    accepted: bool,
    reason: str,
    diff_match: bool | None = None,
) -> Verified:
    node = package.program.nodes.get(target.qualname)
    return Verified(
        name=candidate.name,
        claimed_kind=candidate.kind,
        accepted=accepted,
        reason=reason,
        canonical=target.qualname,
        kind=target.definition.kind,
        file=node.path if node else None,
        line=target.definition.line,
        diff_match=diff_match,
    )


def verify(
    package: PackageSource, candidates: list[Candidate], changes: Touched | None
) -> list[Verified]:
    resolver = package.program.resolver
    touched_names = changes.functions if changes else set()
    results = []
    for candidate in candidates:
        target = resolver.resolve(candidate.name)
        if isinstance(target, ModuleTarget) and target.module in package.modules:
            accepted = candidate.kind == "module"
            reason = "verified_in_source" if accepted else "kind_mismatch"
            results.append(
                Verified(candidate.name, candidate.kind, accepted, reason, target.module, "module")
            )
            continue
        if not (isinstance(target, DefTarget) and target.module in package.modules):
            results.append(Verified(candidate.name, candidate.kind, False, "not_found_in_source"))
            continue
        if target.definition.kind != candidate.kind:
            results.append(_found(candidate, target, package, False, "kind_mismatch"))
            continue
        if not touched_names:
            results.append(_found(candidate, target, package, True, "verified_in_source"))
            continue
        edges = package.program.edges.get(target.qualname, [])
        callees = {edge.target.rsplit(".", 1)[-1] for edge in edges}
        short = target.qualname.rsplit(".", 1)[-1]
        if short in touched_names or callees & touched_names:
            results.append(
                _found(candidate, target, package, True, "verified_in_source_and_fix", True)
            )
        else:
            results.append(_found(candidate, target, package, False, "unrelated_to_fix", False))
    return results
