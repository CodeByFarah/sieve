"""Loading, seeding and recording verification of vulnerable symbols."""

import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.analysis.reachability import SymbolInput
from sieve.db.enums import SymbolKind, SymbolOrigin, SymbolVerification
from sieve.db.models import Advisory, Package, VulnerableSymbol

_KINDS = {
    "function": SymbolKind.FUNCTION,
    "method": SymbolKind.METHOD,
    "class": SymbolKind.CLASS,
    "module": SymbolKind.MODULE,
}


@dataclass(frozen=True)
class CuratedEntry:
    ids: frozenset[str]
    package: str
    symbols: tuple[str, ...]
    rationale: str


@cache
def curated_entries() -> tuple[CuratedEntry, ...]:
    data = json.loads(files(__package__).joinpath("curated.json").read_text("utf-8"))
    return tuple(
        CuratedEntry(frozenset(e["ids"]), e["package"], tuple(e["symbols"]), e["rationale"])
        for e in data["entries"]
    )


def curated_provenance() -> str:
    data: dict[str, str] = json.loads(
        files(__package__).joinpath("curated.json").read_text("utf-8")
    )
    return data["provenance"]


def seed_curated_symbols(session: Session) -> int:
    """Attach curated symbols to every stored advisory they describe (by id or alias)."""
    inserted = 0
    for entry in curated_entries():
        ids = list(entry.ids)
        advisories = session.scalars(
            select(Advisory).where(or_(Advisory.source_id.in_(ids), Advisory.aliases.overlap(ids)))
        ).all()
        package_id = session.scalar(select(Package.id).where(Package.name == entry.package))
        if package_id is None:
            continue
        for advisory in advisories:
            for symbol in entry.symbols:
                result = session.execute(
                    insert(VulnerableSymbol)
                    .values(
                        id=uuid.uuid4(),
                        advisory_id=advisory.id,
                        package_id=package_id,
                        qualified_name=symbol,
                        kind=SymbolKind.FUNCTION,
                        origin=SymbolOrigin.CURATED,
                        verification_detail={"rationale": entry.rationale},
                    )
                    .on_conflict_do_nothing()
                    .returning(VulnerableSymbol.id)
                )
                inserted += result.scalar_one_or_none() is not None
    return inserted


def symbols_for(
    session: Session, advisory_ids: Iterable[uuid.UUID], package_id: uuid.UUID
) -> list[VulnerableSymbol]:
    """Symbols of every advisory record describing this vulnerability (GHSA, PYSEC, ...).

    Symbols an earlier verification rejected are excluded; AI proposals are only used once
    verified, while advisory/curated/reviewer symbols are verified against each installed
    version by the analysis itself.
    """
    rows = session.scalars(
        select(VulnerableSymbol).where(
            VulnerableSymbol.advisory_id.in_(list(advisory_ids)),
            VulnerableSymbol.package_id == package_id,
            VulnerableSymbol.verification != SymbolVerification.REJECTED,
        )
    ).all()
    usable = [
        row
        for row in rows
        if row.origin is not SymbolOrigin.AI or row.verification is SymbolVerification.VERIFIED
    ]
    unique: dict[str, VulnerableSymbol] = {}
    for row in sorted(usable, key=lambda r: (r.origin is SymbolOrigin.AI, r.qualified_name)):
        unique.setdefault(row.qualified_name, row)
    return list(unique.values())


def as_inputs(rows: list[VulnerableSymbol]) -> list[SymbolInput]:
    return [SymbolInput(row.qualified_name, row.origin) for row in rows]


def record_verification(
    rows: list[VulnerableSymbol], report: list[dict[str, Any]], package: str, version: str | None
) -> None:
    """Store what the analysis found for each symbol in the installed version's source."""
    by_name = {entry["requested"]: entry for entry in report}
    for row in rows:
        entry = by_name.get(row.qualified_name)
        if entry is None:
            continue
        checks = dict(row.verification_detail.get("checks", {}))
        checks[f"{package}=={version}"] = {
            "status": entry["status"],
            "canonical": entry.get("canonical"),
            "file": entry.get("file"),
            "line": entry.get("line"),
        }
        row.verification_detail = {**row.verification_detail, "checks": checks}
        if entry["status"] == "found":
            row.verification = SymbolVerification.VERIFIED
            row.kind = _KINDS.get(entry.get("kind", ""), row.kind)
