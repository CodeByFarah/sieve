"""Dependencies × advisories → candidate findings.

OSV often publishes the same vulnerability several times (a GHSA record and a PYSEC record that
alias each other). Matches are grouped by shared identifiers and one record — the preferred one —
represents the group, so one vulnerability produces one finding.
"""

import uuid
from collections import defaultdict
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from sieve.advisories.osv import preference
from sieve.advisories.versions import Affectedness, constraint_may_be_affected, version_affected
from sieve.db.models import Advisory, AdvisoryPackage, Dependency


@dataclass(frozen=True)
class Match:
    advisory: Advisory  # the preferred record of the group
    group_advisory_ids: tuple[uuid.UUID, ...]  # every record describing the same vulnerability
    dependency: Dependency
    version_uncertain: bool  # unpinned, or the version could not be compared


def _group(matches: list[tuple[Advisory, bool]]) -> list[tuple[Advisory, list[Advisory], bool]]:
    """Union records that share any identifier."""
    groups: list[tuple[set[str], list[Advisory], bool]] = []
    for advisory, uncertain in matches:
        ids = {advisory.source_id, *advisory.aliases}
        merged_ids, merged_members, merged_uncertain = set(ids), [advisory], uncertain
        remaining = []
        for group_ids, members, group_uncertain in groups:
            if group_ids & ids:
                merged_ids |= group_ids
                merged_members += members
                merged_uncertain = merged_uncertain and group_uncertain
            else:
                remaining.append((group_ids, members, group_uncertain))
        groups = [*remaining, (merged_ids, merged_members, merged_uncertain)]
    result = []
    for _, members, uncertain in groups:
        members.sort(key=lambda a: (preference(a.source_id), a.source_id))
        result.append((members[0], members, uncertain))
    return result


def match_scan(session: Session, scan_id: uuid.UUID) -> list[Match]:
    dependencies = session.scalars(select(Dependency).where(Dependency.scan_id == scan_id)).all()
    package_ids = {d.package_id for d in dependencies}
    rows = session.execute(
        select(AdvisoryPackage, Advisory)
        .join(Advisory, Advisory.id == AdvisoryPackage.advisory_id)
        .where(AdvisoryPackage.package_id.in_(package_ids), Advisory.withdrawn_at.is_(None))
    ).all()
    by_package: dict[uuid.UUID, list[tuple[AdvisoryPackage, Advisory]]] = defaultdict(list)
    for affected, advisory in rows:
        by_package[affected.package_id].append((affected, advisory))

    matches: list[Match] = []
    for dependency in dependencies:
        hits: list[tuple[Advisory, bool]] = []
        for affected, advisory in by_package.get(dependency.package_id, []):
            if dependency.version is None:
                if constraint_may_be_affected(
                    dependency.constraint_spec, affected.ranges, affected.versions
                ):
                    hits.append((advisory, True))
                continue
            state = version_affected(dependency.version, affected.ranges, affected.versions)
            if state is not Affectedness.NOT_AFFECTED:
                hits.append((advisory, state is Affectedness.UNKNOWN))
        for preferred, members, uncertain in _group(hits):
            matches.append(Match(preferred, tuple(m.id for m in members), dependency, uncertain))
    return matches
