"""Pull-request scans (spec §31): report only what the pull request *introduces*.

The PR head is analysed exactly like any commit, but in memory. The result is compared with the
repository's current findings (its default branch): a vulnerability is reported when it is new in
the PR, or was present but becomes reachable. Only those are evaluated against the policy.
"""

from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from sieve.analysis.reachability import Outcome, decide
from sieve.audit.log import record_event
from sieve.core.workspace import Workspace
from sieve.db.enums import ActorType, Presence, ScanStatus, Verdict
from sieve.db.models import Advisory, Finding, Package, PullRequestCheck, Scan
from sieve.db.session import transaction
from sieve.findings.matching import Match, match_scan
from sieve.findings.service import effective_verdict, exploitation_signals
from sieve.policy.engine import FindingFacts, RuleMatch, evaluate
from sieve.policy.service import active_policy
from sieve.sbom.models import Inventory
from sieve.symbols.registry import as_inputs, seed_curated_symbols, symbols_for
from sieve.worker import queue

if TYPE_CHECKING:
    from sieve.scans.pipeline import ScanPipeline


def _identifiers(advisory: Advisory) -> set[str]:
    return {advisory.source_id, *advisory.aliases}


def _path_summary(outcome: Outcome) -> list[str]:
    if not outcome.paths:
        return []
    steps = outcome.paths[0]["steps"]
    rendered = []
    for step in steps:
        where = (
            f" ({step['file']}:{step['call']['line']})"
            if step["package"] is None and step["call"]
            else ""
        )
        rendered.append(f"{step['symbol']}{where}")
    return rendered


class PullRequestFlow:
    def __init__(
        self, pipeline: "ScanPipeline", scan: Scan, workspace: Workspace, inventory: Inventory
    ) -> None:
        self.pipeline = pipeline
        self.scan = scan
        self.workspace = workspace
        self.inventory = inventory
        self.factory = pipeline.deps.session_factory

    def run(self) -> None:
        scan_id = self.scan.id
        with self.pipeline.stage(scan_id, "match") as counts, self.factory() as session:
            matches = match_scan(session, scan_id)
            names = dict(session.execute(select(Package.id, Package.name)).all())
            counts["findings"] = len(matches)
        with (
            self.pipeline.stage(scan_id, "symbols") as counts,
            transaction(self.factory) as session,
        ):
            seed_curated_symbols(session)
            symbol_inputs = [
                as_inputs(symbols_for(session, m.group_advisory_ids, m.dependency.package_id))
                for m in matches
            ]
            counts["with_symbols"] = sum(1 for inputs in symbol_inputs if inputs)
        result = self.pipeline.callgraph(scan_id, self.workspace, self.inventory)
        with self.pipeline.stage(scan_id, "reachability") as counts:
            outcomes = [
                decide(result.context, names[m.dependency.package_id], inputs)
                for m, inputs in zip(matches, symbol_inputs, strict=True)
            ]
            counts.update({str(v): sum(1 for o in outcomes if o.verdict is v) for v in Verdict})
        with self.pipeline.stage(scan_id, "score") as counts, transaction(self.factory) as session:
            summary = self._evaluate(session, matches, outcomes, names)
            counts.update(introduced=summary["introduced_count"], conclusion=summary["conclusion"])
        with self.pipeline.stage(scan_id, "report") as counts, transaction(self.factory) as session:
            self._report(session, summary)
            counts["conclusion"] = summary["conclusion"]

    def _base_index(self, session: Any) -> dict[str, list[tuple[set[str], Verdict | None]]]:
        rows = session.execute(
            select(Finding, Advisory, Package)
            .join(Advisory, Advisory.id == Finding.advisory_id)
            .join(Package, Package.id == Finding.package_id)
            .where(
                Finding.repository_id == self.scan.repository_id,
                Finding.presence == Presence.PRESENT,
            )
        ).all()
        index: dict[str, list[tuple[set[str], Verdict | None]]] = defaultdict(list)
        for finding, advisory, package in rows:
            index[package.name].append((_identifiers(advisory), effective_verdict(finding)))
        return index

    def _evaluate(
        self, session: Any, matches: list[Match], outcomes: list[Outcome], names: dict[Any, str]
    ) -> dict[str, Any]:
        base = self._base_index(session)
        facts: list[FindingFacts] = []
        details: dict[str, dict[str, Any]] = {}
        for match, outcome in zip(matches, outcomes, strict=True):
            package = names[match.dependency.package_id]
            ids = _identifiers(match.advisory)
            previous = next(
                (verdict for known, verdict in base.get(package, []) if known & ids), "absent"
            )
            if previous == "absent":
                change = "new"
            elif previous is not Verdict.REACHABLE and outcome.verdict is Verdict.REACHABLE:
                change = "newly_reachable"
            else:
                continue
            kev, epss = exploitation_signals(session, match.advisory)
            key = f"{match.advisory.source_id}:{package}"
            facts.append(
                FindingFacts(
                    key,
                    match.advisory.source_id,
                    package,
                    match.dependency.version,
                    match.advisory.severity,
                    outcome.verdict,
                    kev,
                    epss,
                )
            )
            details[key] = {
                "advisory": match.advisory.source_id,
                "package": package,
                "version": match.dependency.version,
                "severity": str(match.advisory.severity),
                "verdict": str(outcome.verdict),
                "kev": kev,
                "change": change,
                "path": _path_summary(outcome),
            }
        version, policy = active_policy(session, self.scan.organization_id)
        evaluation = evaluate(policy, facts)

        def render(items: list[RuleMatch]) -> list[dict[str, Any]]:
            return [
                {**details[item.facts.key], "rule": item.rule.description or item.rule.action}
                for item in items
            ]

        return {
            "conclusion": evaluation.conclusion,
            "policy_version": version.version,
            "policy_version_id": str(version.id),
            "analysed": len(matches),
            "introduced_count": len(facts),
            "blocking": render(evaluation.blocking),
            "warnings": render(evaluation.warnings),
        }

    def _report(self, session: Any, summary: dict[str, Any]) -> None:
        scan = session.get(Scan, self.scan.id, with_for_update=True)
        scan.status = ScanStatus.SUCCEEDED
        scan.finished_at = datetime.now(UTC)
        scan.stats = {
            "pull_request": {k: summary[k] for k in ("conclusion", "introduced_count", "analysed")}
        }
        check = session.scalar(select(PullRequestCheck).where(PullRequestCheck.scan_id == scan.id))
        if check is not None:
            check.summary = summary
            check.conclusion = summary["conclusion"]
            check.policy_version_id = summary["policy_version_id"]
            queue.enqueue(
                session,
                kind="checks.publish",
                idempotency_key=f"checks.publish:{check.id}:{scan.id}",
                payload={"check_id": str(check.id)},
                organization_id=scan.organization_id,
                priority=20,
            )
        record_event(
            session,
            action="scan.completed",
            actor_type=ActorType.SYSTEM,
            organization_id=scan.organization_id,
            target_type="scan",
            target_id=str(scan.id),
            data={
                "pull_request": True,
                "conclusion": summary["conclusion"],
                "introduced": summary["introduced_count"],
            },
        )
