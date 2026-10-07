"""AI evaluation harness (docs/ai-evaluation.md).

    python -m sieve.ai.evaluation --provider heuristic --out ../reports/ai-eval

Runs every golden case through a provider, the schema guardrail and the source verifier, and
scores both the raw proposals and the accepted set. Expected labels are compared after
canonicalisation against the real package source, so `yaml.FullLoader` and
`yaml.loader.FullLoader` count as the same symbol.
"""

import argparse
import json
import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sieve.ai.diffs import touched
from sieve.ai.guardrails import (
    OUTPUT_SCHEMA,
    PROMPT_VERSION,
    SchemaInvalid,
    build_user_message,
    parse_output,
    system_prompt,
)
from sieve.ai.providers import AnthropicProvider, HeuristicProvider, Provider, estimate_cost
from sieve.ai.verification import PackageSource, canonical, load_package, verify
from sieve.analysis.engine import SourceProvider
from sieve.analysis.sandbox import Indexer, InProcessIndexer
from sieve.core.http import build_client
from sieve.packages.pypi import PypiSourceCache

GOLDEN = Path(__file__).resolve().parents[3] / "tests" / "ai" / "golden" / "cases"


@dataclass
class CaseResult:
    case_id: str
    expected: set[str]
    acceptable: set[str]
    proposed: list[str] = field(default_factory=list)
    accepted: list[str] = field(default_factory=list)
    nonexistent: list[str] = field(default_factory=list)
    unacceptable_hits: list[str] = field(default_factory=list)
    schema_invalid: bool = False
    latency_ms: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


def load_cases(directory: Path = GOLDEN) -> list[dict[str, Any]]:
    return [json.loads(p.read_text("utf-8")) for p in sorted(directory.glob("*.json"))]


def _canon(source: PackageSource, names: list[str]) -> set[str]:
    return {canonical(source, name) or f"?{name}" for name in names}


def run_case(case: dict[str, Any], provider: Provider, source: PackageSource) -> CaseResult:
    advisory = case["advisory"]
    diff = case.get("fix_diff")
    user = build_user_message(
        advisory_id=advisory["id"],
        summary=advisory.get("summary"),
        details=advisory.get("details"),
        package=case["package"]["name"],
        version=case["package"]["vulnerable_version"],
        references=advisory.get("references", []),
        diff=diff,
    )
    result = CaseResult(
        case["id"], _canon(source, case["expected"]), _canon(source, case.get("acceptable", []))
    )
    completion = provider.complete(system_prompt(), user, OUTPUT_SCHEMA)
    result.latency_ms = completion.latency_ms
    result.input_tokens, result.output_tokens = completion.input_tokens, completion.output_tokens
    cost = estimate_cost(completion.model, completion.input_tokens, completion.output_tokens)
    result.cost_usd = float(cost) if cost is not None else None
    try:
        output = parse_output(completion.text)
    except SchemaInvalid:
        result.schema_invalid = True
        return result
    verified = verify(source, output.symbols, touched(diff) if diff else None)
    result.proposed = [canonical(source, c.name) or c.name for c in output.symbols]
    result.nonexistent = [v.name for v in verified if v.reason == "not_found_in_source"]
    result.accepted = sorted({v.canonical or v.name for v in verified if v.accepted})
    unacceptable = _canon(source, case.get("unacceptable", []))
    result.unacceptable_hits = sorted(set(result.accepted) & unacceptable)
    return result


def _precision_recall(
    results: list[CaseResult], attribute: str
) -> tuple[float | None, float | None]:
    proposed = correct = expected = found = 0
    for r in results:
        names = set(getattr(r, attribute))
        good = r.expected | r.acceptable
        proposed += len(names)
        correct += len(names & good)
        expected += len(r.expected)
        found += len(names & r.expected)
    return (correct / proposed if proposed else None, found / expected if expected else None)


def summarise(results: list[CaseResult], provider: Provider) -> dict[str, Any]:
    raw_p, raw_r = _precision_recall(results, "proposed")
    acc_p, acc_r = _precision_recall(results, "accepted")
    proposed_total = sum(len(r.proposed) for r in results)
    latencies = [r.latency_ms for r in results]
    costs = [r.cost_usd for r in results if r.cost_usd is not None]
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "provider": provider.name,
        "model": provider.model,
        "prompt_version": PROMPT_VERSION,
        "cases": len(results),
        "indicative_only": len(results) < 30,
        "raw": {"precision": raw_p, "recall": raw_r},
        "accepted": {"precision": acc_p, "recall": acc_r},
        "hallucination_rate": (sum(len(r.nonexistent) for r in results) / proposed_total)
        if proposed_total
        else None,
        "hallucinations_accepted": sum(
            1 for r in results for name in r.accepted if name.startswith("?")
        ),
        "unacceptable_hit_rate": sum(1 for r in results if r.unacceptable_hits) / len(results)
        if results
        else None,
        "structured_output_failure_rate": sum(r.schema_invalid for r in results) / len(results)
        if results
        else None,
        "latency_ms": {
            "p50": statistics.median(latencies) if latencies else None,
            "max": max(latencies, default=None),
        },
        "tokens": {
            "input": sum(r.input_tokens or 0 for r in results),
            "output": sum(r.output_tokens or 0 for r in results),
        },
        "estimated_cost_usd": round(sum(costs), 6) if costs else None,
        "per_case": [
            r.__dict__ | {"expected": sorted(r.expected), "acceptable": sorted(r.acceptable)}
            for r in results
        ],
    }


def evaluate(
    provider: Provider, sources: SourceProvider, indexer: Indexer, cases: list[dict[str, Any]]
) -> dict[str, Any]:
    packages: dict[tuple[str, str], PackageSource] = {}
    results = []
    for case in cases:
        key = (case["package"]["name"], case["package"]["vulnerable_version"])
        if key not in packages:
            packages[key] = load_package(sources, indexer, *key)
        results.append(run_case(case, provider, packages[key]))
    return summarise(results, provider)


def render_markdown(report: dict[str, Any]) -> str:
    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.1%}"

    raw, accepted = report["raw"], report["accepted"]
    cost = report["estimated_cost_usd"]

    lines = [
        f"# AI evaluation — {report['provider']} / {report['model']} ({report['prompt_version']})",
        "",
        f"Generated {report['generated_at']} on {report['cases']} golden cases"
        + (" — indicative only (fewer than 30 cases)." if report["indicative_only"] else "."),
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Raw precision / recall | {pct(raw['precision'])} / {pct(raw['recall'])} |",
        f"| Accepted precision / recall | {pct(accepted['precision'])} / "
        f"{pct(accepted['recall'])} |",
        f"| Hallucination rate (absent from source) | {pct(report['hallucination_rate'])} |",
        f"| Hallucinations accepted | {report['hallucinations_accepted']} |",
        f"| Cases accepting an unacceptable symbol | {pct(report['unacceptable_hit_rate'])} |",
        f"| Structured-output failures | {pct(report['structured_output_failure_rate'])} |",
        f"| Latency p50 | {report['latency_ms']['p50']} ms |",
        f"| Tokens in / out | {report['tokens']['input']} / {report['tokens']['output']} |",
        f"| Estimated cost (USD) | {cost if cost is not None else 'n/a'} |",
        "",
        "| Case | Expected | Accepted |",
        "|---|---|---|",
    ]
    for case in report["per_case"]:
        lines.append(
            f"| {case['case_id']} | {', '.join(case['expected'])} | "
            f"{', '.join(case['accepted']) or '—'} |"
        )
    return "\n".join(lines) + "\n"


TOLERANCE = 0.02


def regressions(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Reasons this report is worse than the committed baseline (empty when it is not)."""
    problems = []
    for metric in ("precision", "recall"):
        now, then = report["accepted"][metric], baseline["accepted"][metric]
        if now is not None and then is not None and now < then - TOLERANCE:
            problems.append(f"accepted {metric} fell from {then:.3f} to {now:.3f}")
    if report["hallucinations_accepted"]:
        problems.append(f"{report['hallucinations_accepted']} non-existent symbols were accepted")
    if (report["unacceptable_hit_rate"] or 0) > (baseline["unacceptable_hit_rate"] or 0):
        problems.append("more cases accepted a known-wrong symbol than the baseline")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["heuristic", "anthropic"], default="heuristic")
    parser.add_argument("--model", default="claude-opus-5-5")
    parser.add_argument("--api-key-env", default="ANTHROPIC_API_KEY")
    parser.add_argument("--cache", type=Path, default=Path("var/cache/packages"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--baseline", type=Path, help="fail if the run regresses against this report"
    )
    args = parser.parse_args()
    import os

    provider: Provider = (
        HeuristicProvider()
        if args.provider == "heuristic"
        else AnthropicProvider(os.environ[args.api_key_env], args.model)
    )
    with build_client(timeout=60) as client:
        report = evaluate(
            provider, PypiSourceCache(args.cache, client), InProcessIndexer(), load_cases()
        )
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2, default=str), "utf-8")
    (args.out / "report.md").write_text(render_markdown(report), "utf-8")
    print(render_markdown(report))  # noqa: T201
    if args.baseline:
        problems = regressions(report, json.loads(args.baseline.read_text("utf-8")))
        for problem in problems:
            print(f"REGRESSION: {problem}")  # noqa: T201
        if problems:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
