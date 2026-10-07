"""Reproducible benchmark of the demo scan pipeline and the read API.

Needs a migrated database with the demo seeded, a running worker, and a running API. It requests
real demo scans through the same path the "Run the live demo" button uses, waits for the worker,
and reads the per-stage timings the pipeline records in ``scans.progress``.

    python benchmarks/bench.py --api http://127.0.0.1:8010 --sequential 5 --concurrent 4 \
        --label warm --out ../reports/benchmarks

Every result is written with the date, machine, inputs and command, so it can be reproduced.
"""

import argparse
import json
import os
import platform
import statistics
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select

from sieve.core.config import get_settings
from sieve.db.enums import ScanStatus
from sieve.db.models import Scan
from sieve.db.session import create_db_engine, create_session_factory, transaction
from sieve.demo.seed import request_demo_scan

API_ROUTES = [
    "/healthz",
    "/api/v1/demo",
    "/api/v1/orgs/{org}/overview",
    "/api/v1/orgs/{org}/findings?limit=50",
    "/api/v1/orgs/{org}/findings?verdict=reachable&limit=50",
    "/api/v1/findings/{finding}",
    "/api/v1/orgs/{org}/repositories",
    "/api/v1/orgs/{org}/activity",
]


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return ordered[index]


def summary(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50": round(statistics.median(values), 3),
        "p95": round(percentile(values, 0.95), 3),
        "max": round(max(values), 3),
    }


def request_scans(factory: Any, count: int, label: str) -> list[uuid.UUID]:
    settings = get_settings()
    ids = []
    with transaction(factory) as session:
        for _ in range(count):
            scan, _created = request_demo_scan(
                session, settings, bucket=f"bench-{label}-{uuid.uuid4()}"
            )
            ids.append(scan.id)
    return ids


def wait(factory: Any, ids: list[uuid.UUID], timeout: float = 1800) -> list[Scan]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with factory() as session:
            scans = list(session.scalars(select(Scan).where(Scan.id.in_(ids))))
            done = [s for s in scans if s.status in (ScanStatus.SUCCEEDED, ScanStatus.FAILED)]
            if len(done) == len(ids):
                for scan in scans:
                    session.expunge(scan)
                return scans
        time.sleep(0.5)
    raise TimeoutError(f"scans {ids} did not finish within {timeout}s")


def scan_metrics(scans: list[Scan]) -> dict[str, Any]:
    failed = [str(s.id) for s in scans if s.status is not ScanStatus.SUCCEEDED]
    ok = [s for s in scans if s.status is ScanStatus.SUCCEEDED]
    stages: dict[str, list[float]] = {}
    for scan in ok:
        for name, entry in scan.progress.items():
            if "duration_seconds" in entry:
                stages.setdefault(name, []).append(entry["duration_seconds"])
    assert all(s.started_at and s.finished_at for s in ok)  # noqa: S101
    return {
        "scans": len(scans),
        "failed": failed,
        "findings": sorted({s.stats.get("findings") for s in ok}),
        "queue_wait_seconds": summary(
            [(s.started_at - s.created_at).total_seconds() for s in ok]  # type: ignore[operator]
        ),
        "run_seconds": summary(
            [(s.finished_at - s.started_at).total_seconds() for s in ok]  # type: ignore[operator]
        ),
        "end_to_end_seconds": summary(
            [(s.finished_at - s.created_at).total_seconds() for s in ok]  # type: ignore[operator]
        ),
        "stages_seconds": {name: summary(values) for name, values in stages.items()},
    }


def api_metrics(base: str, requests: int) -> dict[str, Any]:
    with httpx.Client(base_url=base, timeout=30) as client:
        demo = client.get("/api/v1/demo").raise_for_status().json()
        org = demo["organization_login"]
        findings = client.get(f"/api/v1/orgs/{org}/findings?limit=1").raise_for_status().json()
        finding = findings["items"][0]["id"]
        results: dict[str, Any] = {}
        for template in API_ROUTES:
            path = template.format(org=org, finding=finding)
            client.get(path).raise_for_status()  # warm-up, not counted
            timings = []
            for _ in range(requests):
                started = time.perf_counter()
                client.get(path).raise_for_status()
                timings.append((time.perf_counter() - started) * 1000)
            results[template] = summary(timings)
        return results


def machine() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Benchmark: {report['label']}",
        "",
        f"- Date: {report['date']}",
        f"- Machine: {report['machine']['platform']}, "
        f"{report['machine']['cpu_count']} logical CPUs",
        f"- Command: `{report['command']}`",
        "",
    ]
    for section in ("sequential", "concurrent"):
        data = report.get(section)
        if not data:
            continue
        lines += [
            f"## {section.title()} demo scans ({data['scans']}, failed: {len(data['failed'])})",
            "",
            "| Measure | n | p50 (s) | p95 (s) | max (s) |",
            "|---|---|---|---|---|",
        ]
        rows = {
            "queue wait": data["queue_wait_seconds"],
            "run": data["run_seconds"],
            "end to end": data["end_to_end_seconds"],
        }
        rows |= {f"stage: {k}": v for k, v in data["stages_seconds"].items()}
        for name, s in rows.items():
            lines.append(f"| {name} | {s['n']} | {s['p50']} | {s['p95']} | {s['max']} |")
        lines.append("")
    if report.get("api"):
        lines += [
            "## API latency (sequential, single client, ms)",
            "",
            "| Route | n | p50 | p95 | max |",
            "|---|---|---|---|---|",
        ]
        for route, s in report["api"].items():
            lines.append(f"| `{route}` | {s['n']} | {s['p50']} | {s['p95']} | {s['max']} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--sequential", type=int, default=5, help="scans run one after another")
    parser.add_argument("--concurrent", type=int, default=0, help="scans requested at once")
    parser.add_argument("--api-requests", type=int, default=50, help="0 skips the API benchmark")
    parser.add_argument("--label", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    factory = create_session_factory(create_db_engine(get_settings()))
    report: dict[str, Any] = {
        "label": args.label,
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
        "machine": machine(),
        "command": " ".join(["python", *sys.argv]),
    }
    if args.sequential:
        scans = [
            wait(factory, request_scans(factory, 1, args.label))[0] for _ in range(args.sequential)
        ]
        report["sequential"] = scan_metrics(scans)
    if args.concurrent:
        report["concurrent"] = scan_metrics(
            wait(factory, request_scans(factory, args.concurrent, args.label))
        )
    if args.api_requests:
        report["api"] = api_metrics(args.api, args.api_requests)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"{args.label}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (args.out / f"{args.label}.md").write_text(markdown(report), encoding="utf-8")
    sys.stdout.write(markdown(report))


if __name__ == "__main__":
    main()
