# Performance

No performance claim is made anywhere in this project unless a measurement in this file supports
it. Every result records the date, machine, inputs and command, and the raw output is committed
under [`reports/`](../reports).

## What is measured, and where

| Measurement | Source | Status |
|---|---|---|
| End-to-end scan duration, queue wait | `scans.created_at → started_at → finished_at` | Measured below |
| Per-stage time (inventory, SBOM, match, fetch, call graph, symbols, reachability, score, report) | `scans.progress[stage].duration_seconds`; histogram `sieve_scan_stage_duration_seconds` | Measured below |
| Scan outcomes and verdict counts | counters `sieve_scans_total`, `sieve_findings_verdicts_total` | Exposed |
| Job throughput and run time | counter `sieve_jobs_total{kind,outcome}`, histogram `sieve_job_duration_seconds` | Exposed |
| AI latency, tokens, cost | `ai_extractions` table; counter `sieve_ai_cost_USD_total` | Not yet measured (no live-model run) |
| API latency per route | benchmark script below; OpenTelemetry `http_server_*` histograms | Measured below |
| DB statement latency | OpenTelemetry SQLAlchemy spans (needs an OTLP endpoint) | Not yet measured |
| Frontend: LCP, CLS, accessibility | Chrome performance trace, Lighthouse | Measured below |
| Concurrency beyond one worker | — | Not yet measured |
| Larger repositories (benchmark corpus) | — | Not yet measured |

Metrics are served in Prometheus format at `GET /metrics` on the API and, when
`SIEVE_WORKER_METRICS_PORT` is set, on the worker ([ADR-0012](decisions/0012-observability.md)).

## Results — 2026-10-06

**Machine:** Windows 11 (10.0.26200) laptop, 12 logical CPUs. Python 3.13.16, PostgreSQL 16 in
Docker, API (single uvicorn process) and one worker running natively. Not production hardware;
these numbers show where time goes, not what a deployment will do.

**Input:** the demo repository (`demo/vulnerable-python-app`: 14 pinned PyPI dependencies, 100
findings against the committed advisory snapshot).

**Command:** `python benchmarks/bench.py` in `backend/`, with the flags recorded in each report.

### Demo scan, cold package cache (n = 1)

Raw: [`reports/benchmarks/2026-10-06-cold.md`](../reports/benchmarks/2026-10-06-cold.md)

| | Seconds |
|---|---|
| End to end | 29.3 |
| of which call graph (download, verify and index 14 wheels from PyPI) | 23.6 |
| of which reachability | 1.8 |
| everything else | < 4 |

One run only: the cold number is dominated by PyPI download time on the network in use that day.

### Demo scan, warm cache (sequential, n = 5)

Raw: [`reports/benchmarks/2026-10-06-warm.md`](../reports/benchmarks/2026-10-06-warm.md)

| | p50 (s) | max (s) |
|---|---|---|
| Queue wait (request → worker picks it up) | 0.7 | 1.0 |
| Run | 9.4 | 12.9 |
| End to end | 10.3 | 13.5 |
| Stage: call graph (load cached package indexes, resolve) | 5.2 | 8.3 |
| Stage: reachability (100 findings) | 1.9 | 2.0 |
| Stage: score | 0.8 | 1.2 |
| Stage: symbols | 0.7 | 0.9 |
| Stage: match | 0.7 | 0.9 |
| Stages: inventory, SBOM, fetch, report | < 0.2 each | |

Even warm, the call-graph stage is over half the scan. Cached per-package indexes are loaded and
resolved again on every scan; caching the resolved dependency graph per lockfile digest is the
obvious next optimisation, not yet done.

### Four demo scans requested at once, one worker (n = 4)

| | p50 (s) | max (s) |
|---|---|---|
| Run | 9.7 | 12.4 |
| Queue wait | 17.2 | 32.3 |
| End to end | 27.8 | 41.4 |

With one worker, scans run one at a time: run time is unchanged and the queue absorbs the burst.
Throughput scales by adding workers (each claims jobs with `SKIP LOCKED`); that has not been measured.

### API latency (single client, sequential, 50 requests per route, after one warm-up)

| Route | p50 (ms) | p95 (ms) |
|---|---|---|
| `GET /healthz` | 1.4 | 2.2 |
| `GET /api/v1/demo` | 10.5 | 21.7 |
| `GET /api/v1/orgs/{org}/overview` | 78.7 | 107.7 |
| `GET /api/v1/orgs/{org}/findings?limit=50` | 51.1 | 72.5 |
| `GET /api/v1/orgs/{org}/findings?verdict=reachable&limit=50` | 28.2 | 56.1 |
| `GET /api/v1/findings/{id}` | 43.3 | 86.6 |
| `GET /api/v1/orgs/{org}/repositories` | 45.1 | 64.8 |
| `GET /api/v1/orgs/{org}/activity` | 36.5 | 63.2 |

No load test has been run; these are single-client latencies.

### Frontend (production build, local server, no CPU or network throttling)

| Page | LCP | CLS | Lighthouse accessibility / best practices / SEO |
|---|---|---|---|
| Landing `/` (desktop) | — | — | 100 / 100 / 100 |
| Finding evidence page (desktop) | 449 ms (TTFB 63 ms) | 0.00 | 100 / 100 / 100 |
| Finding evidence page (mobile emulation) | — | — | 100 / 100 / 100 |

Reports: [`reports/lighthouse/`](../reports/lighthouse). Total client JavaScript across all routes
(`.next/static/chunks`): 664 KB uncompressed. The first Lighthouse run found two real accessibility
failures (code line numbers at 3.1:1 contrast; no `<main>` landmark on the landing page); both were
fixed before the numbers above were taken.

## Not yet measured

- Scans of real-world repositories larger than the demo (a pinned benchmark corpus).
- Multiple workers, and API behaviour under concurrent load.
- Live-model AI extraction latency and cost (no API key was available; see
  [ai-evaluation.md](ai-evaluation.md)).
- Anything on AWS.
