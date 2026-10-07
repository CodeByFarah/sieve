# Sieve architecture

> Status: describes the implemented system (2026-10-06). Anything not built is marked
> *(not implemented)*. Measured behaviour is in [performance.md](performance.md).

## 1. What the system does, in one paragraph

Sieve reads a Python repository's lockfiles **without executing anything**, produces a CycloneDX
SBOM, matches pinned dependency versions against OSV advisories (enriched with CISA KEV and EPSS),
works out *which functions* each advisory concerns (from advisory data, or from an LLM proposal that
is then verified against the package's real source), builds a static call graph over the
application and its dependencies, and searches for a path from application code to a vulnerable
function. Each finding gets a verdict (`reachable` / `not_reached` / `needs_review`), a
rule-derived confidence level with reasons, the evidence path, and a transparent risk score. A human
reviews the verdict; reviewed decisions become OpenVEX / CycloneDX VEX statements and drive GitHub
check runs according to versioned policies.

## 2. Shape of the system

```
                 ┌─────────────────────────────┐
  Browser ──────▶│ web  (Next.js, TypeScript)  │
                 └──────────────┬──────────────┘
                                │ HTTPS (JSON, SSE)
  GitHub ──webhooks────────────▶│
                 ┌──────────────▼──────────────┐
                 │ api  (FastAPI)              │── Redis: rate limits (optional)
                 │  validates, authorises,     │
                 │  writes state + jobs in ONE │
                 │  transaction                │
                 └──────────────┬──────────────┘
                                │
                 ┌──────────────▼──────────────┐        ┌─────────────────────┐
                 │ PostgreSQL                  │        │ S3                  │
                 │  domain state, jobs queue,  │        │  SBOMs, call-graph  │
                 │  append-only audit log      │        │  snapshots, VEX,    │
                 └──────────────┬──────────────┘        │  evidence bundles   │
                                │ SKIP LOCKED leases    └──────────▲──────────┘
                 ┌──────────────▼──────────────┐                   │
                 │ worker (same image as api)  │───────────────────┘
                 │  scan · ingest · extract ·  │── GitHub API (installation tokens, check runs)
                 │  analyse · fan-out · notify │── OSV / KEV / EPSS / PyPI (allow-listed egress)
                 └─────────────────────────────┘── LLM provider (structured output only)
```

Three deployable processes, two of them from one Python codebase:

| Process | Responsibility | Scales on |
|---|---|---|
| `web` | UI, SSR for landing/demo pages | HTTP traffic |
| `api` | HTTP API, webhooks, auth, SSE | HTTP traffic |
| `worker` | All slow or external work | `jobs` queue depth |

Why a modular monolith and not services: [ADR-0003](decisions/0003-modular-monolith.md).

## 3. Backend modules

One Python package, `sieve`, in `backend/src/sieve/`. Dependencies point downward only; `core` and
`db` know nothing about the domain modules above them. This is a convention checked in review;
it is not enforced by a tool *(not implemented: import-linter)*.

```
api/            HTTP layer: routers, request/response schemas, dependencies (auth, db session)
worker/         job runner, handler registry, scheduler
───────────────────────────────────────────────────────────────────────────────────────────
github/         App JWT, installation tokens, webhooks, repo contents, check runs
auth/           GitHub user login, sessions, memberships, authorisation helpers
scans/          scan orchestration: stages, progress events, idempotency
sbom/           lockfile parsers, dependency inventory, CycloneDX writer
advisories/     source adapters (OSV, KEV, EPSS), normalised model, ingestion, version matching
packages/       PyPI artifact fetch + safe extraction (no install, no execution)
analysis/       ast indexing, import resolution, call graph, reachability search, evidence
ai/             provider abstraction, prompts, symbol extraction, guardrails, evaluation harness
symbols/        vulnerable-symbol registry + deterministic verification
risk/           transparent scoring
findings/       finding lifecycle, state transitions
reviews/        human decisions
vex/            OpenVEX + CycloneDX VEX generation and schema validation
policy/         versioned policies and evaluation
audit/          append-only, hash-chained audit events
───────────────────────────────────────────────────────────────────────────────────────────
db/             SQLAlchemy models, session management, migrations (Alembic)
core/           settings, logging, errors, correlation ids, telemetry
```

## 4. The scan pipeline

A scan is one job (`scan.run`) that moves through explicit, persisted stages. Each stage writes its
outcome before the next starts, so a crashed worker resumes at the first incomplete stage and the UI
progress view is a direct read of real state (§78: "do not fake progress").

| # | Stage (`scans.stage`) | Work | Output |
|---|---|---|---|
| 1 | `fetch` | Download repo tarball at the commit SHA via installation token; safe extraction. Demo: copy bundled sample app. | workspace dir |
| 2 | `inventory` | Detect manifests, parse supported formats, record unsupported ones. | `scan_manifests`, `dependencies` |
| 3 | `sbom` | Deterministic CycloneDX 1.6 JSON. | S3 object, hash on `scans` |
| 4 | `match` | Match (package, version) → advisories; create/update findings. | `findings` |
| 5 | `symbols` | Ensure each matched advisory has verified symbols; AI extraction where missing (cached by input hash). | `vulnerable_symbols` |
| 6 | `callgraph` | Index application modules; index needed dependency modules from PyPI artifacts. | call-graph snapshot (S3) |
| 7 | `reachability` | Per finding: search from roots to verified symbols. | `analysis_results`, `reachability_paths` |
| 8 | `score` | Risk score + breakdown. | `findings.risk_*` |
| 9 | `report` | Policy evaluation, check run (PR scans), audit events. | `pull_request_checks` |

Progress is written to the `scans` row, the single source of truth. The SSE endpoint
(`GET /api/v1/scans/{id}/events`) reads that row on a short interval, streams changes, and ends
when the scan finishes. Pull-request scans branch after `sbom`: they evaluate findings in memory
against the policy and record only the check summary, never changing the repository's findings.

A scan is marked `succeeded` only after every stage has closed, so a reader never sees a finished
scan with a stage still running.

## 5. Reachability engine

### 5.1 Model

- **Nodes:** functions, methods, classes, and module bodies, identified by fully-qualified name
  (`app.parser.parse_config`, `yaml.load`).
- **Edges:** each carries `(file, line, col)` and a kind. Strong kinds can support `reachable`:
  - `call` — callee resolved through imports, aliases, star imports and module attributes
    (`from yaml import load as l; l()`, `yaml.load()`),
  - `method` — `self.x()`, `cls.x()`, `super().x()` through the class MRO, or a constructor-typed
    local or bound-method alias,
  - `import` — importing a module runs its body.
  Weak kinds over-approximate code that cannot be resolved statically. They never support
  `reachable`, but they block `not_reached`:
  - `reference` — a function is referenced (passed, stored) but not called here,
  - `name_match` — a call on an unknown receiver (`obj.send()`) may reach any method with that name,
  - `dynamic_import` — a dotted name in a string literal may be imported dynamically.
- **Roots:** every module body and function defined in application code. Framework detectors label
  roots as `http_route`, `cli_command`, `task` or `module_init` so evidence paths start somewhere
  meaningful.

### 5.2 Verdict rules

The rules are deliberately asymmetric — a wrong `not_reached` is worse than an unnecessary
`needs_review`, because it can become a false "not affected" VEX statement.

| Verdict | Requires |
|---|---|
| `reachable` | A path from a root to a **verified** vulnerable symbol, using only strong edges (`call`, `method`, `import`). |
| `not_reached` | Pinned version **and** ≥1 verified symbol **and** the traversal completed within budget **and** no path of any kind, weak edges included, reaches the symbol. |
| `needs_review` | Anything else, with machine-readable reasons such as `no_verified_symbols`, `version_unpinned`, `dynamic_dispatch`, `dynamic_import`, `reference_only`, `incomplete_import_graph`, `budget_exceeded`, `parse_failure`, `package_source_unavailable`. When only weak paths exist, the most plausible one is shown as evidence. |

### 5.3 Transitive dependencies

The traversal continues into dependency modules: `app → requests.get → … → urllib3.<symbol>`. Only
wheels (preferring py3 wheels for the newest CPython, falling back to the sdist) are downloaded from
PyPI, digest-verified and safely extracted; only `.py` files are read. Each package is indexed once
per `(package, version)` and the index is cached on the worker's disk keyed by artifact hash, so the
next scan that uses `requests==2.19.1` reuses it.

### 5.4 Resource limits

Package indexing runs in a process pool with a wall-clock timeout and, on Linux, CPU-time and
memory limits (`resource.setrlimit`), plus file size and file count caps. Exceeding a budget yields
`needs_review` with `budget_exceeded` or `parse_failure`, never a crash and never a `not_reached`.

## 6. AI symbol extraction

```
advisory text + references + fix-commit diff (if any, size-capped)
        │  (delimited as untrusted data; no secrets; no tools)
        ▼
LLM ──structured output──▶ JSON schema validation ──▶ source verification ──▶ diff cross-check
                                (reject on failure)       (symbol exists in       (symbol touched
                                                           vulnerable version)     by the fix?)
                                                                │
                                         accepted ◀─────────────┴────────▶ rejected (recorded)
```

The model's only output is a list of *candidate* symbols with evidence quotes. It never decides a
verdict. Verified candidates join the same `vulnerable_symbols` registry as advisory-provided symbols,
with `source = ai` so the UI can label them. Extraction is a job (`symbols.extract`) keyed per
advisory and package, cached by input digest and prompt version, and gated by a daily spend cap. It
is enabled only when a provider and key are configured, and never for the public demo
organization. Details: [ai-evaluation.md](ai-evaluation.md),
[ADR-0008](decisions/0008-ai-proposes-deterministic-decides.md).

## 7. Jobs and events

All asynchronous work is a row in `jobs` ([ADR-0004](decisions/0004-postgres-job-queue.md)).

- **Enqueue** inside the caller's transaction, with a `UNIQUE` `idempotency_key`; a duplicate
  enqueue is a no-op (`ON CONFLICT DO NOTHING`), which is what makes duplicate webhooks and duplicate
  advisory events harmless.
- **Claim:** `UPDATE jobs SET status='running', lease_expires_at=now()+lease … WHERE id = (SELECT id
  … WHERE status='pending' AND run_after<=now() ORDER BY priority, run_after FOR UPDATE SKIP LOCKED
  LIMIT 1) RETURNING *`.
- **Leases** can be extended (`heartbeat`); a reaper returns expired leases to `pending`, or to
  `dead` once attempts are exhausted.
- **Failure** is classified ([§9](#9-errors)). Transient → `pending` with `run_after = now() +
  base·2^attempt + jitter`. Permanent, or `attempts = max_attempts` → `dead` (the dead-letter queue),
  with `last_error` and correlation id. An operator can re-queue a dead job (`queue.retry_dead`);
  there is no HTTP endpoint for this *(not implemented)*.

Job kinds: `scan.run`, `advisories.ingest_osv`, `advisories.ingest_kev`, `advisories.ingest_epss`,
`advisories.fanout`, `demo.apply_reviews`, and, when configured, `github.sync_installation`,
`checks.publish` and `symbols.extract`. A scheduler in the worker enqueues the ingestion jobs on a
fixed period, keyed by period so several workers never double-schedule. Notifications are
*not implemented*.

### Advisory fan-out (§30)

```
ingestion run R upserts advisories; some changed
  └─ after the run: enqueue ONE advisories.fanout      key = advisories.fanout:run:{R.id}
fanout(R):
  A = advisories changed in R;  P = their affected packages
  for each repository whose latest scan has a dependency in P,
      and whose latest scan was created BEFORE R finished (newer scans already saw the data):
        enqueue scan.run(trigger=advisory, commit=latest scanned sha)
```

Fanning out once per run, not once per advisory, means an ingestion that changes 50 advisories
affecting one repository produces one rescan, not 50. Scan idempotency keys make a re-delivered
fan-out job harmless.

## 8. Data

Schema and index rationale: [database.md](database.md). Principles:

- PostgreSQL is the system of record; S3 holds large immutable artifacts referenced by key + SHA-256.
- Every tenant-owned row carries `organization_id`; every query in the repository layer is scoped by
  it. Authorisation is checked in the API dependency layer and again by the query shape.
- `findings.version` gives optimistic concurrency for review decisions (stale writes get HTTP 409).
- `audit_events` is append-only, enforced by a database trigger, and hash-chained per organization.

## 9. Errors

Every error raised inside Sieve derives from `SieveError` and carries a category:

| Category | Example | HTTP | Job behaviour |
|---|---|---|---|
| `user` | unsupported lockfile, invalid policy | 4xx | permanent, no retry |
| `external` | GitHub 5xx, OSV timeout | 502/503 | retry with backoff |
| `transient` | DB serialisation failure, Redis down | 503 | retry with backoff |
| `analysis` | parse budget exceeded | — | recorded on result, not retried |
| `security` | bad webhook signature, path traversal attempt | 401/403/400 | permanent, audited |

API errors use one JSON shape (`{"error": {"code", "message", "correlation_id"}}`); internal detail
goes to logs, never to the response body.

## 10. Observability

A correlation id per HTTP request and per job; jobs inherit the id of whatever enqueued them, so a
webhook → scan → check-run chain shares one id. Logs are JSON lines with secrets redacted.

OpenTelemetry instruments FastAPI, SQLAlchemy and httpx, and each scan stage is a span. Sieve's own
metrics: `sieve_jobs_total{kind,outcome}`, `sieve_job_duration_seconds`,
`sieve_scans_total{status}`, `sieve_scan_stage_duration_seconds{stage}`,
`sieve_findings_verdicts_total{verdict}` and `sieve_ai_cost_USD_total{model}`. They are exposed in
Prometheus format at `/metrics` (API) and on `SIEVE_WORKER_METRICS_PORT` (worker); when
`SIEVE_OTEL_EXPORTER_OTLP_ENDPOINT` is set, traces and metrics are also pushed over OTLP (to the
ADOT collector sidecar in AWS). [ADR-0012](decisions/0012-observability.md).

## 11. Where things change at 10× scale

| Pressure | Change |
|---|---|
| Job throughput loads the primary DB | Move `JobQueue` to SQS; keep the transactional insert as an outbox relay. |
| Call-graph indexing of popular packages repeats | Indexes are cached per artifact hash on each worker's disk; move the cache to S3 so workers share it, and cache the resolved graph per lockfile digest (the call-graph stage is over half of a warm scan). |
| Read-heavy dashboards | Read replica for list/aggregate queries. |
| Large monorepos | Shard reachability per finding across workers, reading a shared call-graph snapshot. |
