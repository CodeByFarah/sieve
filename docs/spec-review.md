# Specification review

Phase 0, steps 6–8: technical risks, internal inconsistencies, and the corrections adopted.
Every correction below is reflected in the architecture and ADRs. Where a correction changes
something the specification asked for explicitly, the ADR that records it is linked.

---

## 1. Inconsistencies and unnecessary complexity

### 1.1 Finding "states" mix three independent dimensions

The spec's state chain (`DISCOVERED → ANALYZING → ANALYZED → REACHABLE/NOT_REACHED/NEEDS_REVIEW → REVIEWED → VEX_GENERATED`)
combines:

- the **analysis lifecycle** (has analysis run?),
- the **reachability verdict** (what did analysis conclude?),
- the **review status** (has a human signed off?),
- and **VEX generation**, which is a property of a *document* covering many findings, not of one finding.

A single enum forces nonsense transitions: a reviewed finding that is re-analyzed after an advisory
update would have to move "backwards" from `VEX_GENERATED` to `ANALYZING`, losing the fact that it
was reviewed.

**Correction:** model them as separate, individually validated fields on `findings`:

| Field | Values |
|---|---|
| `analysis_state` | `pending`, `analyzing`, `analyzed`, `failed` |
| `verdict` | `reachable`, `not_reached`, `needs_review` (null until analyzed) |
| `review_state` | `unreviewed`, `accepted`, `overridden`, `stale` |
| `presence` | `present`, `resolved` (dependency upgraded or removed) |

`stale` means: a human reviewed it, but analysis has since produced different evidence, so the review
must be re-confirmed. VEX documents reference the review decisions they were built from.
See [ADR-0009](decisions/0009-finding-state-model.md).

### 1.2 "94% confidence" implies a calibrated probability we do not have

Static reachability analysis does not produce a calibrated probability. Displaying `94%` would be a
fabricated precision, which conflicts with the spec's own honesty rules (§47, §66).

**Correction:** confidence is a discrete, rule-derived level — `high`, `medium`, `low` — and every
level is accompanied by the concrete reasons that produced it (e.g. "symbol verified in installed
source", "direct call resolved through import alias", "path crosses one unresolved dynamic call").
If a numeric score is ever displayed it must be the output of a measured calibration against a
labelled dataset, and the docs must say so. See [ADR-0010](decisions/0010-confidence-levels.md).

### 1.3 Marketing numbers in the hero (214 / 9 / 187 / 18) and a "fake/demo repository" in §73

§7 and §71 say "use real demo numbers only"; §73 says "display a fake/demo repository". The only
consistent reading: the landing page visualisations are rendered **from the stored result of a real
demo scan** of the project-owned sample application. The numbers on the page are whatever that scan
produced. No number appears in source code as a literal.

### 1.4 Redis queue *and* AWS queue *and* outbox *and* event bus

§8 offers "Redis-backed worker system OR AWS-native queue", §29 adds an outbox and a queue, §59
forbids complex event buses. An outbox exists to solve the dual-write problem between the database
and a separate broker. If the queue **is** the database, the dual-write problem disappears.

**Correction:** a PostgreSQL-backed job queue (`jobs` table, `SELECT … FOR UPDATE SKIP LOCKED`,
lease timeouts, attempts, exponential backoff, `dead` status as the dead-letter queue, unique
idempotency keys). Jobs are inserted in the same transaction as the domain change that caused them,
so they are exactly as durable as the data. Redis is used only for rate limiting, short-lived caches
and scan-progress fan-out to SSE clients — never as the system of record for work.
At 10× scale (or once job throughput threatens primary DB load) the `JobQueue` interface can be
backed by SQS; the transactional insert then becomes a real outbox relay.
See [ADR-0004](decisions/0004-postgres-job-queue.md).

### 1.5 Top-level `analysis/`, `ai/`, `workers/`, `packages/` split one Python application

The suggested layout scatters one Python codebase across five top-level directories. In practice
this produces `sys.path` hacks, several `pyproject.toml` files that must be versioned together,
and "shared" packages that are imported by exactly one consumer.

**Correction:** one Python distribution, `sieve`, in `backend/`, organised by domain module
(`sieve.analysis`, `sieve.ai`, `sieve.advisories`, …). The API and the worker are two **entry points**
of the same package and the same container image, started with different commands.
`packages/schemas` (shared TS/Python types) is replaced by generating TypeScript types from the API's
OpenAPI document. See [ADR-0003](decisions/0003-modular-monolith.md).

### 1.6 Separate "OAuth login" and "GitHub App"

Two GitHub registrations (an OAuth App for login, a GitHub App for repo access) mean two sets of
secrets and two permission models. A GitHub App can perform user authorization itself
(user-to-server tokens). **Correction:** one GitHub App handles both login and installation.

### 1.7 "Vulnerability" and "Advisory" as separate entities

OSV already normalises an advisory and its aliases (CVE, GHSA, PYSEC) into one record. Two tables
would duplicate data with no consumer for the distinction.
**Correction:** one `advisories` table with an `aliases` array (GIN-indexed); CVE-keyed data (KEV,
EPSS) is joined via aliases. `AnalysisJob` is likewise subsumed by the generic `jobs` table.

### 1.8 "Symbol exists in the installed dependency" — but we never install anything

§15 forbids installing packages or running install scripts; §20 and §83 require verification against
"installed" source. **Correction:** Sieve downloads the exact released artifact from PyPI
(preferring wheels; sdists only as archives) over an allow-listed host, extracts it into an isolated
temp directory with zip-slip/size/count limits, and **parses** the Python files with `ast`. Nothing
is imported, built or executed. "Installed version" in the UI means "the version pinned in the
lockfile". See [ADR-0007](decisions/0007-static-analysis-only.md).

### 1.9 Resolving unpinned requirements would execute code

`requirements.txt` lines such as `flask>=2` and bare `pyproject.toml` dependency ranges do not
identify a version. Resolving them means running a resolver, and resolving sdists can execute
`setup.py`. **Correction:** Sieve never resolves. Unpinned dependencies are recorded with their
constraint and `version = null`; advisories matching the constraint produce findings with verdict
`needs_review` and reason `version_unpinned`. The UI recommends committing a lockfile.

### 1.10 AI evaluation "in CI" on every pull request

Live LLM calls on every PR are non-deterministic, cost money, and need a secret that fork PRs must
not receive. **Correction:** two tiers.
- **Every PR:** the evaluation harness runs against *recorded* model responses (replay). This
  exercises parsing, guardrails, deterministic verification and metric computation, and fails if the
  validator's behaviour regresses.
- **Prompt/model change (path filter) or manual dispatch:** live run against the configured provider
  on a protected branch, producing a regression report artifact compared to the stored baseline.
See [docs/ai-evaluation.md](ai-evaluation.md).

### 1.11 Observability: OpenTelemetry + Prometheus + Grafana + CloudWatch + "error tracking"

Five overlapping systems is more to operate than the application itself.
**Correction:** instrument once with OpenTelemetry (traces + metrics) and JSON structured logs.
Locally, `/metrics` is exposed in Prometheus format and traces go to the console or an optional
Jaeger container. In AWS, logs go to CloudWatch Logs; metrics and traces go through the ADOT
collector to CloudWatch/X-Ray. Errors are logged with correlation IDs and alarmed on in CloudWatch;
a third-party error tracker is optional. See [ADR-0012](decisions/0012-observability.md).

### 1.12 Phase 16 deliverables are not engineering artifacts

LinkedIn posts, résumé bullets and a demo video cannot be produced truthfully until the system
exists and has been measured. They are drafted at the end, using only measured numbers.

### 1.13 Demo "real AI" vs. "no unlimited expensive AI requests"

A public visitor clicking "Run demo scan" must not be able to spend LLM budget.
**Correction:** the demo scan performs real SBOM generation, advisory matching, source verification
and reachability analysis on every click. AI symbol extraction results for the demo's advisories are
real model outputs produced ahead of time by the normal extraction pipeline and **cached** in the
`ai_extractions` table (the same cache every scan uses); the UI labels them with model, prompt
version and extraction date. Demo scans never trigger a live model call.

---

## 2. Technical risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | **False `not_reached` on transitive dependencies.** A vulnerable function in `urllib3` may be reached via `requests`, never named in app code. | A wrong "not affected" VEX is the worst failure mode of the product. | Reachability walks into dependency source (bounded). `not_reached` requires: verified symbols, a completed traversal that crossed every imported dependency on the path, and no unresolved dynamic dispatch in the traversed frontier. Anything else is `needs_review`. Asymmetric policy: we prefer false `needs_review` over false `not_reached`. |
| R2 | **Python dynamism** (`getattr`, `importlib`, decorators that wrap, monkey-patching, `__getattr__` modules, plugin entry points). | Missed edges → false negatives. | Detect and record dynamic constructs as "unresolved edges"; they downgrade confidence and block `not_reached` when they could reach the vulnerable package. Documented in limitations. |
| R3 | **Advisories lack symbols.** Most OSV PyPI records carry no symbol-level data. | Without symbols, every finding is `needs_review`. | AI extraction from advisory text + fix-commit diffs, verified against source. Measure coverage; report honestly. |
| R4 | **LLM hallucinated symbols.** | Wrong symbols → wrong verdicts. | Symbols must exist in the package source at a vulnerable version; when a fix diff is available, the symbol must be touched by the diff (or be a public caller of something touched). Rejections are recorded and measured. |
| R5 | **Entry-point detection** (which functions are "reachable from the outside"). | Too narrow → false negatives; too broad → noise. | Conservative default: all module-level code and all functions of application modules are roots; framework-aware detection (Flask/FastAPI/Django/Click) annotates *which* roots are HTTP/CLI entry points for the evidence path. |
| R6 | **Hostile repository content** (zip bombs, symlinks, path traversal, giant files, pathological ASTs, prompt injection in READMEs/advisories). | DoS, data exfiltration, model manipulation. | Size/count/depth limits, no symlink following, AST parse in a resource-limited subprocess, structured-only model outputs, input delimiting, no tools for the model. See [threat model](threat-model.md). |
| R7 | **GitHub API rate limits** during advisory fan-out across many repositories. | Rescans stall. | Fan-out re-analyses the stored SBOM and cached call graph first; only fetches from GitHub when the commit changed. Per-installation concurrency limits. |
| R8 | **Ingestion volume.** The full OSV PyPI export is tens of thousands of records. | Slow ingestion, large DB. | Bulk export download once, then incremental by `modified` timestamp; content-hash dedup to skip unchanged records. |
| R9 | **Version semantics.** PEP 440 vs. OSV `ECOSYSTEM` ranges, pre-releases, local versions, yanked releases. | Wrong affected/not-affected classification. | `packaging.version`; table-driven tests of range semantics; unparseable versions → `needs_review`. |
| R10 | **AWS cost for a portfolio deployment** (NAT gateway, ALB, RDS, ElastiCache). | Project gets turned off. | Documented low-cost profile in [deployment.md](deployment.md): no NAT gateway, single-AZ small instances, Fargate Spot for workers. |
| R11 | **Scope.** The spec describes many months of work. | Nothing ships. | Strict dependency-ordered phases; each ends with working, tested software. The golden demo path (§7) is prioritised over breadth. |

---

## 3. Decisions intentionally left open

- **Default LLM provider/model.** Chosen by running the evaluation suite against candidates, not by
  preference. Until then the `mock` and replay providers are the only ones exercised in CI.
- **Hosting the frontend.** Fargate behind the same ALB is the default (single cloud, single
  pipeline). Moving `web` to a CDN-backed host is a later optimisation if measured latency warrants it.
