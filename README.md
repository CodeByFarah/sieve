# Sieve

**Know which vulnerabilities actually reach your code.**

Your dependency scanner tells you what is vulnerable. Sieve tells you what is *reachable*, and shows
the evidence: the call path from your application code to the vulnerable function, which parts of
the reasoning came from an AI model, and which parts were verified deterministically.

> **Status:** all sixteen planned phases are built and tested locally: the analysis engine, GitHub
> integration, review workflow, VEX output, web app and public demo. **Not done:** nothing has been
> deployed to AWS (the Terraform is validated, never applied), no live AI model has been evaluated
> (no API key was available), and the GitHub App has not been registered. Details in
> [What exists](#what-exists).

---

## The problem

A typical dependency scanner answers *"does this repository contain a vulnerable version?"* For a
Python service with a few hundred transitive dependencies, that produces a long list, much of it
about functions the application never calls. Teams either drown in alerts or start ignoring them.

Sieve asks a narrower question: *can this application actually reach the vulnerable code?* Every
finding ends in one of three verdicts:

| Verdict | Meaning |
|---|---|
| `reachable` | A static call path exists from application code to a verified vulnerable function. |
| `not_reached` | The vulnerable function is known and verified, analysis completed, and no path, including weak or dynamic ones, was found. |
| `needs_review` | Analysis cannot establish either. **This is a real answer, not a failure.** |

Sieve is not a replacement for Snyk, Endor Labs, Dependabot, Semgrep or similar products, several
of which offer reachability analysis. It is a transparent, evidence-first implementation of the
idea, built to show its work.

## On the demo application

The public demo scans a deliberately vulnerable Flask app pinned to old dependencies, against a
recorded snapshot of real OSV, CISA KEV and EPSS data (2026-10-06):

| | Findings |
|---|---|
| Vulnerable dependency versions a scanner would report | 100 |
| `reachable`, with a call path as evidence | 9 |
| `needs_review` | 48 |
| `not_reached` | 43 |
| On CISA's known-exploited list | 1 |

After the maintainers' recorded reviews (one of them overrides a verdict), the demo shows 8
reachable and 44 not reached. These numbers describe one small sample app, not real-world
repositories in general; nothing larger has been measured.

## How it works

```
lockfiles ──▶ SBOM ──▶ OSV / KEV / EPSS ──▶ vulnerable symbols ──▶ call graph ──▶ verdict + evidence ──▶ human review ──▶ VEX
                                              ▲            │
                                AI proposes ──┘            └─ verified against real package source
```

1. **Inventory**: parse lockfiles (never execute or install anything) into a CycloneDX 1.6 SBOM.
2. **Intelligence**: match pinned versions against OSV advisories, enriched with CISA KEV and EPSS.
3. **Symbols**: work out *which functions* an advisory concerns. Curated entries come first; when
   none exist, an AI model can propose candidates from the advisory and its fix diff. Each candidate
   must exist in the published package source and match the fix, or it is rejected.
4. **Reachability**: build a static call graph over the application *and* its dependencies
   (downloaded from PyPI, digest-verified, parsed only) and search for paths to verified symbols.
5. **Decision**: a transparent risk score, human review with optimistic locking, an append-only
   hash-chained audit log, OpenVEX and CycloneDX VEX output validated against the official schemas,
   and pull-request checks driven by a versioned policy.

Design rules:

- **Customer code is never executed.** Static analysis only ([ADR-0007](docs/decisions/0007-static-analysis-only.md)).
- **The AI proposes; deterministic analysis decides** ([ADR-0008](docs/decisions/0008-ai-proposes-deterministic-decides.md)).
- **Unknown stays unknown.** A wrong `not_reached` can become a false "not affected" statement,
  so the verdict rules are asymmetric: dynamic code can push a finding to `needs_review`, never to
  `not_reached` ([architecture §5.2](docs/architecture.md#52-verdict-rules)).
- **No invented precision.** Confidence is `high`/`medium`/`low` with stated reasons
  ([ADR-0010](docs/decisions/0010-confidence-levels.md)). No metric appears anywhere without a
  measurement behind it.

## What exists

| Area | State |
|---|---|
| Lockfile parsing, CycloneDX SBOM, OSV/KEV/EPSS ingestion with per-run fan-out rescans | Implemented, tested |
| Static reachability engine (aliases, star imports, MRO, `super()`, transitive dependencies, weak-edge blocking) | Implemented, tested |
| AI symbol extraction with schema validation, source verification and fix-diff cross-check | Implemented, tested offline; **live model not evaluated** |
| AI evaluation harness, 32-case golden dataset, CI regression gate | Implemented; heuristic baseline measured ([results](docs/ai-evaluation.md#8-results)) |
| Risk scoring, review workflow, VEX generation, audit log, policy engine, PR checks | Implemented, tested |
| GitHub App integration (webhooks, installation tokens, check runs, OAuth login) | Implemented, tested with signed fixtures; **not connected to a registered App** |
| Web app (Next.js): landing, overview, findings, evidence page, scans, repositories, policy, VEX, activity | Implemented; Lighthouse accessibility, best practices and SEO 100 on the pages audited |
| Observability: JSON logs, OpenTelemetry traces, Prometheus metrics, CloudWatch alarms | Implemented locally; alarms in Terraform only |
| AWS infrastructure (ECS Fargate, RDS, ElastiCache, S3, ALB, Secrets Manager, OIDC deploy) | Terraform validated and Trivy-scanned; **never applied** |
| Threat model with a test linked to each mitigation | [docs/threat-model.md](docs/threat-model.md) |

Measured on 2026-10-06 on a Windows laptop (details and caveats in
[performance.md](docs/performance.md)): a demo scan takes **29.3 s** with a cold package cache and
**10.3 s** (p50, n = 5) warm. 231 backend tests pass.

## Run it yourself

The quickest way to see Sieve working. You only need [Git](https://git-scm.com/downloads) and
[Docker Desktop](https://www.docker.com/products/docker-desktop/) (running).

```bash
git clone https://github.com/CodeByFarah/sieve.git
cd sieve
docker compose up -d --build                        # first build takes a few minutes
docker compose exec api python -m sieve.demo.seed   # load the demo data and queue the demo scan
```

Open **http://localhost:3000**. The demo scan finishes in under a minute; refresh the page and open
the `sieve-demo` organization to explore findings, call paths, scans and VEX output.

- Stop it with `docker compose down` (add `-v` to also delete the database).
- If port 3000, 8000 or 5432 is already in use, set `SIEVE_WEB_PORT`, `SIEVE_API_PORT` or
  `SIEVE_POSTGRES_PORT` before `docker compose up`, for example `SIEVE_WEB_PORT=3001`.
- Live advisory ingestion is off by default, so the demo uses the recorded snapshot. Set
  `SIEVE_INGEST_EVERY_HOURS=24` to pull live OSV, KEV and EPSS data instead.

## Running locally

For development (tests, linting, hot reload). Requirements: [uv](https://docs.astral.sh/uv/),
Docker with Compose, Node 22, and `make` (on Windows, run the commands from the
[Makefile](Makefile) directly).

```bash
make setup     # backend dependencies, backend/.env
make dev       # postgres + migrations + api (:8000) + worker + web (:3000)
make demo      # load the advisory snapshot and queue the demo scan
make check     # backend lint + mypy --strict + tests
make web-check # frontend typecheck, lint, build
```

Then open http://localhost:3000 and choose **Run the live demo**.

Connecting real repositories needs a GitHub App you register yourself (App id, private key,
webhook secret, OAuth client id and secret; see [ADR-0013](docs/decisions/0013-single-github-app.md) and
[deployment.md](docs/deployment.md#first-deployment)). AI extraction needs
`SIEVE_AI_PROVIDER=anthropic` and an API key; without it, findings that lack curated symbols are
`needs_review`.

## Documentation

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | System shape, modules, scan pipeline, reachability rules, jobs, observability |
| [threat-model.md](docs/threat-model.md) | Assets, actors, mitigations, each with its status and test |
| [security.md](docs/security.md) | Security properties and controls |
| [ai-evaluation.md](docs/ai-evaluation.md) | Golden dataset, metrics, regression gate, results |
| [performance.md](docs/performance.md) | Benchmarks with machine, date and command |
| [deployment.md](docs/deployment.md) | Local stack, AWS Terraform, CI, releases, rollback |
| [api.md](docs/api.md) · [database.md](docs/database.md) | API conventions and resources; schema and index rationale |
| [spec-review.md](docs/spec-review.md) · [development-plan.md](docs/development-plan.md) | Corrections to the original spec; build plan |
| [decisions/](docs/decisions/) | Architecture Decision Records |

## Limitations

- Python and PyPI only. Reads requirements files, `poetry.lock`, `uv.lock`, `Pipfile.lock` and
  `pyproject.toml`. Unpinned dependencies are `needs_review`, not resolved.
- Static analysis cannot see through every form of dynamic dispatch, reflection, monkey-patching,
  generated code or native extensions. Such cases become `needs_review`.
- Nearly half the demo findings are `needs_review` (48 of 100): 32 because no verified symbols
  exist for those advisories without an AI model, 16 because the only paths found go through
  dynamic dispatch, dynamic attributes or plain references. That is the honest result, not a bug.
- The AI golden dataset has 32 cases, labelled during development and not independently reviewed.
- Benchmarks come from one laptop and one small app.

## License

[MIT](LICENSE)
