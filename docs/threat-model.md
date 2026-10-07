# Threat model

> Status: re-run in Phase 11 (2026-10-06) against the implemented code. Every mitigation carries one
> of three labels: **Tested** (with the test that fails if it regresses), **Implemented** (in code or
> configuration, verified by hand, no automated test), or **Not implemented** (with the reason).
> Nothing is listed as done because it was designed. Re-running this review found and fixed two
> gaps: demo scans could still request AI extraction when a model was configured, and the frontend
> CSP allowed inline scripts. Both are now closed and tested or verified below.

Sieve is a security product that ingests **attacker-controllable input from three directions**:
customer repositories, public advisory databases, and the open internet (public demo). Its outputs
(VEX "not affected" statements, passing PR checks) are themselves security-relevant: a manipulated
Sieve can *hide* a real vulnerability. That second point drives several decisions below.

Test paths are relative to `backend/tests/`; `api_security` means
`integration/test_api_security.py`.

## 1. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| GitHub App private key | Mints installation tokens for every customer repo. Highest-value secret. | Secrets Manager; loaded into worker/API memory only. |
| Installation access tokens | Read access to customer source for ≤ 1 h. | Minted on demand; cached **in process memory** until 5 minutes before expiry; never in Postgres or logs. |
| Customer source code | Confidential IP. | Ephemeral worker directories, deleted after each scan. Never sent to the LLM (§5). |
| Session tokens | Account takeover. | Cookie (HttpOnly, SameSite=Lax, Secure in production); the database stores SHA-256 only. |
| Findings, review decisions, VEX | Integrity: a forged "not affected" hides a real risk. | Postgres + artifact store (S3 in AWS). |
| Audit log | Accountability; evidence of who decided what. | Postgres, append-only + hash chain. |
| LLM API key and budget | Financial abuse. | Secrets Manager; spend recorded per call. |
| Webhook secret | Forged events. | Secrets Manager. |

## 2. Threat actors

| Actor | Capability | Goal |
|---|---|---|
| **Malicious repository** (or malicious contributor to a scanned repo) | Controls every byte of the repository: filenames, lockfiles, Python source, README. | Execute code on Sieve workers; exfiltrate tokens; exhaust resources; make a reachable vuln look `not_reached`. |
| **Malicious advisory content** | Controls advisory text and reference URLs in a public database. | Prompt-inject the extractor; induce SSRF via reference URLs; poison symbols. |
| **Prompt-injection attacker** | Text inside an advisory or diff designed to steer the LLM. | Make the model emit attacker-chosen symbols. |
| **Compromised GitHub account** | Legitimate session for a user. | Access other tenants' data; rewrite review history. |
| **Abusive public-demo visitor** | Unauthenticated HTTP. | Burn compute or model budget; DoS; probe for IDOR. |
| **Network attacker** | Arbitrary HTTP to public endpoints. | Forge webhooks; replay deliveries; CSRF. |

## 3. Attack surfaces and mitigations

### 3.1 GitHub webhooks (`POST /webhooks/github`)

| Threat | Mitigation | Status |
|---|---|---|
| Forged webhook triggers scans or fake installation events. | HMAC-SHA256 over the raw body (`X-Hub-Signature-256`), constant-time compare, checked before JSON parsing. | **Tested** — `api_security::test_forged_webhooks_are_rejected` |
| Replayed delivery re-triggers work. | Deliveries keyed on `X-GitHub-Delivery`; duplicates acknowledged and dropped; scans idempotent per commit. | **Tested** — `api_security::test_signed_push_queues_one_scan_and_replays_are_ignored` |
| Payload claims installation X for a repository owned by tenant Y. | The payload is a hint: the repository must already belong to that installation in Sieve's records. | **Tested** — `api_security::test_webhook_for_a_repository_under_another_installation_is_ignored` |
| Large payloads. | Body size capped before HMAC. | **Tested** — `api_security::test_oversized_webhook_is_refused` |

### 3.2 Authentication (GitHub user login)

| Threat | Mitigation | Status |
|---|---|---|
| OAuth CSRF / login fixation. | Random `state` bound to a short-lived, path-scoped HttpOnly cookie; a mismatch is rejected before the code is exchanged. | **Tested** — `api_security::test_oauth_callback_with_a_forged_state_is_rejected_before_contacting_github` |
| OAuth code interception. | PKCE. | **Not implemented.** Sieve is a confidential client (the exchange needs the client secret, held server-side), the case where PKCE adds least. |
| Session theft from the database. | Opaque 256-bit token; only its SHA-256 is stored. | **Tested** — `api_security::test_sessions_are_stored_as_hashes_only` |
| Session theft in transit or via script. | HttpOnly, SameSite=Lax; `Secure` when `environment=production`; server-side revocation on logout. | **Implemented** |
| CSRF on state-changing API calls. | SameSite=Lax plus double-submit token (`X-Sieve-CSRF` header must match the `sieve_csrf` cookie) on every non-GET route. | **Tested** — `api_security::test_state_changes_require_the_csrf_token` |
| Login abuse. | Rate limit on login and callback (20 per 10 minutes per client). | **Implemented** |

### 3.3 API (authorisation, IDOR)

| Threat | Mitigation | Status |
|---|---|---|
| IDOR: guessing another tenant's finding, scan, repository or VEX id. | Every lookup is scoped to the viewer's memberships; unknown and unauthorised ids both return 404 (no existence oracle). The web app renders both as the same not-found page. | **Tested** — `api_security::test_other_tenants_resources_are_indistinguishable_from_missing_ones`, `::test_cannot_review_another_tenants_finding`, `::test_vex_documents_are_generated_validated_and_tenant_scoped` |
| Anonymous access. | Anonymous viewers see only the public demo organization. | **Tested** — `api_security::test_anonymous_sees_only_the_demo`, `::test_members_see_their_organizations` |
| Privilege escalation: a `viewer` submitting a review; a member changing policy. | Role checks in the access layer. | **Tested** — `api_security::test_viewer_role_cannot_review`, `::test_policy_changes_need_an_admin_and_are_versioned` |
| Lost update: two reviewers overwrite each other. | Optimistic lock on the finding version. | **Tested** — `api_security::test_stale_review_is_rejected` |
| SQL injection. | SQLAlchemy with bound parameters only; ruff rule `S608` (string-built SQL) fails CI. | **Tested** — `api_security::test_search_inputs_are_data_not_sql` |
| Mass assignment / malformed input. | Request models with `extra="forbid"` and bounded fields. | **Tested** — `api_security::test_review_payload_is_validated` |
| Internal detail leaking in errors. | One error shape; internal messages are logged, never returned. | **Tested** — `unit/test_core.py::TestErrors::test_internal_message_is_not_the_public_message` |
| Operational endpoints exposed. | `/metrics` is excluded from the OpenAPI document and, in AWS, not routed by the public load balancer. | Exclusion **Tested** — `integration/test_api.py::test_metrics_exposes_request_and_domain_metrics`; load-balancer rule in Terraform, **not applied** |

### 3.4 Repository content (the largest surface)

| Threat | Mitigation | Status |
|---|---|---|
| **Code execution** via `setup.py`, build backends, `conftest.py`, `.pth` files, pip resolution. | **Nothing from the repository or its dependencies is executed, imported, installed or built.** Parsing is `ast.parse` only; no `pip`, no `subprocess` with repository-derived arguments ([ADR-0007](decisions/0007-static-analysis-only.md)). | **Implemented** by construction: no code path executes input |
| Path traversal / zip-slip; absolute paths; device files; links. | Every archive member is validated; anything escaping the root, links and devices are skipped and counted. | **Tested** — `security/test_untrusted_files.py::test_unsafe_member_paths_are_refused`, `::test_zip_slip_and_symlinks_are_skipped`, `::test_tar_links_devices_and_traversal_are_skipped` |
| Symlinks inside a checkout pointing outside it. | Never followed (`lstat` check). | **Tested** — `security/test_untrusted_files.py::TestWorkspace::test_symlinks_are_not_followed` (skipped on Windows without symlink privilege; runs on Linux CI) |
| Decompression bombs / huge repositories. | Limits on actual decompressed bytes, member count, file count, per-file size. | **Tested** — `::test_zip_bomb_is_rejected_by_actual_decompressed_size`, `::test_member_count_limit`, `::TestWorkspace::test_oversized_files_are_not_read`, `::TestWorkspace::test_file_count_limit` |
| Malicious filenames reaching UI or logs. | Paths are data; React renders them as text. | **Tested** — `::TestWorkspace::test_odd_but_legal_filenames_are_data`, `api_security::test_stored_markup_is_returned_as_inert_text` |
| Pathological Python (deep nesting, huge literals). | Package indexing runs in a process pool with a wall-clock timeout and, on Linux, `RLIMIT_AS`/`RLIMIT_CPU`; a failed parse becomes a reason on affected findings. | **Implemented**; the consequence (an unparseable file blocks `not_reached`) is **Tested** — `unit/test_reachability.py::test_unparseable_application_file_blocks_not_reached` |
| Hiding a real call behind dynamic dispatch to obtain `not_reached`. | Dynamic constructs produce blocking edges: an attacker can push a finding to `needs_review`, never to `not_reached`. | **Tested** — `unit/test_reachability.py::test_dynamic_import_prevents_package_not_imported_conclusion`, `::test_unavailable_imported_dependency_blocks_not_imported_conclusions` |
| Prompt injection through repository text. | Repository source is never sent to the LLM (§5). | **Tested** — `ai/test_guardrails.py::test_customer_data_cannot_reach_the_prompt` |

### 3.5 Advisory ingestion and external fetches

| Threat | Mitigation | Status |
|---|---|---|
| SSRF via advisory reference URLs or package URLs. | One HTTP client with a host allow-list (`api.osv.dev`, `osv-vulnerabilities.storage.googleapis.com`, `www.cisa.gov`, `api.first.org`, `pypi.org`, `files.pythonhosted.org`, `api.github.com`); redirects off the list are refused. Fix-commit URLs are parsed into `(owner, repo, sha)` and fetched through the GitHub API. | **Tested** — `security/test_egress.py::test_requests_outside_the_allow_list_are_refused`, `::test_redirects_off_the_allow_list_are_refused` |
| Tampered or oversized PyPI artifacts. | SHA-256 from the PyPI JSON API checked before extraction; download size capped; bad files deleted. | **Tested** — `security/test_egress.py::test_download_verifies_digest_and_removes_bad_files`, `::test_download_enforces_size_cap` |
| Poisoned advisory content (HTML/JS). | Stored and rendered as plain text; no markdown or HTML rendering anywhere. | **Tested** — `api_security::test_stored_markup_is_returned_as_inert_text` |
| One malformed record aborts ingestion or is silently lost. | Failures recorded per record; the run continues. | **Tested** — `integration/test_ingestion.py::test_bad_records_are_dead_lettered_not_dropped` |
| Stale data silently produces "no vulnerabilities". | Ingestion runs recorded; `GET /api/v1/advisories/health` reports per-source freshness. | **Implemented** |

### 3.6 LLM / AI

| Threat | Mitigation | Status |
|---|---|---|
| Prompt injection in advisory text or diffs. | Untrusted text is fenced and cannot close its fence. More importantly, output cannot act by itself: it is schema-validated, and each symbol must exist in the package source and (with a fix diff) be touched by the fix. | **Tested** — `ai/test_guardrails.py::test_untrusted_text_cannot_close_its_fence`, `::test_prompt_injection_cannot_smuggle_a_decoy` |
| Model fabricates symbols. | Same verification; the rejection rate is measured. | **Tested** — `::test_only_existing_fix_related_symbols_of_the_right_kind_are_accepted`, `::test_malformed_outputs_are_rejected_whole`; measured in [ai-evaluation.md](ai-evaluation.md) (0 fabricated symbols accepted on the 32-case golden set with the heuristic provider; live model not yet measured) |
| Data exfiltration through the model. | No tools, no network; context never contains secrets, tokens or customer source. | **Tested** — `::test_customer_data_cannot_reach_the_prompt` |
| Budget exhaustion. | Extraction keyed per advisory and cached; per-day spend cap checked before each call. | **Implemented** |

### 3.7 Frontend

| Threat | Mitigation | Status |
|---|---|---|
| XSS via repository paths, advisory text, symbol names, code snippets. | React escaping; the syntax highlighter emits tokens, not HTML; the only raw HTML is a constant theme script. CSP `script-src 'self' 'nonce-…' 'strict-dynamic'` with a fresh nonce per request (`web/src/proxy.ts`). Styles allow `'unsafe-inline'` because React style attributes cannot carry a nonce. | **Implemented**; verified 2026-10-06 in Chrome: every rendered script carries the nonce, the app hydrates, and the console shows no CSP violations |
| Clickjacking. | `frame-ancestors 'none'` and `X-Frame-Options: DENY`. | **Implemented** |
| Session cookies sent cross-site. | The browser talks to one origin; the API is reached through same-origin rewrites. | **Implemented** |

### 3.8 Workers, storage and audit

| Threat | Mitigation | Status |
|---|---|---|
| Rewriting review history or the audit log. | `audit_events` and `review_decisions` are append-only (database triggers reject UPDATE/DELETE); events are hash-chained per organization; tampering that bypasses the trigger is detected on verification. | **Tested** — `integration/test_audit.py::test_database_rejects_rewriting_history`, `::test_tampering_that_bypasses_the_trigger_is_detected`, `::test_events_form_a_verifiable_chain`, `::test_chains_are_per_organization` |
| Tampering with stored VEX or SBOM. | SHA-256 recorded at generation; the artifact store verifies it on every read. | **Tested** — `api_security::test_vex_documents_are_generated_validated_and_tenant_scoped` |
| Worker compromise → lateral movement. | Non-root container user; read-only root filesystem with a writable scratch volume; IAM role limited to the artifact bucket; application-level egress allow-list. | Non-root user and allow-list **Implemented** / **Tested** (above). Read-only root filesystem and IAM scope are in the Terraform task definitions, **not applied** (no AWS account). Network-level egress filtering **Not implemented**. |
| S3 data exposure. | Block Public Access; encryption at rest; TLS-only bucket policy; downloads only through the authorised API. | In Terraform, **not applied** |
| Secrets in logs. | Redaction processor for known secret settings and token patterns (`ghs_`, `ghu_`, `gho_`, `sk-`, private keys, URL credentials). | **Tested** — `unit/test_core.py::TestRedaction` |

### 3.9 Public demo

| Threat | Mitigation | Status |
|---|---|---|
| Unlimited scans → compute DoS. | Demo scans coalesced per time bucket (repeated clicks share one scan) and rate limited per client. | **Tested** — `api_security::test_demo_scans_are_coalesced_and_rate_limited` |
| Demo used to reach or change tenant data. | The demo is its own organization; read-only even for signed-in users; same authorisation path as real tenants. | **Tested** — `api_security::test_demo_is_read_only_even_for_signed_in_users`, `::test_anonymous_sees_only_the_demo` |
| Demo used to spend model budget. | Scans of the demo organization never request AI extraction, whatever triggered them (demo click or advisory rescan). | **Tested** — `integration/test_scan_pipeline.py::test_missing_symbols_reach_the_model_only_for_customer_organizations` |

## 4. Secrets handling

- Never committed: `.env` is git-ignored; `gitleaks` runs in CI.
- Local: `.env`. CI: GitHub Actions secrets (not exposed to fork PRs). Production: AWS Secrets
  Manager, injected into ECS tasks as secrets (Terraform, not applied).
- Log redaction as in §3.8.

## 5. What the LLM sees

Allowed: advisory id, summary, details (size-capped), affected package name and version, reference
URLs, and the **public** upstream fix-commit diff (size-capped). Not allowed: customer repository
source, file paths, tokens, user identities, any secret. `build_user_message` is the only place model
input is assembled; its parameters, and those of `ExtractionService.extract`, are pinned by
`ai/test_guardrails.py::test_customer_data_cannot_reach_the_prompt`, so adding a repository-derived
input fails CI until this section is revisited.

## 6. Residual risks (accepted, documented)

- Static analysis can be evaded by sufficiently dynamic code; the mitigation pushes such findings to
  `needs_review`, it does not detect intent.
- A malicious upstream *package* (supply-chain malware) is out of scope; Sieve triages known
  advisories, it is not a malware scanner.
- A GitHub organization owner can grant themselves access; Sieve inherits GitHub's authorisation.
- Installation tokens live in worker memory; a compromised worker process can read the tokens it
  holds (at most one hour of read access per installation).
- No network-level egress control yet: the allow-list is enforced in the application's HTTP client
  only.
- No external penetration test has been performed.
