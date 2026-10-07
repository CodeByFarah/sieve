# Security

How Sieve protects the people who use it. The adversarial analysis lives in
[threat-model.md](threat-model.md); this page is the operational summary.

## Security properties Sieve aims to guarantee

1. **Customer code is never executed.** Not imported, not installed, not built, not run in a
   sandbox. Repository content is parsed with `ast.parse` and nothing else. Dependencies are analysed
   from their published PyPI artifacts, also by parsing only.
2. **Credentials are short-lived.** Sieve stores no GitHub user or installation tokens at rest.
   Installation tokens are minted per job from the App private key and expire within an hour.
3. **Tenants are isolated.** Every tenant-owned row carries an `organization_id`, and every query is
   scoped by the caller's membership. Cross-tenant access returns 404.
4. **History is append-only.** Review decisions and audit events cannot be updated or deleted through
   the application, and a database trigger rejects it at the storage layer too. The audit log is
   hash-chained so tampering that bypasses the trigger is detectable.
5. **AI output is never trusted.** It is schema-validated and verified against package source before
   use, and it can never set a verdict.
6. **Unknown stays unknown.** Analysis that cannot establish a result reports `needs_review`; it is
   not rounded to `not_reached`.

## Controls

| Area | Control |
|---|---|
| Transport | TLS at the load balancer (TLS 1.3 policy, HTTP redirected), HSTS, TLS to the database (`rds.force_ssl`) and Redis. |
| Sessions | Opaque random token in an HttpOnly, SameSite=Lax cookie (Secure in production); hashed at rest; absolute expiry (12 h by default; no idle timeout yet); server-side revocation on logout. |
| CSRF | SameSite=Lax plus double-submit token header on state-changing requests. |
| Webhooks | HMAC-SHA256 verification on the raw body, constant-time compare, delivery-id replay protection. |
| Input validation | Pydantic models with `extra="forbid"`; size limits on bodies, files and fields. |
| Output encoding | React escaping; CSP with a per-request script nonce; no raw HTML from data. |
| Rate limiting | Fixed-window limits in Redis (in-process without Redis) for login, scan triggers and the demo. AI extraction is never triggered by a request; it has a daily spend cap. |
| Egress | Outbound HTTP only to an allow-list of hosts; no redirects off the list. |
| Archives | Zip-slip, symlink, hardlink, device-file, size, count and depth checks on every extraction. |
| Secrets | Env vars locally; GitHub Actions secrets in CI; AWS Secrets Manager in production. `gitleaks` in CI (no pre-commit hook yet). Log redaction processor. |
| Dependencies | Lockfiles committed for Python and JS; `pip-audit` and `npm audit` in CI; Trivy image and IaC scans; Dependabot for Python, npm, Actions, Docker and Terraform. |
| Containers | Non-root user, slim base image, read-only root filesystem with one writable scratch volume in the AWS task definitions. |

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting on this repository.
There is no bug bounty.

## Security testing

Security tests run on every pull request: `backend/tests/security/` (archives, workspaces, egress),
`backend/tests/integration/test_api_security.py` (authorisation, CSRF, webhooks, OAuth, demo abuse)
and `backend/tests/ai/test_guardrails.py` (prompt injection, prompt isolation). Each mitigation in the
threat model links to the test that proves it. Categories: webhook forgery and
replay, path traversal and archive attacks, malicious filenames, IDOR and role escalation, SQL
injection probes, XSS payloads in stored fields, SSRF via advisory references, secret leakage in logs
and error bodies, and prompt-injection fixtures in the AI golden dataset.
