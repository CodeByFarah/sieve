# API

The authoritative contract is the OpenAPI document served by the API at `/openapi.json`
(interactive docs at `/docs` outside production) and committed as `web/openapi.json`. The
frontend's TypeScript types are generated from it, and CI fails if either copy is stale.

## Conventions

- Base path `/api/v1`. JSON only. UTC ISO-8601 timestamps. UUID identifiers.
- Authentication: session cookie (`sieve_session`). State-changing requests also require the
  `X-Sieve-CSRF` header matching the `sieve_csrf` cookie.
- Authorisation: resources are addressed by id or organization login and checked against the
  caller's memberships. Resources outside the caller's organizations return **404**, never 403, so
  the API is not an existence oracle. Anonymous callers can read only the public demo.
- Pagination: cursor-based (`?cursor=…&limit=…`, response `{items, total, next_cursor}`).
- Concurrency: findings carry `version`; a review sends `expected_version`; a mismatch is **409**.
- Errors: `{"error": {"code": "…", "message": "…", "correlation_id": "…"}}`. Every response carries
  `X-Correlation-Id`.
- Rate limits: login, demo scans and other abuse-prone routes return **429** when exceeded.

## Resources

| Method & path | Purpose |
|---|---|
| `GET /healthz` | Liveness (process up; checks nothing else) |
| `GET /readyz` | Readiness: database reachable and migrations at head |
| `GET /metrics` | Prometheus metrics. Not in the OpenAPI document and not routed by the public load balancer |
| `GET /api/v1/me` | Current user, their organizations (plus the demo), whether GitHub login is configured |
| `GET /api/v1/auth/github/login` · `GET …/callback` · `POST /api/v1/auth/logout` | GitHub OAuth login with a `state` check; logout revokes the session |
| `GET /api/v1/orgs/{login}/overview` | Exposure summary: verdict counts, KEV, top risks, recent scans, data freshness |
| `GET /api/v1/orgs/{login}/findings` | Findings, filterable by verdict, severity, KEV, package, repository, presence, text; sortable |
| `GET /api/v1/orgs/{login}/repositories` | Repositories with health and verdict counts |
| `GET /api/v1/orgs/{login}/activity` | Audit events, with verification of the hash chain |
| `GET /api/v1/orgs/{login}/vex` | Generated VEX documents |
| `GET`, `PUT /api/v1/orgs/{login}/policy` | Pull-request policy; `PUT` (admins) creates a new version |
| `GET /api/v1/orgs/{login}/search` | Command-palette search over findings, repositories and packages |
| `GET /api/v1/repositories/{id}` | One repository |
| `GET`, `POST /api/v1/repositories/{id}/scans` | Scan history; `POST` requests a rescan of the latest commit |
| `GET /api/v1/repositories/{id}/pull-requests` | Pull-request checks and their policy outcome |
| `GET /api/v1/repositories/{id}/vex/preview?format=openvex\|cyclonedx` | VEX for the current findings, not stored |
| `POST /api/v1/repositories/{id}/vex` | Generate, validate against the official schema, and store a VEX document |
| `GET /api/v1/scans/{id}` | Scan detail: stages, counts, manifests, errors |
| `GET /api/v1/scans/{id}/events` | Server-Sent Events stream of scan progress; ends when the scan finishes |
| `GET /api/v1/scans/{id}/sbom` | The scan's CycloneDX 1.6 SBOM |
| `GET /api/v1/findings/{id}` | Finding detail: verdict, reasons, evidence path, verified symbols, risk breakdown, VEX statement, review, history |
| `POST /api/v1/findings/{id}/reviews` | Accept or override the verdict, with VEX status and justification |
| `GET /api/v1/demo` · `POST /api/v1/demo/scans` | Public demo state and its rate-limited, coalesced rescan |
| `GET /api/v1/advisories/health` | Freshness and last result of each advisory source (OSV, KEV, EPSS) |
| `GET /api/v1/vex/{id}/download` | A stored VEX document; its SHA-256 is verified on read |
| `POST /webhooks/github` | GitHub App webhook (HMAC-verified, deduplicated by delivery id) |
