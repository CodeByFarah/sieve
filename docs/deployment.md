# Deployment

> Status: runs locally (Docker Compose, or natively). The AWS deployment exists as Terraform in
> [`infrastructure/terraform`](../infrastructure/terraform): it passes `terraform validate` and a
> Trivy misconfiguration scan, but it has **never been applied** (no AWS account was available).
> Treat the first apply as a test of the configuration, not a routine release.

## Local development

```
make setup       # backend dependencies (uv) and backend/.env from .env.example
make dev         # docker compose: postgres, one-shot migrate, api (reload), worker, web
make demo        # load the advisory snapshot and queue the demo scan
make test        # unit + integration tests (throwaway sieve_test database)
make check       # lint + mypy --strict + tests
make web-check   # typecheck, lint and build the frontend
make ai-eval     # golden-dataset evaluation, gated on the committed baseline
make bench       # scan and API benchmark (docs/performance.md)
```

| Service | Host port | Notes |
|---|---|---|
| web | 3000 (`SIEVE_WEB_PORT`) | Next.js production server; `/api/*` is rewritten to the API |
| api | 8000 (`SIEVE_API_PORT`) | FastAPI with reload; OpenAPI at `/docs`, Prometheus at `/metrics` |
| worker | — | Same image as api, `python -m sieve.worker`; set `SIEVE_WORKER_METRICS_PORT` for its `/metrics` |
| migrate | — | One-shot `alembic upgrade head`; api and worker start after it succeeds |
| postgres | 5432 (`SIEVE_POSTGRES_PORT`) | PostgreSQL 16 |

Redis and S3 are optional locally: without `SIEVE_REDIS_URL` each API process rate-limits on its
own, and artifacts go to the filesystem (`SIEVE_ARTIFACT_BACKEND=filesystem`).

Windows note: use `127.0.0.1`, not `localhost`, in database URLs. On some Windows setups
`localhost` resolves to IPv6 first and each connection waits for that attempt to time out.

## AWS (ca-central-1)

```
DNS ─▶ ALB (ACM TLS) ─┬─ /api/*, /webhooks/* ─▶ ECS Fargate: api ──┐
                      └─ everything else ─────▶ ECS Fargate: web ──┤ (web → api over Service Connect)
                                                ECS Fargate: worker┤ (same image as api, Fargate Spot)
                                                                   ├─▶ RDS PostgreSQL 16 (private subnets)
                                                                   ├─▶ ElastiCache Redis (private, TLS)
                                                                   ├─▶ S3 artifacts (gateway endpoint)
                                                                   └─▶ Secrets Manager
api and worker tasks run an ADOT collector sidecar: OTLP → X-Ray (traces) and CloudWatch (metrics).
```

| File | Contents |
|---|---|
| `network.tf` | VPC, two public subnets for tasks and the ALB, two private subnets for data, S3 gateway endpoint. No NAT gateway. |
| `security_groups.tf` | One group per role. Tasks accept traffic only from the ALB (and web → api). Outbound: HTTPS anywhere, everything inside the VPC. |
| `data.tf` | RDS PostgreSQL 16 (encrypted, `rds.force_ssl`, backups, deletion protection, final snapshot), Redis with TLS and at-rest encryption, and the secrets. |
| `storage.tf` | ECR repositories (immutable tags, scan on push) and the artifact bucket (Block Public Access, SSE, versioning, TLS-only policy). |
| `iam.tf` | Execution role (pull images, read this deployment's secrets); backend task role (artifact bucket, X-Ray, metrics); web task role with no permissions. |
| `alb.tf` | HTTPS listener (TLS 1.3 policy), HTTP → HTTPS redirect, path routing. `/metrics`, `/readyz` and `/docs` are not routed. |
| `ecs.tf` | Cluster, task definitions (api, worker, web, one-off migrate), services with circuit-breaker rollback. Read-only root filesystems with a writable `/scratch` volume. |
| `monitoring.tf` | Alarms → SNS: dead jobs, repeated scan failures and unhandled API errors (from JSON log metric filters), 5xx responses, unhealthy targets, database CPU and storage. |
| `ci.tf` | GitHub OIDC provider and a deploy role that only the repository's `production` environment can assume. |

### Cost-conscious profile (the defaults)

- No NAT gateway: tasks run in public subnets with public IPs; security groups admit **no inbound**
  traffic except from the ALB. Data stores have no route to the internet.
- Single-AZ RDS (`db.t4g.micro`), one small Redis node, workers on Fargate Spot (jobs are
  idempotent and lease-based, so an interrupted job is re-run).
- Log retention 14 days. SSE-S3 rather than a customer-managed KMS key.

For production availability set `db_multi_az = true`, `worker_use_spot = false` and raise the
service counts. Moving tasks to private subnets with NAT or an egress proxy is not parameterised
yet.

### First deployment

1. Create an S3 bucket for Terraform state, then `cp backend.hcl.example backend.hcl` and
   `cp terraform.tfvars.example terraform.tfvars` and fill both in.
2. Request an ACM certificate for the domain in ca-central-1.
3. `terraform init -backend-config=backend.hcl`, then `terraform apply`. Services will not become
   healthy yet: there are no images and the secrets are empty.
4. Give every secret listed in the `secrets_to_populate` output a value
   (`aws secretsmanager put-secret-value`): the GitHub App private key, webhook secret and OAuth
   client secret, and the model API key if `ai_provider = "anthropic"`.
5. Set the repository variables listed at the top of `.github/workflows/deploy.yml` from the
   Terraform outputs, create the `production` environment with required reviewers, and run the
   Deploy workflow. It builds and pushes both images, runs migrations, then rolls out api, worker
   and web.
6. Point the domain's DNS at `load_balancer_dns_name`, and set the GitHub App's webhook URL to
   `https://<domain>/webhooks/github` and its callback URL to
   `https://<domain>/api/v1/auth/github/callback`.
7. Seed the demo: run the migrate task definition with the command overridden to
   `python -m sieve.demo.seed`.

### Releases

`Deploy` (on a published release, or manually) runs in the `production` environment, so it waits
for approval. It registers new task definition revisions with the commit's images, runs the
migration task and checks its exit code, then updates the services one at a time, waiting for each
to become stable. Terraform ignores the services' task definitions so a later `terraform apply`
does not roll a release back; `image_tag` only sets the first image.

Migrations must be backward-compatible with the version still running (expand/contract): the new
schema is applied while the old code serves traffic.

## CI

Every pull request and push to `main` runs:

| Job | What it checks |
|---|---|
| Backend | ruff, mypy `--strict`, unit and integration tests against PostgreSQL with real migrations, and that `web/openapi.json` matches the API |
| AI regression gate | The golden dataset against the committed heuristic baseline |
| Frontend | Generated API types are current, typecheck, lint, production build |
| Security | gitleaks, pip-audit, `npm audit` (production dependencies) |
| Infrastructure | `terraform fmt`, `terraform validate`, Trivy misconfiguration scan of Terraform and Dockerfiles |
| Container images | Both images build; Trivy image scan (critical and high, fixed-available) |

## Rollback

ECS keeps previous task definition revisions: roll back by updating the service to the previous
revision (`aws ecs update-service --task-definition <family>:<revision>`); the circuit breaker does
this automatically when a deployment fails health checks. Database migrations are forward-only;
destructive steps ship in a later release, after no running code uses the old schema.

## Not done

- Nothing has been applied to AWS; the Terraform is validated and scanned only.
- The ADOT collector image is not pinned to a digest.
- No WAF in front of the ALB; rate limits are enforced in the application.
- No network-level egress filtering; the destination allow-list lives in the application.
