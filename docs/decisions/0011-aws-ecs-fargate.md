# ADR-0011: AWS ECS Fargate in ca-central-1

- Status: Accepted
- Date: 2026-10-06

## Problem

Run three container types (web, api, worker) with managed Postgres, Redis and object storage,
reproducibly via Terraform, at a cost a single engineer can sustain.

## Alternatives

- **EKS (Kubernetes)** — powerful, but a control plane cost and operational surface that three
  services don't need (spec §59).
- **EC2 + docker compose** — cheap, but patching, scaling and deploys are manual.
- **App Runner** — simpler, but less control over networking and no worker-style long-running tasks
  without HTTP.
- **Lambda** — scans can exceed time limits and need larger temp storage; cold starts on the API.
- **ECS Fargate** — chosen.

## Decision

ECS Fargate services for `web`, `api`, `worker`; RDS PostgreSQL; ElastiCache Redis; S3; Secrets
Manager; ALB with ACM. Region `ca-central-1` as the initial deployment region (specified by the
project owner; it is also the natural region for Canadian data-residency expectations).

## Trade-offs

Fargate costs more per vCPU than EC2; worth it for zero node management. ALB has a fixed monthly cost.

## 10× scale

Service auto-scaling on CPU (api) and queue depth (worker, via a custom CloudWatch metric).

## Enterprise

Multi-account (separate prod/staging accounts via Organizations), private subnets with egress
control, WAF on the ALB, possibly EKS if the organisation standardises on it.
