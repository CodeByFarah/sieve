# ADR-0012: OpenTelemetry + structured logs, one backend per environment

- Status: Accepted
- Date: 2026-10-06

## Problem

Debugging a scan means following one request across webhook → job → worker stages → GitHub API.
The spec lists OpenTelemetry, Prometheus, Grafana, CloudWatch and an error tracker — more systems
than one engineer can operate well.

## Decision

- **Instrument once** with OpenTelemetry (FastAPI, SQLAlchemy, httpx auto-instrumentation + custom
  spans per scan stage) and the OTel metrics API.
- **Logs**: JSON lines to stdout via `structlog`, every line carrying `correlation_id`,
  `organization_id` (when known), `job_id`/`scan_id`. Secrets are redacted by a processor.
- **Local**: Prometheus-format `/metrics`; traces to console or optional Jaeger container.
- **AWS**: stdout → CloudWatch Logs; OTLP → ADOT collector sidecar → CloudWatch metrics + X-Ray.
  Alarms on error rate, dead-job count, scan failure rate, ingestion staleness.
- No separate error-tracking SaaS initially; error events are logs with stack traces and correlation
  ids, alarmed via CloudWatch metric filters.

## Trade-offs

CloudWatch dashboards are less pleasant than Grafana. Because instrumentation is vendor-neutral OTel,
switching to Grafana Cloud/Honeycomb is a collector configuration change.

## 10× scale / Enterprise

Sampling for traces; the organisation's standard observability backend via the same collector.
