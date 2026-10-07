"""OpenTelemetry setup and Sieve's own metrics (ADR-0012).

Instrumentation is vendor-neutral: metrics are exposed in Prometheus format (``/metrics`` on the
API, an optional port on the worker); traces and metrics are also pushed to an OTLP endpoint when
one is configured. The instruments below are created against the global meter, which proxies to
the real provider once ``configure_telemetry`` has run, so importing this module never has side
effects.
"""

from importlib.metadata import version

from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import MetricReader, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import start_http_server
from sqlalchemy import Engine

from sieve.core.config import Settings

_meter = metrics.get_meter("sieve")
tracer = trace.get_tracer("sieve")

JOBS = _meter.create_counter(
    "sieve.jobs", unit="{job}", description="Jobs processed, by kind and outcome."
)
JOB_DURATION = _meter.create_histogram(
    "sieve.job.duration", unit="s", description="Job handler run time."
)
SCANS = _meter.create_counter(
    "sieve.scans", unit="{scan}", description="Scan outcomes, by status and error code."
)
SCAN_STAGE_DURATION = _meter.create_histogram(
    "sieve.scan.stage.duration", unit="s", description="Run time of each scan pipeline stage."
)
VERDICTS = _meter.create_counter(
    "sieve.findings.verdicts", unit="{finding}", description="Verdicts produced by completed scans."
)
AI_COST = _meter.create_counter(
    "sieve.ai.cost", unit="USD", description="Estimated spend on model calls for symbol extraction."
)

# Probes and the metrics endpoint would dominate request traces without telling anyone anything.
_UNTRACED = "healthz,readyz,metrics"

_configured = False


def configure_telemetry(settings: Settings, service: str) -> None:
    """Install the global meter and tracer providers. Idempotent: the API factory runs once per
    test, and OpenTelemetry providers can only be set once per process."""
    global _configured
    if _configured:
        return
    _configured = True
    resource = Resource.create(
        {
            "service.name": service,
            "service.version": version("sieve"),
            "deployment.environment": settings.environment,
        }
    )
    otlp = settings.otel_exporter_otlp_endpoint
    readers: list[MetricReader] = [PrometheusMetricReader()]
    if otlp:
        # In AWS the ADOT collector sidecar receives OTLP and forwards to CloudWatch and X-Ray.
        readers.append(
            PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{otlp.rstrip('/')}/v1/metrics")
            )
        )
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=readers))
    provider = TracerProvider(resource=resource)
    if otlp:
        endpoint = f"{otlp.rstrip('/')}/v1/traces"
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    HTTPXClientInstrumentor().instrument()


def instrument_engine(engine: Engine) -> None:
    SQLAlchemyInstrumentor().instrument(engine=engine)


def instrument_app(app: FastAPI) -> None:
    FastAPIInstrumentor.instrument_app(app, excluded_urls=_UNTRACED)


def serve_worker_metrics(settings: Settings) -> None:
    if settings.worker_metrics_port is not None:
        start_http_server(settings.worker_metrics_port, addr="0.0.0.0")  # noqa: S104 - container port
