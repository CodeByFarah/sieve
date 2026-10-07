"""The extraction service: cache → budget check → model → schema → verification → registry.

Extraction is keyed per advisory and package, not per repository, so one call serves every
repository using that package. Every call is recorded in ``ai_extractions`` (model, tokens,
estimated cost, latency, outcome); successful calls are the cache.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from sieve.advisories.osv import fix_commits
from sieve.ai.diffs import fetch_commit_diff, touched
from sieve.ai.guardrails import (
    OUTPUT_SCHEMA,
    PROMPT_VERSION,
    SchemaInvalid,
    build_user_message,
    input_digest,
    parse_output,
    system_prompt,
)
from sieve.ai.providers import Provider, ProviderRefused, estimate_cost
from sieve.ai.verification import load_package, verify
from sieve.analysis.engine import SourceProvider
from sieve.analysis.sandbox import Indexer
from sieve.core.errors import SieveError
from sieve.core.telemetry import AI_COST
from sieve.db.enums import AIExtractionStatus, SymbolKind, SymbolOrigin, SymbolVerification
from sieve.db.models import Advisory, AIExtraction, Package, VulnerableSymbol


class AIBudgetExhausted(SieveError):
    code = "ai_budget_exhausted"


@dataclass
class ExtractionService:
    provider: Provider
    sources: SourceProvider
    indexer: Indexer
    http: httpx.Client
    daily_budget_usd: Decimal

    def spent_today(self, session: Session) -> Decimal:
        since = datetime.now(UTC) - timedelta(days=1)
        total = session.scalar(
            select(func.coalesce(func.sum(AIExtraction.cost_usd), 0)).where(
                AIExtraction.created_at >= since
            )
        )
        return Decimal(total or 0)

    def extract(
        self, session: Session, advisory_id: uuid.UUID, package_id: uuid.UUID, version: str | None
    ) -> AIExtraction:
        advisory = session.get(Advisory, advisory_id)
        package = session.get(Package, package_id)
        assert advisory is not None and package is not None  # noqa: S101
        diff = None
        for commit in fix_commits(advisory.references)[:1]:
            diff = fetch_commit_diff(self.http, commit)
        user = build_user_message(
            advisory_id=advisory.source_id,
            summary=advisory.summary,
            details=advisory.details,
            package=package.name,
            version=version,
            references=[r["url"] for r in advisory.references],
            diff=diff,
        )
        digest = input_digest(user)
        cached = session.scalar(
            select(AIExtraction).where(
                AIExtraction.input_sha256 == digest,
                AIExtraction.provider == self.provider.name,
                AIExtraction.model == self.provider.model,
                AIExtraction.prompt_version == PROMPT_VERSION,
                AIExtraction.status == AIExtractionStatus.SUCCEEDED,
            )
        )
        if cached is not None:
            return cached
        if self.spent_today(session) >= self.daily_budget_usd:
            raise AIBudgetExhausted(f"daily AI budget of ${self.daily_budget_usd} reached")

        record = AIExtraction(
            advisory_id=advisory.id,
            package_id=package.id,
            provider=self.provider.name,
            model=self.provider.model,
            prompt_version=PROMPT_VERSION,
            input_sha256=digest,
            status=AIExtractionStatus.PROVIDER_ERROR,
        )
        session.add(record)
        try:
            completion = self.provider.complete(system_prompt(), user, OUTPUT_SCHEMA)
        except ProviderRefused as exc:
            record.status, record.error = AIExtractionStatus.REFUSED, str(exc)
            session.flush()
            return record
        except SieveError as exc:
            record.error = f"{exc.code}: {exc.message}"
            session.flush()
            raise
        record.model = completion.model
        record.input_tokens, record.output_tokens = (
            completion.input_tokens,
            completion.output_tokens,
        )
        record.cost_usd = estimate_cost(
            completion.model, completion.input_tokens, completion.output_tokens
        )
        record.latency_ms = completion.latency_ms
        AI_COST.add(float(record.cost_usd or 0), {"model": completion.model})
        try:
            output = parse_output(completion.text)
        except SchemaInvalid as exc:
            record.status, record.error = AIExtractionStatus.SCHEMA_INVALID, exc.message
            session.flush()
            return record

        verified = []
        if version is not None:
            source = load_package(self.sources, self.indexer, package.name, version)
            verified = verify(source, output.symbols, touched(diff) if diff else None)
        record.status = AIExtractionStatus.SUCCEEDED
        record.output = {
            "symbols": [c.model_dump() for c in output.symbols],
            "notes": output.notes,
            "verification": [v.__dict__ for v in verified],
            "fix_diff_used": diff is not None,
        }
        session.flush()
        for result in verified:
            name = result.canonical or result.name
            session.execute(
                insert(VulnerableSymbol)
                .values(
                    id=uuid.uuid4(),
                    advisory_id=advisory.id,
                    package_id=package.id,
                    qualified_name=name,
                    kind=SymbolKind(result.kind or result.claimed_kind),
                    origin=SymbolOrigin.AI,
                    ai_extraction_id=record.id,
                    verification=SymbolVerification.VERIFIED
                    if result.accepted
                    else SymbolVerification.REJECTED,
                    verification_detail={
                        "reason": result.reason,
                        "version": version,
                        "file": result.file,
                        "line": result.line,
                        "diff_match": result.diff_match,
                    },
                )
                .on_conflict_do_nothing()
            )
        return record
