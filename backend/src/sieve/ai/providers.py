"""Model providers behind one small interface, so the product is not coupled to a vendor.

* ``AnthropicProvider`` — Claude via the official SDK with JSON-schema structured outputs.
* ``HeuristicProvider`` — no model at all: proposes the functions the fix diff touches. It is the
  deterministic baseline every model is evaluated against.
* ``ScriptedProvider`` — returns fixed outputs; used by tests and for adversarial cases.

An OpenAI provider is not implemented; the interface is the extension point.
"""

import json
import re
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

import anthropic

from sieve.ai.diffs import module_for, touched
from sieve.core.errors import ExternalServiceError, SieveError

# USD per million tokens (input, output), Anthropic first-party rates as of 2026-09-25.
# Used only for cost *estimates*; update when prices change.
PRICES_PER_MTOK: dict[str, tuple[Decimal, Decimal]] = {
    "claude-opus-5-5": (Decimal(4), Decimal(20)),
    "claude-sonnet-5-5": (Decimal(2), Decimal(10)),
    "claude-haiku-4-5": (Decimal(1), Decimal(5)),
}


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    latency_ms: int


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> Completion: ...


class ProviderRefused(SieveError):
    code = "ai_refused"


class ProviderRejected(SieveError):
    code = "ai_request_rejected"


def estimate_cost(
    model: str, input_tokens: int | None, output_tokens: int | None
) -> Decimal | None:
    prices = PRICES_PER_MTOK.get(model)
    if prices is None or input_tokens is None or output_tokens is None:
        return None
    return (prices[0] * input_tokens + prices[1] * output_tokens) / Decimal(1_000_000)


class AnthropicProvider:
    name = "anthropic"

    def __init__(
        self, api_key: str, model: str = "claude-opus-5-5", *, fallbacks: bool = True
    ) -> None:
        self.model = model
        self.fallbacks = fallbacks
        self._client = anthropic.Anthropic(api_key=api_key, max_retries=2, timeout=120.0)

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> Completion:
        started = time.perf_counter()
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 16000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {
                "effort": "medium",
                "format": {"type": "json_schema", "schema": schema},
            },
        }
        try:
            if self.fallbacks:
                # Server-side fallback: a safety decline is retried on a fallback model in the
                # same call instead of failing the extraction.
                response: Any = self._client.beta.messages.create(
                    betas=["server-side-fallback-2026-07-01"], fallbacks="default", **request
                )
            else:
                response = self._client.messages.create(**request)
        except (
            anthropic.RateLimitError,
            anthropic.InternalServerError,
            anthropic.APIConnectionError,
        ) as exc:
            raise ExternalServiceError(f"Anthropic API unavailable: {type(exc).__name__}") from exc
        except anthropic.APIStatusError as exc:
            raise ProviderRejected(
                f"Anthropic API rejected the request: {exc.status_code}"
            ) from exc
        if response.stop_reason == "refusal":
            raise ProviderRefused("the model declined the request")
        text = next((block.text for block in response.content if block.type == "text"), "")
        return Completion(
            text=text,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            latency_ms=int((time.perf_counter() - started) * 1000),
        )


class ScriptedProvider:
    name = "scripted"

    def __init__(self, outputs: list[str], model: str = "scripted") -> None:
        self.model = model
        self._outputs = list(outputs)

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> Completion:
        return Completion(self._outputs.pop(0), self.model, None, None, 0)


_DIFF_BLOCK = re.compile(r"<fix_diff>\n?(.*?)\n?</fix_diff>", re.S)


class HeuristicProvider:
    """Baseline: every function the fix diff changes, named by its file's module."""

    name = "heuristic"
    model = "diff-heuristic-v1"

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> Completion:
        match = _DIFF_BLOCK.search(user)
        symbols = []
        if match:
            diff = match.group(1).replace("<\\/", "</")
            changes = touched(diff)
            for path, names in sorted(changes.by_file.items()):
                module = module_for(path)
                if module is None:
                    continue
                for name in sorted(names):
                    symbols.append(
                        {
                            "name": f"{module}.{name}",
                            "kind": "function",
                            "confidence": 0.5,
                            "evidence": f"changed in {path}",
                        }
                    )
        output = {"symbols": symbols[:10], "notes": "diff heuristic: functions touched by the fix"}
        return Completion(json.dumps(output), self.model, None, None, 0)
