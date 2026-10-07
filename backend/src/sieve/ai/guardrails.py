"""Input fencing and output validation for symbol extraction.

The model's input is public advisory data, never customer code. Untrusted text is placed inside
tagged blocks with closing tags neutralised, and capped in size. The output must match a strict
schema; anything else is rejected whole (recorded as ``schema_invalid``), never partially used.
"""

import hashlib
from importlib.resources import files
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sieve.core.errors import SieveError

PROMPT_VERSION = "symbol-extraction/v1"
MAX_DETAILS = 8_000
MAX_DIFF = 30_000
MAX_SYMBOLS = 10
SYMBOL_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,12}$"

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "symbols": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "kind": {"type": "string", "enum": ["function", "method", "class", "module"]},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                },
                "required": ["name", "kind", "confidence", "evidence"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "string"},
    },
    "required": ["symbols", "notes"],
    "additionalProperties": False,
}


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=SYMBOL_PATTERN, max_length=200)
    kind: Literal["function", "method", "class", "module"]
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(max_length=2000)


class ExtractionOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    symbols: list[Candidate] = Field(max_length=MAX_SYMBOLS)
    notes: str = Field(default="", max_length=4000)


class SchemaInvalid(SieveError):
    code = "ai_schema_invalid"


def system_prompt() -> str:
    return files(__package__).joinpath("prompts/symbol_extraction_v1.md").read_text("utf-8")


def _fence(tag: str, text: str, limit: int) -> str:
    safe = text[:limit].replace("</", "<\\/")
    return f"<{tag}>\n{safe}\n</{tag}>"


def build_user_message(
    *,
    advisory_id: str,
    summary: str | None,
    details: str | None,
    package: str,
    version: str | None,
    references: list[str],
    diff: str | None,
) -> str:
    parts = [
        f"Package: {package}" + (f" (vulnerable version {version})" if version else ""),
        _fence("advisory", f"{advisory_id}\n{summary or ''}\n\n{details or ''}", MAX_DETAILS),
        _fence("references", "\n".join(references[:20]), 4_000),
        _fence("fix_diff", diff, MAX_DIFF) if diff else "No fix diff is available.",
        "Return the candidate vulnerable symbols.",
    ]
    return "\n\n".join(parts)


def input_digest(user_message: str) -> bytes:
    return hashlib.sha256(f"{PROMPT_VERSION}\n{user_message}".encode()).digest()


def parse_output(text: str) -> ExtractionOutput:
    try:
        return ExtractionOutput.model_validate_json(text)
    except ValidationError as exc:
        raise SchemaInvalid(f"model output failed validation: {exc.error_count()} errors") from exc
