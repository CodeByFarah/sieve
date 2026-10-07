"""Vendored official JSON schemas and validators.

* CycloneDX 1.6 (``bom-1.6.schema.json`` + its ``spdx`` and ``jsf`` dependencies), Apache-2.0,
  from https://github.com/CycloneDX/specification
* OpenVEX 0.2.0 (``openvex-0.2.0.schema.json``), Apache-2.0, from https://github.com/openvex/spec

Vendored rather than fetched so validation never depends on network access.
"""

import json
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft7Validator, Draft202012Validator
from jsonschema.protocols import Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

MAX_REPORTED_ERRORS = 20


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(files(__package__).joinpath(name).read_text("utf-8"))
    return data


@cache
def _cyclonedx_validator() -> Validator:
    resources = []
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        schema = _load(name)
        resources.append(
            (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7))
        )
    registry: Registry[Any] = Registry().with_resources(resources)
    return Draft7Validator(_load("bom-1.6.schema.json"), registry=registry)


@cache
def _openvex_validator() -> Validator:
    return Draft202012Validator(_load("openvex-0.2.0.schema.json"))


def _errors(validator: Validator, document: Any) -> list[str]:
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in errors[:MAX_REPORTED_ERRORS]
    ]


def cyclonedx_errors(document: Any) -> list[str]:
    """Schema violations of a CycloneDX 1.6 JSON document (empty when valid)."""
    return _errors(_cyclonedx_validator(), document)


def openvex_errors(document: Any) -> list[str]:
    """Schema violations of an OpenVEX 0.2.0 document (empty when valid)."""
    return _errors(_openvex_validator(), document)
