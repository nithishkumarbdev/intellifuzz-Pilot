"""
Generates a plausible, deterministic *valid* value for a given
FieldSchema. This is the "happy path" — the value a well-behaved
client would send. It is deliberately NOT random and NOT adversarial;
that's what the mutation engine (Phase 4) does, starting from what
this module produces.

Preference order, most to least specific:
  1. an explicit `example` in the schema
  2. a `default` in the schema
  3. the first `enum` value
  4. a sensible type-based value, respecting min/max/length constraints
"""

from __future__ import annotations

from typing import Any

from app.parser.models import FieldSchema

_STRING_FORMAT_SAMPLES = {
    "email": "test.user@example.com",
    "date": "2024-01-15",
    "date-time": "2024-01-15T10:00:00Z",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "uri": "https://example.com/resource",
    "hostname": "example.com",
    "ipv4": "127.0.0.1",
}


def _generate_string(schema: FieldSchema) -> str:
    if schema.format and schema.format in _STRING_FORMAT_SAMPLES:
        value = _STRING_FORMAT_SAMPLES[schema.format]
    else:
        value = "teststring"

    if schema.max_length is not None and len(value) > schema.max_length:
        value = value[: schema.max_length]
    if schema.min_length is not None and len(value) < schema.min_length:
        value = value.ljust(schema.min_length, "x")
    return value


def _generate_integer(schema: FieldSchema) -> int:
    value = 1
    if schema.minimum is not None:
        value = max(value, int(schema.minimum))
    if schema.maximum is not None:
        value = min(value, int(schema.maximum))
    return value


def _generate_number(schema: FieldSchema) -> float:
    value = 1.0
    if schema.minimum is not None:
        value = max(value, float(schema.minimum))
    if schema.maximum is not None:
        value = min(value, float(schema.maximum))
    return value


def generate_valid_value(schema: FieldSchema) -> Any:
    if schema.example is not None:
        return schema.example
    if schema.default is not None:
        return schema.default
    if schema.enum:
        return schema.enum[0]

    generators = {
        "string": _generate_string,
        "integer": _generate_integer,
        "number": _generate_number,
        "boolean": lambda s: True,
        "array": lambda s: [],
        "object": lambda s: {},
    }
    generator = generators.get(schema.type)
    if generator is not None:
        return generator(schema)

    # Unknown/unspecified type (e.g. a schema we couldn't fully resolve) —
    # fall back to a generic, clearly-fake string rather than guessing.
    return "test-value"
