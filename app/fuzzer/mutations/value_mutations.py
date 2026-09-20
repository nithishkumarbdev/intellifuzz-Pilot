"""
Generates deterministic mutated values for a single field, based on its
FieldSchema and (where useful) its original valid value. Dispatches by
`schema.type`, plus universal enum and null handling that apply
regardless of type.

Ordering within each function is fixed and documented — determinism
("same input -> same mutations in the same order") matters for
reproducibility, debugging, and testing, per the project's own rules.
Per-field truncation (MutationConfig.max_mutations_per_field) always
truncates from the END of each list, never by random sampling.

Known, documented limitation: FieldSchema (app/parser/models.py) is a
flat, practical JSON Schema subset — it has no `items` sub-schema for
arrays and no `properties` for nested objects (see Phase 1's own
docstring). So array mutations use generic placeholder elements rather
than type-correct ones, and object mutations only operate at the whole-
field level (null / empty / wrong type) rather than reaching into
sub-properties. Extending the parser to carry nested schemas is a real,
bounded piece of future work — not attempted here per the project's
"extend only where necessary" rule, since none of our own vulnerable-
api's fields currently need it beyond what's implemented.
"""

from __future__ import annotations

from typing import Any

from app.fuzzer.mutations.models import MutationConfig, MutationType
from app.parser.models import FieldSchema

SPECIAL_CHARACTERS_SAMPLE = "<>'\"&/\\;=$"


def _mutate_string(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    out: list[tuple[MutationType, Any]] = [
        (MutationType.EMPTY, ""),
        (MutationType.WHITESPACE, " "),
        (MutationType.LONG_STRING, "A" * config.long_string_length),
    ]

    if schema.max_length is not None:
        out.append((MutationType.BOUNDARY_LENGTH, "A" * (schema.max_length + 1)))
    if schema.min_length is not None and schema.min_length > 0:
        out.append((MutationType.BOUNDARY_LENGTH, "A" * (schema.min_length - 1)))

    out.append((MutationType.SPECIAL_CHARACTERS, SPECIAL_CHARACTERS_SAMPLE))
    out.append((MutationType.TYPE_CONFUSION, 12345))
    return out


def _mutate_integer(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    out: list[tuple[MutationType, Any]] = [
        (MutationType.ZERO, 0),
        (MutationType.NEGATIVE, -1),
    ]

    if schema.minimum is not None:
        minimum = int(schema.minimum)
        out.append((MutationType.BELOW_MINIMUM, minimum - 1))
        out.append((MutationType.BOUNDARY_NUMBER, minimum))
    if schema.maximum is not None:
        maximum = int(schema.maximum)
        out.append((MutationType.BOUNDARY_NUMBER, maximum))
        out.append((MutationType.ABOVE_MAXIMUM, maximum + 1))
    if schema.minimum is None and schema.maximum is None:
        # No declared bounds — still worth an oversized value, capped so
        # it won't destabilize a local test target.
        out.append((MutationType.BOUNDARY_NUMBER, 999_999_999))

    out.append((MutationType.TYPE_CONFUSION, str(original) if original is not None else "999"))
    return out


def _mutate_number(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    out: list[tuple[MutationType, Any]] = [
        (MutationType.ZERO, 0.0),
        (MutationType.NEGATIVE, -1.0),
    ]

    if schema.minimum is not None:
        out.append((MutationType.BELOW_MINIMUM, schema.minimum - 1))
        out.append((MutationType.BOUNDARY_NUMBER, schema.minimum))
    if schema.maximum is not None:
        out.append((MutationType.BOUNDARY_NUMBER, schema.maximum))
        out.append((MutationType.ABOVE_MAXIMUM, schema.maximum + 1))
    if schema.minimum is None and schema.maximum is None:
        out.append((MutationType.BOUNDARY_NUMBER, 999_999_999.0))

    out.append((MutationType.TYPE_CONFUSION, str(original) if original is not None else "999.0"))
    return out


def _mutate_boolean(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    opposite = not bool(original) if isinstance(original, bool) else False
    return [
        (MutationType.BOOLEAN_FLIP, opposite),
        (MutationType.TYPE_CONFUSION, "true" if opposite else "false"),
        (MutationType.TYPE_CONFUSION, 1 if opposite else 0),
    ]


def _mutate_array(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    # No `items` sub-schema available (see module docstring) — elements
    # are generic placeholders, not type-correct for whatever the array
    # actually holds.
    return [
        (MutationType.EMPTY_ARRAY, []),
        (MutationType.ARRAY_BOUNDARY, ["fuzz-item"]),
        (MutationType.ARRAY_BOUNDARY, ["fuzz-item-1", "fuzz-item-2", "fuzz-item-3"]),
        (MutationType.TYPE_CONFUSION, "not-an-array"),
    ]


def _mutate_object(schema: FieldSchema, original: Any, config: MutationConfig) -> list[tuple[MutationType, Any]]:
    # Shallow only — see module docstring: no nested `properties` to
    # mutate individually, so this operates on the field as a whole.
    return [
        (MutationType.OBJECT_EMPTY, {}),
        (MutationType.TYPE_CONFUSION, "not-an-object"),
    ]


_TYPE_MUTATORS = {
    "string": _mutate_string,
    "integer": _mutate_integer,
    "number": _mutate_number,
    "boolean": _mutate_boolean,
    "array": _mutate_array,
    "object": _mutate_object,
}


def _mutate_enum(schema: FieldSchema) -> list[tuple[MutationType, Any]]:
    out: list[tuple[MutationType, Any]] = []
    if schema.enum and len(schema.enum) > 1:
        out.append((MutationType.VALID_ENUM_ALTERNATE, schema.enum[1]))
    out.append((MutationType.INVALID_ENUM, "__invalid_enum_value__"))
    return out


def generate_value_mutations(
    schema: FieldSchema, original_value: Any, config: MutationConfig
) -> list[tuple[MutationType, Any]]:
    """
    Deterministic mutation order:
      1. type-specific mutations (dispatched on schema.type)
      2. enum mutations, if schema.enum is set (applies regardless of
         declared type — enums are commonly typed as "string" but the
         mutation strategy that matters is enum-specific, not generic
         string fuzzing)
      3. a universal null mutation, unless a prior step already
         produced None (avoids a duplicate test case)
    Truncated to config.max_mutations_per_field from the end — never
    randomly sampled, so the same input always yields the same subset.
    """
    mutations: list[tuple[MutationType, Any]] = []

    mutator = _TYPE_MUTATORS.get(schema.type)
    if mutator is not None:
        mutations.extend(mutator(schema, original_value, config))

    if schema.enum:
        mutations.extend(_mutate_enum(schema))

    if not any(value is None for _, value in mutations):
        mutations.append((MutationType.NULL, None))

    return mutations[: config.max_mutations_per_field]
