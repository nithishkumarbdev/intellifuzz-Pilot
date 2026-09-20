"""
Data models for the mutation engine: what kind of mutation was applied,
where, and the resulting mutated TestCase — plus MutationConfig, which
bounds how much fuzzing a single run can generate.

Nothing here judges whether a mutation's *result* is interesting or
dangerous. This module (and the mutation engine built on it) only ever
answers "what test cases should we try", never "what do the responses
mean" — that's Phase 7+ (anomaly detection) and Phase 8 (security
rules), deliberately kept out of this phase entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.runner.models import TestCase


class MutationType(str, Enum):
    # string
    EMPTY = "empty"
    WHITESPACE = "whitespace"
    LONG_STRING = "long_string"
    BOUNDARY_LENGTH = "boundary_length"
    SPECIAL_CHARACTERS = "special_characters"
    # shared
    TYPE_CONFUSION = "type_confusion"
    NULL = "null"
    # numeric
    ZERO = "zero"
    NEGATIVE = "negative"
    BELOW_MINIMUM = "below_minimum"
    ABOVE_MAXIMUM = "above_maximum"
    BOUNDARY_NUMBER = "boundary_number"
    # boolean
    BOOLEAN_FLIP = "boolean_flip"
    # structural
    MISSING_FIELD = "missing_field"
    UNEXPECTED_FIELD = "unexpected_field"
    # enum
    VALID_ENUM_ALTERNATE = "valid_enum_alternate"
    INVALID_ENUM = "invalid_enum"
    # array / object
    EMPTY_ARRAY = "empty_array"
    ARRAY_BOUNDARY = "array_boundary"
    OBJECT_EMPTY = "object_empty"


class Mutation(BaseModel):
    """Metadata describing one mutation — what changed and where.
    Independent of HTTP concerns; this is the evidence trail later
    phases (anomaly detection, reporting) will key off of."""

    mutation_type: MutationType
    location: str  # e.g. "body.age", "path.user_id", "query.limit"
    field_name: Optional[str] = None
    original_value: Optional[Any] = None
    mutated_value: Optional[Any] = None


@dataclass
class MutatedTestCase:
    """One mutated TestCase, tied back to the baseline it was derived from."""

    baseline_key: str  # f"{method} {path}" — matches BaselineStore's key shape
    mutation: Mutation
    test_case: TestCase


class MutationConfig(BaseModel):
    """Bounds on mutation generation. Defaults are conservative on
    purpose — this is a local security-testing tool, not a load
    generator, and several endpoints in our own test target are
    state-changing."""

    max_mutations_per_field: int = 8
    max_mutations_per_endpoint: int = 40
    max_total_mutations: int = 500
    long_string_length: int = 500

    # Endpoints whose method is in this set are skipped entirely during
    # a fuzzing pass — e.g. {"DELETE"} to avoid repeatedly deleting
    # state while iterating. Empty by default (nothing skipped).
    skip_methods: set[str] = Field(default_factory=set)
