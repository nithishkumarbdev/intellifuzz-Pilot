"""Tests for app.fuzzer.mutations.value_mutations."""

from __future__ import annotations

from app.fuzzer.mutations.models import MutationConfig, MutationType
from app.fuzzer.mutations.value_mutations import generate_value_mutations
from app.parser.models import FieldSchema

CONFIG = MutationConfig()


def _types(mutations):
    return [t for t, _ in mutations]


def _values(mutations):
    return [v for _, v in mutations]


# ---------------------------------------------------------------------------
# String
# ---------------------------------------------------------------------------


def test_string_includes_empty_and_whitespace():
    mutations = generate_value_mutations(FieldSchema(type="string"), "hello", CONFIG)
    assert (MutationType.EMPTY, "") in mutations
    assert (MutationType.WHITESPACE, " ") in mutations


def test_string_long_string_respects_configured_length():
    config = MutationConfig(long_string_length=50)
    mutations = generate_value_mutations(FieldSchema(type="string"), "hello", config)
    long_value = next(v for t, v in mutations if t == MutationType.LONG_STRING)
    assert len(long_value) == 50


def test_string_boundary_length_uses_schema_max_length():
    schema = FieldSchema(type="string", max_length=5)
    mutations = generate_value_mutations(schema, "hello", CONFIG)
    boundary_values = [v for t, v in mutations if t == MutationType.BOUNDARY_LENGTH]
    assert any(len(v) == 6 for v in boundary_values)  # max_length + 1


def test_string_special_characters_present():
    mutations = generate_value_mutations(FieldSchema(type="string"), "hello", CONFIG)
    special = next(v for t, v in mutations if t == MutationType.SPECIAL_CHARACTERS)
    assert "<" in special and "'" in special


def test_string_includes_universal_null():
    mutations = generate_value_mutations(FieldSchema(type="string"), "hello", CONFIG)
    assert (MutationType.NULL, None) in mutations


# ---------------------------------------------------------------------------
# Integer
# ---------------------------------------------------------------------------


def test_integer_includes_zero_and_negative():
    mutations = generate_value_mutations(FieldSchema(type="integer"), 25, CONFIG)
    assert (MutationType.ZERO, 0) in mutations
    assert (MutationType.NEGATIVE, -1) in mutations


def test_integer_boundary_uses_minimum_and_maximum():
    schema = FieldSchema(type="integer", minimum=0, maximum=120)
    mutations = generate_value_mutations(schema, 25, CONFIG)
    values = _values(mutations)
    assert -1 in values  # minimum - 1
    assert 121 in values  # maximum + 1
    assert 0 in values
    assert 120 in values


def test_integer_type_confusion_stringifies_original():
    mutations = generate_value_mutations(FieldSchema(type="integer"), 25, CONFIG)
    assert (MutationType.TYPE_CONFUSION, "25") in mutations


def test_integer_without_bounds_still_includes_large_value():
    mutations = generate_value_mutations(FieldSchema(type="integer"), 5, CONFIG)
    assert (MutationType.BOUNDARY_NUMBER, 999_999_999) in mutations


# ---------------------------------------------------------------------------
# Number (float)
# ---------------------------------------------------------------------------


def test_number_boundary_uses_minimum_and_maximum():
    schema = FieldSchema(type="number", minimum=0.0, maximum=100.0)
    mutations = generate_value_mutations(schema, 50.0, CONFIG)
    values = _values(mutations)
    assert -1.0 in values
    assert 101.0 in values


# ---------------------------------------------------------------------------
# Boolean
# ---------------------------------------------------------------------------


def test_boolean_flip_true_to_false():
    mutations = generate_value_mutations(FieldSchema(type="boolean"), True, CONFIG)
    assert (MutationType.BOOLEAN_FLIP, False) in mutations


def test_boolean_flip_false_to_true():
    mutations = generate_value_mutations(FieldSchema(type="boolean"), False, CONFIG)
    assert (MutationType.BOOLEAN_FLIP, True) in mutations


def test_boolean_type_confusion_variants():
    mutations = generate_value_mutations(FieldSchema(type="boolean"), True, CONFIG)
    assert (MutationType.TYPE_CONFUSION, "false") in mutations
    assert (MutationType.TYPE_CONFUSION, 0) in mutations


def test_boolean_includes_universal_null():
    mutations = generate_value_mutations(FieldSchema(type="boolean"), True, CONFIG)
    assert (MutationType.NULL, None) in mutations
    # Null must appear exactly once even though it's a "shared" mutation.
    assert _values(mutations).count(None) == 1


# ---------------------------------------------------------------------------
# Array / Object (shallow, per documented limitation)
# ---------------------------------------------------------------------------


def test_array_includes_empty_and_boundary_sizes():
    mutations = generate_value_mutations(FieldSchema(type="array"), [], CONFIG)
    assert (MutationType.EMPTY_ARRAY, []) in mutations
    assert any(t == MutationType.ARRAY_BOUNDARY and len(v) == 1 for t, v in mutations)
    assert any(t == MutationType.ARRAY_BOUNDARY and len(v) == 3 for t, v in mutations)


def test_object_includes_empty_and_type_confusion():
    mutations = generate_value_mutations(FieldSchema(type="object"), {}, CONFIG)
    assert (MutationType.OBJECT_EMPTY, {}) in mutations
    assert any(t == MutationType.TYPE_CONFUSION for t, _ in mutations)


# ---------------------------------------------------------------------------
# Enum
# ---------------------------------------------------------------------------


def test_enum_alternate_and_invalid_value():
    schema = FieldSchema(type="string", enum=["active", "inactive", "pending"])
    mutations = generate_value_mutations(schema, "active", CONFIG)
    assert (MutationType.VALID_ENUM_ALTERNATE, "inactive") in mutations
    assert (MutationType.INVALID_ENUM, "__invalid_enum_value__") in mutations


def test_enum_with_single_value_skips_alternate():
    schema = FieldSchema(type="string", enum=["only-option"])
    mutations = generate_value_mutations(schema, "only-option", CONFIG)
    assert not any(t == MutationType.VALID_ENUM_ALTERNATE for t, _ in mutations)
    assert (MutationType.INVALID_ENUM, "__invalid_enum_value__") in mutations


# ---------------------------------------------------------------------------
# Limits and determinism
# ---------------------------------------------------------------------------


def test_per_field_limit_is_respected():
    config = MutationConfig(max_mutations_per_field=3)
    schema = FieldSchema(type="integer", minimum=0, maximum=100)
    mutations = generate_value_mutations(schema, 50, config)
    assert len(mutations) == 3


def test_generation_is_deterministic():
    schema = FieldSchema(type="string", min_length=2, max_length=10)
    first = generate_value_mutations(schema, "hello", CONFIG)
    second = generate_value_mutations(schema, "hello", CONFIG)
    assert first == second


def test_unknown_type_produces_only_universal_null():
    mutations = generate_value_mutations(FieldSchema(type=None), "whatever", CONFIG)
    assert mutations == [(MutationType.NULL, None)]
