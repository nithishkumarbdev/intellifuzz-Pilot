"""Tests for app.fuzzer.valid_values."""

from __future__ import annotations

from app.fuzzer.valid_values import generate_valid_value
from app.parser.models import FieldSchema


def test_example_takes_priority_over_everything():
    schema = FieldSchema(type="string", example="from-example", default="from-default", enum=["a", "b"])
    assert generate_valid_value(schema) == "from-example"


def test_default_takes_priority_over_enum_and_type():
    schema = FieldSchema(type="string", default="from-default", enum=["a", "b"])
    assert generate_valid_value(schema) == "from-default"


def test_enum_first_value_used_when_no_example_or_default():
    schema = FieldSchema(type="string", enum=["red", "green", "blue"])
    assert generate_valid_value(schema) == "red"


def test_plain_string():
    assert generate_valid_value(FieldSchema(type="string")) == "teststring"


def test_string_respects_max_length():
    schema = FieldSchema(type="string", max_length=4)
    value = generate_valid_value(schema)
    assert len(value) <= 4


def test_string_respects_min_length():
    schema = FieldSchema(type="string", min_length=20)
    value = generate_valid_value(schema)
    assert len(value) >= 20


def test_string_email_format():
    schema = FieldSchema(type="string", format="email")
    assert "@" in generate_valid_value(schema)


def test_integer_default():
    assert generate_valid_value(FieldSchema(type="integer")) == 1


def test_integer_respects_minimum_above_default():
    schema = FieldSchema(type="integer", minimum=50)
    assert generate_valid_value(schema) == 50


def test_integer_respects_maximum_below_default():
    schema = FieldSchema(type="integer", maximum=0)
    assert generate_valid_value(schema) == 0


def test_number_respects_bounds():
    schema = FieldSchema(type="number", minimum=2.5, maximum=10)
    assert generate_valid_value(schema) == 2.5


def test_boolean():
    assert generate_valid_value(FieldSchema(type="boolean")) is True


def test_array_default_empty():
    assert generate_valid_value(FieldSchema(type="array")) == []


def test_object_default_empty():
    assert generate_valid_value(FieldSchema(type="object")) == {}


def test_unknown_type_falls_back_to_placeholder_string():
    """A schema we couldn't fully resolve (type=None) should still
    produce *something* usable, not crash or return None."""
    assert generate_valid_value(FieldSchema(type=None)) == "test-value"
