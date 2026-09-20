"""
Tests for app.fuzzer.mutations.engine, using real Endpoints parsed from
the vulnerable-api spec and real baseline TestCases built by Phase 3's
test_case_builder — the same reality-grounding approach used throughout
this test suite.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.mutations.engine import generate_mutations_for_test_case
from app.fuzzer.mutations.models import MutationConfig, MutationType
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.parser.openapi_parser import parse_openapi_spec
from app.runner.validation import validate_test_case

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"

SETTINGS = RunnerSettings(
    base_url="http://test", auth_header_name="x-api-token", auth_header_value="alice-token"
)


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _endpoint(spec, path, method):
    return next(e for e in spec.endpoints if e.path == path and e.method == method)


def _baseline_case(spec, path, method):
    endpoint = _endpoint(spec, path, method)
    return endpoint, build_baseline_test_case(endpoint, SETTINGS)


# ---------------------------------------------------------------------------
# Path parameters
# ---------------------------------------------------------------------------


def test_path_parameter_is_mutated(spec):
    endpoint, baseline = _baseline_case(spec, "/users/{user_id}", "GET")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    path_mutations = [m for m in mutations if m.mutation.location == "path.user_id"]
    assert len(path_mutations) > 0
    # user_id is an integer path param — should include a negative mutation.
    assert any(m.mutation.mutation_type == MutationType.NEGATIVE for m in path_mutations)


def test_path_mutation_produces_valid_test_case(spec):
    """Every mutated TestCase must still pass validation — mutating a
    VALUE must never produce a structurally invalid request (e.g. a
    missing path param)."""
    endpoint, baseline = _baseline_case(spec, "/users/{user_id}", "GET")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    for mutated in mutations:
        validate_test_case(mutated.test_case)  # raises if invalid


# ---------------------------------------------------------------------------
# Body fields — required (present in baseline)
# ---------------------------------------------------------------------------


def test_required_body_field_is_mutated(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    age_mutations = [m for m in mutations if m.mutation.location == "body.age"]
    assert len(age_mutations) > 0
    assert any(m.mutation.mutation_type == MutationType.NEGATIVE for m in age_mutations)


def test_required_body_field_gets_missing_field_mutation(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    missing = [m for m in mutations if m.mutation.mutation_type == MutationType.MISSING_FIELD]
    missing_locations = {m.mutation.location for m in missing}
    assert "body.username" in missing_locations
    assert "body.email" in missing_locations
    assert "body.age" in missing_locations
    # Each missing-field mutation should actually have removed that key.
    age_missing = next(m for m in missing if m.mutation.location == "body.age")
    assert "age" not in age_missing.test_case.body


def test_unexpected_field_mutation_present(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    unexpected = [m for m in mutations if m.mutation.mutation_type == MutationType.UNEXPECTED_FIELD]
    assert len(unexpected) == 1
    assert unexpected[0].test_case.body["unexpected_fuzz_field"] == "fuzz"
    # Original fields must still be present — only ADDING a field, not
    # replacing the body.
    assert "username" in unexpected[0].test_case.body


# ---------------------------------------------------------------------------
# Body fields — optional, absent from baseline (the PATCH case)
# ---------------------------------------------------------------------------


def test_optional_body_fields_are_still_mutated_via_synthesis(spec):
    """PATCH /users/{user_id}'s UserUpdate fields are ALL optional, so
    Phase 3's baseline body is empty ({}). The mutation engine must
    still generate mutations for them by synthesizing a starting value
    — otherwise this endpoint would get zero body mutations, which
    would be a real gap for exactly the kind of endpoint (partial
    update) attackers target."""
    endpoint, baseline = _baseline_case(spec, "/users/{user_id}", "PATCH")
    assert baseline.body == {}  # confirms the premise

    mutations = generate_mutations_for_test_case(endpoint, baseline)
    body_mutations = [m for m in mutations if m.mutation.location.startswith("body.")]
    assert len(body_mutations) > 0
    locations = {m.mutation.location for m in body_mutations}
    assert "body.age" in locations
    # The mutated test case must actually carry the field, even though
    # the baseline never did.
    age_mutation = next(m for m in body_mutations if m.mutation.location == "body.age")
    assert "age" in age_mutation.test_case.body


def test_optional_field_never_present_in_baseline_gets_no_missing_field_mutation(spec):
    """MISSING_FIELD only makes sense for a field that WAS present —
    removing a field that was never there isn't a meaningful test."""
    endpoint, baseline = _baseline_case(spec, "/users/{user_id}", "PATCH")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    missing = [m for m in mutations if m.mutation.mutation_type == MutationType.MISSING_FIELD]
    assert missing == []


# ---------------------------------------------------------------------------
# Array / object body fields (the /users/{user_id}/tags endpoint)
# ---------------------------------------------------------------------------


def test_array_and_object_body_fields_are_mutated(spec):
    endpoint, baseline = _baseline_case(spec, "/users/{user_id}/tags", "PUT")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    locations = {m.mutation.location for m in mutations}
    assert "body.tags" in locations
    assert "body.metadata" in locations

    tags_mutations = [m for m in mutations if m.mutation.location == "body.tags"]
    assert any(m.mutation.mutation_type == MutationType.EMPTY_ARRAY for m in tags_mutations)

    metadata_mutations = [m for m in mutations if m.mutation.location == "body.metadata"]
    assert any(m.mutation.mutation_type == MutationType.OBJECT_EMPTY for m in metadata_mutations)


# ---------------------------------------------------------------------------
# Determinism and limits
# ---------------------------------------------------------------------------


def test_mutation_generation_is_deterministic(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    first = generate_mutations_for_test_case(endpoint, baseline)
    second = generate_mutations_for_test_case(endpoint, baseline)
    assert [m.mutation.model_dump() for m in first] == [m.mutation.model_dump() for m in second]


def test_max_mutations_per_endpoint_is_respected(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    config = MutationConfig(max_mutations_per_endpoint=5)
    mutations = generate_mutations_for_test_case(endpoint, baseline, config)
    assert len(mutations) == 5


def test_every_mutation_preserves_baseline_relationship(spec):
    endpoint, baseline = _baseline_case(spec, "/users", "POST")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    for m in mutations:
        assert m.baseline_key == "POST /users"


def test_endpoint_with_no_params_or_body_produces_no_mutations(spec):
    endpoint, baseline = _baseline_case(spec, "/health", "GET")
    mutations = generate_mutations_for_test_case(endpoint, baseline)
    assert mutations == []
