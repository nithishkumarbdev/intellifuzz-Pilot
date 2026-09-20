"""
Tests for app.generator.candidates — parsing raw LLM output and
validating candidates against a real endpoint. This is the file that
proves the phase's core security boundaries actually hold.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.mutations.models import MutationType
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.generator.candidates import parse_llm_response, validate_candidates
from app.generator.models import GeneratorConfig, LLMGenerationResponse
from app.parser.openapi_parser import parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"

SETTINGS = RunnerSettings(base_url="http://test")


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _endpoint(spec, path, method):
    return next(e for e in spec.endpoints if e.path == path and e.method == method)


def _users_post(spec):
    return _endpoint(spec, "/users", "POST")


def _baseline(spec, endpoint):
    return build_baseline_test_case(endpoint, SETTINGS)


# ---------------------------------------------------------------------------
# parse_llm_response
# ---------------------------------------------------------------------------


def test_parse_valid_json():
    raw = json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": []})
    response, error = parse_llm_response(raw)
    assert error is None
    assert response.endpoint.method == "POST"


def test_parse_invalid_json_returns_error_not_exception():
    response, error = parse_llm_response("not json {{{")
    assert response is None
    assert "invalid JSON" in error


def test_parse_missing_required_field_returns_error():
    raw = json.dumps({"tests": []})  # missing "endpoint"
    response, error = parse_llm_response(raw)
    assert response is None
    assert error is not None


def test_parse_wrong_type_returns_error():
    response, error = parse_llm_response(json.dumps(["not", "an", "object"]))
    assert response is None
    assert error is not None


def test_parse_tests_missing_target_location_returns_error():
    raw = json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"proposed_value": 1}]})
    response, error = parse_llm_response(raw)
    assert response is None  # target_location is required on each candidate
    assert error is not None


def test_parse_empty_tests_list_is_valid():
    raw = json.dumps({"endpoint": {"method": "GET", "path": "/health"}, "tests": []})
    response, error = parse_llm_response(raw)
    assert error is None
    assert response.tests == []


# ---------------------------------------------------------------------------
# validate_candidates — acceptance
# ---------------------------------------------------------------------------


def test_valid_body_candidate_is_accepted(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {
                "endpoint": {"method": "POST", "path": "/users"},
                "tests": [{"target_location": "body.age", "proposed_value": 999, "reason": "large value"}],
            }
        )
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert rejected == []
    assert len(accepted) == 1
    assert accepted[0].mutation.mutation_type == MutationType.LLM_SUGGESTED
    assert accepted[0].mutation.mutated_value == 999
    assert accepted[0].source == "llm"
    assert accepted[0].reason == "large value"


def test_valid_path_candidate_is_accepted(spec):
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {"endpoint": {"method": "GET", "path": "/users/{user_id}"}, "tests": [{"target_location": "path.user_id", "proposed_value": 0}]}
        )
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert len(accepted) == 1
    assert accepted[0].test_case.path_params["user_id"] == 0


def test_candidate_preserves_original_value(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    original_age = baseline.body["age"]
    response, _ = parse_llm_response(
        json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.age", "proposed_value": -5}]})
    )
    accepted, _ = validate_candidates(response, endpoint, baseline)
    assert accepted[0].mutation.original_value == original_age


def test_confidence_is_preserved_but_not_used_for_anything(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.age", "proposed_value": -5, "confidence": 0.93}]}
        )
    )
    accepted, _ = validate_candidates(response, endpoint, baseline)
    assert accepted[0].confidence == 0.93


def test_type_mismatched_value_is_accepted_not_rejected(spec):
    """A string proposed for an integer field is often exactly the
    interesting test case — validation checks structure (does the
    field exist), never the proposed value's type."""
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.age", "proposed_value": "not-a-number"}]})
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert rejected == []
    assert accepted[0].mutation.mutated_value == "not-a-number"


# ---------------------------------------------------------------------------
# validate_candidates — rejection / security boundaries
# ---------------------------------------------------------------------------


def test_endpoint_mismatch_rejects_entire_batch(spec):
    """The concrete defense against a prompt-injection attempt trying
    to redirect candidates at a different endpoint."""
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {
                "endpoint": {"method": "DELETE", "path": "/admin/delete-all"},
                "tests": [
                    {"target_location": "body.age", "proposed_value": 1},
                    {"target_location": "body.username", "proposed_value": "x"},
                ],
            }
        )
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert accepted == []
    assert len(rejected) == 2
    assert all(r.reason == "endpoint_mismatch" for r in rejected)


def test_unknown_field_is_rejected(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.is_admin", "proposed_value": True}]})
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert accepted == []
    assert rejected[0].reason == "unknown_field"


def test_unknown_path_field_is_rejected(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "path.nonexistent_id", "proposed_value": 1}]})
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert accepted == []
    assert rejected[0].reason == "unknown_field"


def test_malformed_location_no_dot_is_rejected(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "age", "proposed_value": 1}]})
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert accepted == []
    assert rejected[0].reason == "malformed_location"


def test_header_location_is_rejected(spec):
    """Headers are out of scope for this generator — same boundary the
    deterministic engine already respects."""
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "header.x-api-token", "proposed_value": "stolen"}]}
        )
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert accepted == []
    assert rejected[0].reason == "unsupported_location_kind"


def test_cannot_select_arbitrary_url_target():
    """There is no field anywhere in LLMTestCandidateRaw for a host,
    scheme, or URL — proven structurally: constructing one with an
    extra 'url' field is simply ignored (pydantic doesn't reject unknown
    fields by default, but nothing downstream ever reads one)."""
    from app.generator.models import LLMTestCandidateRaw

    candidate = LLMTestCandidateRaw.model_validate(
        {"target_location": "body.age", "proposed_value": 1, "url": "http://evil.example.com"}
    )
    assert not hasattr(candidate, "url") or "url" not in LLMTestCandidateRaw.model_fields


def test_excessive_candidate_count_is_capped(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    many_tests = [{"target_location": "body.age", "proposed_value": i} for i in range(20)]
    response, _ = parse_llm_response(json.dumps({"endpoint": {"method": "POST", "path": "/users"}, "tests": many_tests}))
    config = GeneratorConfig(max_candidates_per_endpoint=5)
    accepted, rejected = validate_candidates(response, endpoint, baseline, config)
    assert len(accepted) == 5
    assert len(rejected) == 15
    assert all(r.reason == "exceeds_max_candidates" for r in rejected)


def test_mixed_valid_and_invalid_candidates(spec):
    endpoint = _users_post(spec)
    baseline = _baseline(spec, endpoint)
    response, _ = parse_llm_response(
        json.dumps(
            {
                "endpoint": {"method": "POST", "path": "/users"},
                "tests": [
                    {"target_location": "body.age", "proposed_value": 999},
                    {"target_location": "body.nonexistent", "proposed_value": "x"},
                    {"target_location": "body.username", "proposed_value": ""},
                ],
            }
        )
    )
    accepted, rejected = validate_candidates(response, endpoint, baseline)
    assert len(accepted) == 2
    assert len(rejected) == 1
    assert rejected[0].detail == "body.nonexistent"
