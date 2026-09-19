"""
Tests for app.fuzzer.test_case_builder.

Uses real Endpoints parsed from the vulnerable-api spec (same fixture
pattern as test_parser.py) so these tests exercise the real shapes
Phase 1 produces, not hand-rolled ones that might not match reality.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.parser.openapi_parser import parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"

NO_AUTH_SETTINGS = RunnerSettings(base_url="http://test")
WITH_AUTH_SETTINGS = RunnerSettings(
    base_url="http://test", auth_header_name="x-api-token", auth_header_value="alice-token"
)


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _endpoint(spec, path, method):
    return next(e for e in spec.endpoints if e.path == path and e.method == method)


def test_path_param_is_always_filled(spec):
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    test_case = build_baseline_test_case(endpoint, NO_AUTH_SETTINGS)
    assert "user_id" in test_case.path_params
    assert isinstance(test_case.path_params["user_id"], int)


def test_optional_header_omitted_without_configured_auth(spec):
    """/users/{user_id}'s x-api-token header is Optional in the spec —
    without a configured auth header, it should simply be absent, not
    filled with a placeholder."""
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    test_case = build_baseline_test_case(endpoint, NO_AUTH_SETTINGS)
    assert "x-api-token" not in test_case.headers


def test_configured_auth_header_is_filled_even_though_optional_in_spec(spec):
    """This is the documented heuristic: the spec marks x-api-token as
    optional (FastAPI has no way to say 'conditionally required'), but
    a baseline request should still authenticate when we have a
    configured credential — otherwise every baseline would 401."""
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    test_case = build_baseline_test_case(endpoint, WITH_AUTH_SETTINGS)
    assert test_case.headers.get("x-api-token") == "alice-token"


def test_required_body_fields_are_filled(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    test_case = build_baseline_test_case(endpoint, NO_AUTH_SETTINGS)
    assert set(test_case.body.keys()) == {"username", "email", "age"}
    assert isinstance(test_case.body["age"], int)


def test_endpoint_with_no_params_or_body_produces_minimal_test_case(spec):
    endpoint = _endpoint(spec, "/health", "GET")
    test_case = build_baseline_test_case(endpoint, NO_AUTH_SETTINGS)
    assert test_case.path_params == {}
    assert test_case.query_params == {}
    assert test_case.body is None


def test_built_test_case_passes_validation(spec):
    """Every baseline TestCase we build must be structurally valid —
    otherwise capture_baseline_for_endpoint would just be recording
    validation errors instead of real evidence."""
    from app.runner.validation import validate_test_case

    for endpoint in spec.endpoints:
        test_case = build_baseline_test_case(endpoint, WITH_AUTH_SETTINGS)
        validate_test_case(test_case)  # raises if invalid
