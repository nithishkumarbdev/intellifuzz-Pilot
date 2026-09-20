"""
Tests for app.generator.context — with special attention to what it
deliberately EXCLUDES: header values (including real auth tokens) and
any information about endpoints other than the one requested.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.generator.context import build_endpoint_context
from app.parser.openapi_parser import parse_openapi_spec
from app.runner.models import TestResult

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"

SETTINGS = RunnerSettings(
    base_url="http://test", auth_header_name="x-api-token", auth_header_value="super-secret-alice-token"
)


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _endpoint(spec, path, method):
    return next(e for e in spec.endpoints if e.path == path and e.method == method)


def test_context_never_includes_the_real_auth_token(spec):
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    assert "super-secret-alice-token" in baseline_case.headers.values()  # confirms the premise: it WAS in the test case

    context = build_endpoint_context(endpoint, baseline_case)
    context_text = str(context)
    assert "super-secret-alice-token" not in context_text
    assert "headers" not in context


def test_context_includes_method_and_path(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case)
    assert context["method"] == "POST"
    assert context["path"] == "/users"


def test_context_includes_body_field_schemas(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case)
    field_names = {f["name"] for f in context["request_body_fields"]}
    assert field_names == {"username", "email", "age"}
    age_field = next(f for f in context["request_body_fields"] if f["name"] == "age")
    assert age_field["schema"]["type"] == "integer"
    assert age_field["required"] is True


def test_context_includes_baseline_request_shape(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case)
    assert context["baseline_request"]["body"] == baseline_case.body


def test_context_includes_baseline_status_when_given(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case, baseline_result=TestResult(status_code=201))
    assert context["baseline_status_code"] == 201


def test_context_omits_status_when_not_given(spec):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case)
    assert context["baseline_status_code"] is None


def test_context_for_one_endpoint_never_mentions_another_endpoints_path(spec):
    """Token/cost control + scope enforcement: context is built per
    endpoint, and nothing about /admin/stats (a DIFFERENT sensitive
    endpoint) should leak into /users' context."""
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    context = build_endpoint_context(endpoint, baseline_case)
    assert "/admin/stats" not in str(context)
