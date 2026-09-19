"""
Tests for app.fuzzer.baseline: capturing baselines against the
in-process vulnerable-api, and BaselineStore's JSON round-trip.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.baseline import Baseline, BaselineStore, capture_baseline_for_endpoint, capture_baselines
from app.parser.openapi_parser import parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"

SETTINGS = RunnerSettings(
    base_url="http://vulnerable-api-test", auth_header_name="x-api-token", auth_header_value="alice-token"
)


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _endpoint(spec, path, method):
    return next(e for e in spec.endpoints if e.path == path and e.method == method)


async def test_capture_single_endpoint_baseline(spec, asgi_client):
    endpoint = _endpoint(spec, "/health", "GET")
    baseline = await capture_baseline_for_endpoint(endpoint, SETTINGS, client=asgi_client)
    assert baseline.endpoint_path == "/health"
    assert baseline.endpoint_method == "GET"
    assert baseline.result.executed
    assert baseline.result.status_code == 200


async def test_capture_authenticated_endpoint_baseline(spec, asgi_client):
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    baseline = await capture_baseline_for_endpoint(endpoint, SETTINGS, client=asgi_client)
    # user_id defaults to 1, which happens to be alice's real seeded id —
    # so with a valid configured token this should genuinely succeed.
    assert baseline.result.status_code == 200
    assert baseline.result.body["username"] == "alice"


async def test_capture_all_baselines_covers_every_endpoint(spec, asgi_client):
    store = await capture_baselines(spec, SETTINGS, client=asgi_client)
    assert len(store) == spec.endpoint_count()
    for endpoint in spec.endpoints:
        baseline = store.get(endpoint.method, endpoint.path)
        assert baseline is not None
        # Every baseline should have at least executed (gotten *a*
        # response) — some may legitimately be 4xx (e.g. DELETE running
        # after an earlier DELETE already removed the resource), but
        # none should be a connection/timeout-level runner error against
        # our own in-process target.
        assert baseline.result.error is None, (
            f"{endpoint.method} {endpoint.path} baseline failed to execute: {baseline.result.error}"
        )


async def test_missing_no_auth_configured_still_produces_a_result_not_a_crash(spec, asgi_client):
    """Without a configured credential, an auth-required endpoint's
    baseline should still come back as a normal 401 TestResult — never
    an exception, never a runner-level error."""
    settings_no_auth = RunnerSettings(base_url="http://vulnerable-api-test")
    endpoint = _endpoint(spec, "/users/{user_id}", "GET")
    baseline = await capture_baseline_for_endpoint(endpoint, settings_no_auth, client=asgi_client)
    assert baseline.result.executed
    assert baseline.result.status_code == 401


def test_baseline_store_json_round_trip(tmp_path):
    from app.runner.models import TestCase, TestResult

    store = BaselineStore()
    store.add(
        Baseline(
            endpoint_path="/health",
            endpoint_method="GET",
            test_case=TestCase(method="GET", path="/health"),
            result=TestResult(status_code=200, body={"status": "ok"}, body_is_json=True),
        )
    )

    file_path = tmp_path / "baselines.json"
    store.save_to_file(str(file_path))

    reloaded = BaselineStore.load_from_file(str(file_path))
    assert len(reloaded) == 1
    baseline = reloaded.get("GET", "/health")
    assert baseline is not None
    assert baseline.result.status_code == 200
    assert baseline.result.body == {"status": "ok"}


def test_baseline_store_get_returns_none_for_unknown_endpoint():
    store = BaselineStore()
    assert store.get("GET", "/nonexistent") is None
