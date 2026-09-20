"""
Tests for app.fuzzer.mutation_runner — actually executing mutations
through the real HTTP runner against the in-process vulnerable-api.

Includes the phase's required end-to-end integration test: OpenAPI ->
Endpoint -> Baseline -> Mutation Engine -> Mutated TestCases -> API
Runner -> Results, all the way through.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.baseline import capture_baselines
from app.fuzzer.mutation_runner import run_fuzzing_pass, run_mutations_for_endpoint
from app.fuzzer.mutations.models import MutationConfig, MutationType
from app.fuzzer.test_case_builder import build_baseline_test_case
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


# ---------------------------------------------------------------------------
# Single-endpoint execution
# ---------------------------------------------------------------------------


async def test_mutations_execute_and_return_results(spec, asgi_client):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)

    results = await run_mutations_for_endpoint(endpoint, baseline_case, SETTINGS, client=asgi_client)

    assert len(results) > 0
    for r in results:
        # Every mutated request against our own live target should at
        # least get *a* response — connection-level errors would mean
        # something is wrong with the harness, not the mutation.
        assert r.result.error is None
        assert r.result.status_code is not None
        assert r.baseline_key == "POST /users"


async def test_negative_age_mutation_is_accepted_by_vulnerable_api(spec, asgi_client):
    """Ties back to VULN #2 (weak input validation) documented in
    vulnerable-api: age has no bounds checking, so a NEGATIVE mutation
    should come back 201 (accepted), not rejected. This phase makes NO
    claim that this is a vulnerability — it's just evidence that the
    mutation reached the target and the target's behavior is visible
    in the result, which is exactly what Phase 4 is responsible for."""
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    results = await run_mutations_for_endpoint(endpoint, baseline_case, SETTINGS, client=asgi_client)

    negative_age = next(
        r
        for r in results
        if r.mutation.location == "body.age" and r.mutation.mutation_type == MutationType.NEGATIVE
    )
    assert negative_age.result.status_code == 201
    assert negative_age.result.body["age"] == -1


async def test_missing_required_field_mutation_is_rejected_by_target(spec, asgi_client):
    """The counterpart to the above: removing a genuinely required field
    (username) should produce a 422 from FastAPI's own request
    validation — a case where the target DOES behave correctly."""
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    results = await run_mutations_for_endpoint(endpoint, baseline_case, SETTINGS, client=asgi_client)

    missing_username = next(
        r for r in results if r.mutation.mutation_type == MutationType.MISSING_FIELD and r.mutation.field_name == "username"
    )
    assert missing_username.result.status_code == 422


async def test_max_total_mutations_limit_is_respected_within_single_endpoint(spec, asgi_client):
    endpoint = _endpoint(spec, "/users", "POST")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    results = await run_mutations_for_endpoint(
        endpoint, baseline_case, SETTINGS, client=asgi_client, limit=3
    )
    assert len(results) == 3


# ---------------------------------------------------------------------------
# Full pipeline: capture baselines, then run a complete fuzzing pass
# ---------------------------------------------------------------------------


async def test_full_pipeline_openapi_to_mutation_results(spec, live_vulnerable_api_url):
    """
    The phase's required end-to-end test: OpenAPI -> Endpoint ->
    Baseline -> Mutation Engine -> Mutated TestCases -> API Runner ->
    Results, exercised against a REAL running vulnerable-api instance.

    This deliberately does NOT use asgi_client here: the spec includes
    every endpoint, including /slow, and a numeric mutation with no
    declared bounds can legitimately produce a very large value (see
    test_value_mutations.py — a field with neither `minimum` nor
    `maximum` gets a "large value" mutation of 999,999,999). Executed
    against /slow's `await asyncio.sleep(delay)`, that's effectively
    an infinite hang — and ASGITransport does not enforce httpx's
    client-level timeout (no real I/O for it to interrupt; established
    in Phase 2), so that hang would never be cut off.

    Against a REAL client with a short configured timeout, this
    resolves itself correctly with no special-casing needed: /slow's
    own BASELINE capture (default delay=2.0) exceeds the short timeout
    and comes back as a timeout ErrorInfo, and run_fuzzing_pass already
    skips endpoints whose baseline didn't execute — so /slow is
    naturally excluded before any mutation of it is ever attempted.
    This is the same lesson as Phase 2's timeout tests: real
    timeout-dependent behavior needs a real socket.
    """
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    baseline_store = await capture_baselines(spec, settings)
    slow_baseline = baseline_store.get("GET", "/slow")
    assert slow_baseline is not None
    assert slow_baseline.result.executed is False  # confirms the premise: timed out, as expected

    config = MutationConfig(max_total_mutations=60, skip_methods={"DELETE"})
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=config)

    assert len(results_by_endpoint) > 0
    total_results = sum(len(v) for v in results_by_endpoint.values())
    assert 0 < total_results <= 60

    # /slow must be excluded (failed baseline), DELETE must be excluded
    # (skip_methods).
    assert "GET /slow" not in results_by_endpoint
    for key in results_by_endpoint:
        assert not key.startswith("DELETE ")

    # Every individual result must have actually executed against the
    # target — no connection/timeout-level runner errors for any
    # endpoint that DID make it into the pass.
    for endpoint_results in results_by_endpoint.values():
        for r in endpoint_results:
            assert r.result.error is None


async def test_fuzzing_pass_skips_endpoint_with_failed_baseline(spec, asgi_client):
    """An endpoint whose baseline itself never got a response has
    nothing meaningful to mutate from — it should be skipped, not
    crash the whole pass."""
    from app.fuzzer.baseline import Baseline, BaselineStore
    from app.runner.models import ErrorInfo, TestResult

    store = BaselineStore()
    endpoint = _endpoint(spec, "/health", "GET")
    baseline_case = build_baseline_test_case(endpoint, SETTINGS)
    store.add(
        Baseline(
            endpoint_path=endpoint.path,
            endpoint_method=endpoint.method,
            test_case=baseline_case,
            result=TestResult(error=ErrorInfo(type="connection_error", message="simulated failure")),
        )
    )

    results_by_endpoint = await run_fuzzing_pass(spec, store, SETTINGS, client=asgi_client)
    assert results_by_endpoint == {}


async def test_max_total_mutations_caps_across_multiple_endpoints(spec, live_vulnerable_api_url):
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    baseline_store = await capture_baselines(spec, settings)
    config = MutationConfig(max_total_mutations=10, skip_methods={"DELETE"})
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=config)
    total = sum(len(v) for v in results_by_endpoint.values())
    assert total <= 10
