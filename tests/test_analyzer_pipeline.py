"""
End-to-end test for app.analyzer.pipeline: OpenAPI -> baseline capture
-> fuzzing pass -> analysis, against the real (in-process) vulnerable-
api. Proves the full chain works together, not just each piece in
isolation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzer.models import AnalysisConfig, AnomalyType
from app.analyzer.pipeline import analyze_fuzzing_results
from app.core.config import RunnerSettings
from app.fuzzer.baseline import capture_baselines
from app.fuzzer.mutation_runner import run_fuzzing_pass
from app.fuzzer.mutations.models import MutationConfig
from app.parser.openapi_parser import parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


async def test_full_pipeline_baseline_to_fuzz_to_analysis(spec, live_vulnerable_api_url):
    """
    Uses the REAL live-server fixture, not asgi_client, deliberately:
    this exercises the full spec including /slow, and (per the exact
    lesson from Phase 4's own test_mutation_runner.py) a numeric
    mutation with no declared bounds can produce a very large value
    that, fed into /slow's `await asyncio.sleep(delay)`, would hang
    forever under ASGITransport (which doesn't enforce httpx's client
    timeout). A real client with a short timeout resolves this cleanly:
    /slow's own baseline capture (default delay=2.0) exceeds the short
    timeout and is excluded before any mutation of it is attempted, via
    the same "skip endpoints with a failed baseline" logic already in
    run_fuzzing_pass.
    """
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    baseline_store = await capture_baselines(spec, settings)
    config = MutationConfig(max_total_mutations=80, skip_methods={"DELETE"})
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=config)

    analysis_by_endpoint = analyze_fuzzing_results(baseline_store, results_by_endpoint)

    assert len(analysis_by_endpoint) > 0
    assert "GET /slow" not in analysis_by_endpoint  # excluded: baseline timed out
    assert set(analysis_by_endpoint.keys()) == set(results_by_endpoint.keys())

    total_analyses = sum(len(v) for v in analysis_by_endpoint.values())
    total_mutations = sum(len(v) for v in results_by_endpoint.values())
    assert total_analyses == total_mutations  # every mutation result got analyzed, none dropped

    # Real, expected finding: GET /users/{user_id} with a negative/zero
    # path param mutation should produce a genuine status-category shift
    # (200 -> 404), captured as UNEXPECTED_CLIENT_ERROR — proving the
    # pipeline surfaces real anomalies from real execution, not just
    # synthetic unit-test inputs.
    user_lookup_analyses = analysis_by_endpoint.get("GET /users/{user_id}", [])
    assert any(
        a.mutation.location == "path.user_id" and AnomalyType.UNEXPECTED_CLIENT_ERROR in {an.type for an in a.anomalies}
        for a in user_lookup_analyses
    )


async def test_pipeline_analysis_is_deterministic_given_same_captured_data(spec, live_vulnerable_api_url):
    """
    Determinism claim, stated precisely: given the SAME already-captured
    baseline_store and results_by_endpoint, analyze_fuzzing_results
    produces identical output every time it's called.

    This deliberately does NOT re-run baseline capture + fuzzing twice
    against the live server — Phase 4's mutations genuinely change
    server-side state (PUT/PATCH modify real user records), so two full
    pipeline runs against the same stateful target are not expected to
    produce identical results, and that's already a documented
    limitation (see PROJECT_STATE.md), not a determinism bug. The
    analyzer's own pure determinism (same inputs -> same output) is
    already covered at the unit level in test_analyzer.py; this proves
    it holds at the orchestration level too, against real captured data.
    """
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    config = MutationConfig(max_total_mutations=30, skip_methods={"DELETE"})

    baseline_store = await capture_baselines(spec, settings)
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=config)

    analysis_1 = analyze_fuzzing_results(baseline_store, results_by_endpoint)
    analysis_2 = analyze_fuzzing_results(baseline_store, results_by_endpoint)

    dump_1 = {k: [a.model_dump() for a in v] for k, v in analysis_1.items()}
    dump_2 = {k: [a.model_dump() for a in v] for k, v in analysis_2.items()}
    assert dump_1 == dump_2


def test_analyze_fuzzing_results_skips_endpoint_with_no_baseline():
    """Hand-built case: a mutation result referencing an endpoint the
    baseline store has no entry for must be skipped, not crash."""
    from app.fuzzer.baseline import BaselineStore
    from app.fuzzer.mutation_runner import MutationResult
    from app.fuzzer.mutations.models import Mutation, MutationType
    from app.runner.models import TestResult

    empty_store = BaselineStore()
    fake_results = {
        "GET /nonexistent": [
            MutationResult(
                baseline_key="GET /nonexistent",
                mutation=Mutation(mutation_type=MutationType.NULL, location="path.id", field_name="id"),
                result=TestResult(status_code=404),
            )
        ]
    }
    analysis = analyze_fuzzing_results(empty_store, fake_results)
    assert analysis == {}
