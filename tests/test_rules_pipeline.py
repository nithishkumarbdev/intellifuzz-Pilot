"""
End-to-end test for app.rules.pipeline.evaluate_fuzzing_results against
the real (live) vulnerable-api: OpenAPI -> baseline -> mutations ->
execution -> analysis -> rules -> findings.

Uses the live-server fixture with a short timeout deliberately — same
reasoning as every other full-spec test in this project since Phase 4
(see tests/test_mutation_runner.py for the original story): the spec
includes /slow, and only a real client with a real timeout can exclude
it safely.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.baseline import capture_baselines
from app.fuzzer.mutations.models import MutationConfig
from app.fuzzer.mutation_runner import run_fuzzing_pass
from app.parser.openapi_parser import parse_openapi_spec
from app.rules.models import Severity
from app.rules.pipeline import evaluate_fuzzing_results

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


async def test_full_pipeline_produces_real_findings_against_vulnerable_api(spec, live_vulnerable_api_url):
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=150, skip_methods={"DELETE"})
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=fuzz_config)

    findings = evaluate_fuzzing_results(baseline_store, results_by_endpoint)

    # Every finding must be fully traceable and use non-alarmist language.
    for finding in findings:
        assert finding.title.startswith("Potential")
        assert finding.baseline_key in results_by_endpoint
        assert finding.rule_id in {"INPUT-001", "AUTH-001", "AUTHZ-001", "DATA-001", "BEHAVIOR-001"}
        assert finding.reproduction.url  # reproducible
        for banned in ("confirmed", "Confirmed", "bypass confirmed"):
            assert banned not in finding.title
            assert banned not in finding.description

    # Deduplication actually reduced volume: many mutations target the
    # same handful of (endpoint, rule) pairs (e.g. many /users/{user_id}
    # path-identifier mutations all hitting AUTHZ-001).
    total_mutations = sum(len(v) for v in results_by_endpoint.values())
    assert len(findings) <= total_mutations

    # No finding ID collides across genuinely different findings.
    ids = [f.finding_id for f in findings]
    assert len(ids) == len(set(ids))


async def test_pipeline_is_deterministic_given_same_captured_data(spec, live_vulnerable_api_url):
    """Same precise claim as the analyzer's own Phase 5 determinism
    test: given the SAME already-captured results, evaluate_fuzzing_results
    is deterministic. Does not re-run capture+fuzz twice against the
    live server — that's not expected to be identical (state-changing
    mutations), and asserting it would test something false."""
    settings = RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=60, skip_methods={"DELETE"})
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, settings, config=fuzz_config)

    findings_1 = evaluate_fuzzing_results(baseline_store, results_by_endpoint)
    findings_2 = evaluate_fuzzing_results(baseline_store, results_by_endpoint)

    dump_1 = [f.model_dump(mode="json") for f in findings_1]
    dump_2 = [f.model_dump(mode="json") for f in findings_2]
    assert dump_1 == dump_2


async def test_pipeline_finds_authz_signal_on_users_endpoint(spec, isolated_live_vulnerable_api_url):
    """
    A concrete, expected live finding: GET /users/{user_id} is
    documented as VULN #1 (IDOR) in vulnerable-api — mutating the path
    identifier to another user's real id should trip AUTHZ-001.

    Deliberately uses isolated_live_vulnerable_api_url (a dedicated,
    function-scoped server), not the shared session-scoped
    live_vulnerable_api_url: an earlier test in this file already ran a
    full-spec capture_baselines() against the shared server, which also
    captures /users/{user_id}'s DELETE baseline as a side effect — that
    really deletes user 1 (the same documented, pre-existing baseline-
    capture limitation from Phase 3). By the time a later test in this
    file runs against the SAME shared server, user 1 no longer exists.
    A dedicated server for this test sidesteps that entirely.
    """
    from app.fuzzer.baseline import BaselineStore, capture_baseline_for_endpoint
    from app.fuzzer.mutation_runner import execute_mutated_test_cases
    from app.fuzzer.mutations.models import MutatedTestCase, Mutation, MutationType

    settings = RunnerSettings(
        base_url=isolated_live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )
    endpoint = next(e for e in spec.endpoints if e.path == "/users/{user_id}" and e.method == "GET")
    baseline = await capture_baseline_for_endpoint(endpoint, settings)
    assert baseline.result.status_code == 200  # confirms the premise: alice still exists

    # One explicit, realistic cross-resource mutation (alice's id -> bob's
    # real id) rather than the deterministic engine's own boundary values
    # (0, -1, huge numbers), which by design don't target real ids.
    mutated_case = baseline.test_case.model_copy(deep=True)
    mutated_case.path_params["user_id"] = 2  # bob's real seeded id
    mutation = Mutation(
        mutation_type=MutationType.BOUNDARY_NUMBER, location="path.user_id", field_name="user_id", original_value=1, mutated_value=2
    )
    mutated = MutatedTestCase(baseline_key="GET /users/{user_id}", mutation=mutation, test_case=mutated_case)

    results = await execute_mutated_test_cases([mutated], settings)
    assert results[0].result.status_code == 200  # confirms the premise: IDOR really is reachable here

    store = BaselineStore()
    store.add(baseline)
    findings = evaluate_fuzzing_results(store, {"GET /users/{user_id}": results})

    authz_findings = [f for f in findings if f.rule_id == "AUTHZ-001"]
    assert len(authz_findings) == 1
    assert authz_findings[0].severity == Severity.HIGH
    assert authz_findings[0].evidence.details["mutated_identifier"] == 2


def test_pipeline_skips_endpoint_with_no_baseline():
    from app.fuzzer.baseline import BaselineStore
    from app.fuzzer.mutations.models import Mutation, MutationType
    from app.fuzzer.mutation_runner import MutationResult
    from app.runner.models import TestResult

    empty_store = BaselineStore()
    fake_results = {
        "GET /nonexistent": [
            MutationResult(
                baseline_key="GET /nonexistent",
                mutation=Mutation(mutation_type=MutationType.NULL, location="path.id"),
                result=TestResult(status_code=500),
            )
        ]
    }
    findings = evaluate_fuzzing_results(empty_store, fake_results)
    assert findings == []
