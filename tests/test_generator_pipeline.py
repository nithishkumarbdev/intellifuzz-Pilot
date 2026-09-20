"""
Tests for app.generator.pipeline's generation-level logic: dedup and
generate_combined_mutations. End-to-end execution against the live
vulnerable-api lives in test_generator_pipeline_e2e.py.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.mutations.models import MutationConfig, MutationType
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.generator.models import GeneratorConfig
from app.generator.pipeline import deduplicate_against, generate_combined_mutations
from app.generator.provider import FailingLLMProvider, FakeLLMProvider, ProviderTimeout
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


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _mutated(baseline_key, location, value, source="deterministic"):
    from app.fuzzer.mutations.models import MutatedTestCase, Mutation
    from app.runner.models import TestCase

    return MutatedTestCase(
        baseline_key=baseline_key,
        mutation=Mutation(mutation_type=MutationType.NEGATIVE, location=location, mutated_value=value),
        test_case=TestCase(method="POST", path="/x"),
        source=source,
    )


def test_dedup_removes_exact_duplicate_against_existing():
    existing = [_mutated("POST /users", "body.age", -1)]
    candidates = [_mutated("POST /users", "body.age", -1, source="llm")]
    deduped, removed = deduplicate_against(candidates, existing)
    assert deduped == []
    assert removed == 1


def test_dedup_keeps_distinct_mutations():
    existing = [_mutated("POST /users", "body.age", -1)]
    candidates = [_mutated("POST /users", "body.age", 999, source="llm")]
    deduped, removed = deduplicate_against(candidates, existing)
    assert len(deduped) == 1
    assert removed == 0


def test_dedup_removes_duplicates_within_candidates_themselves():
    candidates = [
        _mutated("POST /users", "body.age", 999, source="llm"),
        _mutated("POST /users", "body.age", 999, source="llm"),
    ]
    deduped, removed = deduplicate_against(candidates, [])
    assert len(deduped) == 1
    assert removed == 1


def test_dedup_treats_different_locations_as_distinct_even_with_same_value():
    existing = [_mutated("POST /users", "body.age", -1)]
    candidates = [_mutated("POST /users", "body.quantity", -1, source="llm")]
    deduped, removed = deduplicate_against(candidates, existing)
    assert len(deduped) == 1


def test_dedup_treats_different_endpoints_as_distinct():
    existing = [_mutated("POST /users", "body.age", -1)]
    candidates = [_mutated("POST /orders", "body.age", -1, source="llm")]
    deduped, removed = deduplicate_against(candidates, existing)
    assert len(deduped) == 1


def test_dedup_preserves_order():
    candidates = [
        _mutated("POST /users", "body.age", 1, source="llm"),
        _mutated("POST /users", "body.age", 2, source="llm"),
        _mutated("POST /users", "body.age", 3, source="llm"),
    ]
    deduped, _ = deduplicate_against(candidates, [])
    assert [m.mutation.mutated_value for m in deduped] == [1, 2, 3]


# ---------------------------------------------------------------------------
# generate_combined_mutations
# ---------------------------------------------------------------------------


async def test_no_provider_returns_deterministic_only(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    result = await generate_combined_mutations(endpoint, baseline, provider=None)
    assert result.llm_candidate_count == 0
    assert result.llm_error is None
    assert all(m.source == "deterministic" for m in result.mutations)
    assert len(result.mutations) == result.deterministic_count


async def test_llm_candidates_are_merged_with_deterministic(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    provider = FakeLLMProvider(
        fixed_response=json.dumps(
            {"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.age", "proposed_value": 999}]}
        )
    )
    result = await generate_combined_mutations(endpoint, baseline, provider)
    assert result.llm_accepted_count == 1
    sources = {m.source for m in result.mutations}
    assert sources == {"deterministic", "llm"}


async def test_provider_failure_degrades_to_deterministic_only(spec):
    """The scan must not fail just because the LLM is unavailable."""
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    provider = FailingLLMProvider(ProviderTimeout("simulated"))
    result = await generate_combined_mutations(endpoint, baseline, provider)
    assert result.llm_error is not None
    assert "ProviderTimeout" in result.llm_error
    assert len(result.mutations) == result.deterministic_count  # deterministic still fully present
    assert all(m.source == "deterministic" for m in result.mutations)


async def test_malformed_llm_output_degrades_to_deterministic_only(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    provider = FakeLLMProvider(fixed_response="not valid json")
    result = await generate_combined_mutations(endpoint, baseline, provider)
    assert result.llm_error is not None
    assert len(result.mutations) == result.deterministic_count


async def test_endpoint_mismatch_degrades_to_deterministic_only_via_rejection(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    provider = FakeLLMProvider(
        fixed_response=json.dumps(
            {"endpoint": {"method": "DELETE", "path": "/admin"}, "tests": [{"target_location": "body.age", "proposed_value": 1}]}
        )
    )
    result = await generate_combined_mutations(endpoint, baseline, provider)
    assert result.llm_error is None  # not a provider/parse failure — a validation rejection
    assert result.llm_accepted_count == 0
    assert len(result.llm_rejected) == 1
    assert all(m.source == "deterministic" for m in result.mutations)


async def test_llm_duplicate_of_deterministic_mutation_is_deduplicated(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    # -1 is exactly the deterministic engine's own NEGATIVE mutation for age.
    provider = FakeLLMProvider(
        fixed_response=json.dumps(
            {"endpoint": {"method": "POST", "path": "/users"}, "tests": [{"target_location": "body.age", "proposed_value": -1}]}
        )
    )
    result = await generate_combined_mutations(endpoint, baseline, provider)
    assert result.duplicates_removed == 1
    assert len(result.mutations) == result.deterministic_count  # the LLM duplicate didn't add anything new


async def test_combined_result_respects_max_mutations_per_endpoint(spec):
    endpoint = _users_post(spec)
    baseline = build_baseline_test_case(endpoint, SETTINGS)
    provider = FakeLLMProvider(
        fixed_response=json.dumps(
            {
                "endpoint": {"method": "POST", "path": "/users"},
                "tests": [{"target_location": "body.age", "proposed_value": v} for v in range(50, 60)],
            }
        )
    )
    fuzz_config = MutationConfig(max_mutations_per_endpoint=5)
    result = await generate_combined_mutations(endpoint, baseline, provider, fuzz_config=fuzz_config)
    assert len(result.mutations) == 5
