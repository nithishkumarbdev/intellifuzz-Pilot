"""
End-to-end test for app.generator.pipeline.run_combined_fuzzing_pass
against the real (live) vulnerable-api. Uses the live-server fixture
with a short timeout deliberately — same reasoning as Phase 4/5's own
full-spec tests: the spec includes /slow, and only a real client with a
real timeout can exclude it safely (its baseline times out and it's
skipped before any mutation is attempted). See
tests/test_mutation_runner.py and tests/test_analyzer_pipeline.py for
the full history of this exact issue.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import RunnerSettings
from app.fuzzer.baseline import capture_baselines
from app.fuzzer.mutations.models import MutationConfig
from app.generator.models import GeneratorConfig
from app.generator.pipeline import run_combined_fuzzing_pass
from app.generator.prompt import heuristic_offline_response
from app.generator.provider import FailingLLMProvider, FakeLLMProvider, ProviderTimeout
from app.parser.openapi_parser import parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"


@pytest.fixture(scope="module")
def spec():
    return parse_openapi_spec(VULN_API_SPEC)


def _live_settings(live_vulnerable_api_url):
    return RunnerSettings(
        base_url=live_vulnerable_api_url,
        auth_header_name="x-api-token",
        auth_header_value="alice-token",
        request_timeout_seconds=1.0,
    )


async def test_full_combined_pass_no_provider_matches_deterministic_only(spec, live_vulnerable_api_url):
    """With provider=None, the combined pass should behave exactly like
    the deterministic-only one, just wrapped in the richer summary."""
    settings = _live_settings(live_vulnerable_api_url)
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=80, skip_methods={"DELETE"})

    summary = await run_combined_fuzzing_pass(spec, baseline_store, settings, provider=None, fuzz_config=fuzz_config)

    assert summary.llm_candidate_count == 0
    assert summary.llm_accepted_count == 0
    assert summary.llm_errors == []
    assert "GET /slow" not in summary.results_by_endpoint
    assert summary.total_executed > 0
    for results in summary.results_by_endpoint.values():
        assert all(r.source == "deterministic" for r in results)


async def test_full_combined_pass_with_fake_provider(spec, live_vulnerable_api_url):
    """The offline heuristic fake provider, wired through the entire
    real pipeline against a real (local) target."""
    settings = _live_settings(live_vulnerable_api_url)
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=100, skip_methods={"DELETE"})
    provider = FakeLLMProvider(response_fn=heuristic_offline_response)

    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, settings, provider=provider, fuzz_config=fuzz_config
    )

    assert summary.llm_candidate_count > 0
    assert summary.total_executed > 0
    # At least one executed result should genuinely be LLM-sourced.
    llm_sourced = [r for results in summary.results_by_endpoint.values() for r in results if r.source == "llm"]
    assert len(llm_sourced) > 0
    for r in llm_sourced:
        assert r.reason is not None  # rationale preserved through to the final result


async def test_full_combined_pass_provider_failure_isolated_per_call(spec, live_vulnerable_api_url):
    """A failing provider must not stop deterministic fuzzing across the
    WHOLE run — every endpoint still gets its deterministic mutations."""
    settings = _live_settings(live_vulnerable_api_url)
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=80, skip_methods={"DELETE"})
    provider = FailingLLMProvider(ProviderTimeout("simulated"))

    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, settings, provider=provider, fuzz_config=fuzz_config
    )

    assert summary.total_executed > 0
    assert len(summary.llm_errors) > 0  # every attempted call failed and was logged
    for results in summary.results_by_endpoint.values():
        assert all(r.source == "deterministic" for r in results)


async def test_max_total_llm_calls_is_respected(spec, live_vulnerable_api_url):
    """Once the LLM call budget is exhausted, remaining endpoints still
    get deterministic mutations — they just stop calling the LLM."""
    settings = _live_settings(live_vulnerable_api_url)
    baseline_store = await capture_baselines(spec, settings)
    fuzz_config = MutationConfig(max_total_mutations=200, skip_methods={"DELETE"})
    generator_config = GeneratorConfig(max_total_llm_calls=1)

    call_count = {"n": 0}

    def counting_heuristic(prompt: str) -> str:
        call_count["n"] += 1
        return heuristic_offline_response(prompt)

    provider = FakeLLMProvider(response_fn=counting_heuristic)

    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, settings, provider=provider, fuzz_config=fuzz_config, generator_config=generator_config
    )

    assert call_count["n"] == 1
    assert summary.total_executed > 0  # deterministic fuzzing still ran for every endpoint
