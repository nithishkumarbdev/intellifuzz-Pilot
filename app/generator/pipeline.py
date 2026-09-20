"""
The combined generation pipeline: deterministic mutations (Phase 4,
unchanged) plus, if a provider is configured, LLM-suggested candidates
— validated, deduplicated against each other, and merged into ONE
ordered list of MutatedTestCases. The runner that executes that list
(app.fuzzer.mutation_runner.execute_mutated_test_cases) doesn't know
or care which half of the list a given mutation came from.

An LLM failure at any stage (timeout, malformed JSON, provider error)
degrades this endpoint's generation to deterministic-only and records
why — it never raises out of generate_combined_mutations. This is the
concrete implementation of "the scan must not completely fail just
because the LLM is unavailable."
"""

from __future__ import annotations

import json
from typing import Optional

import httpx

from app.core.config import RunnerSettings
from app.fuzzer.baseline import BaselineStore
from app.fuzzer.mutation_runner import execute_mutated_test_cases
from app.fuzzer.mutations.engine import generate_mutations_for_test_case
from app.fuzzer.mutations.models import MutatedTestCase, MutationConfig
from app.generator.candidates import parse_llm_response, validate_candidates
from app.generator.context import build_endpoint_context
from app.generator.models import CombinedGenerationResult, CombinedScanSummary, GeneratorConfig
from app.generator.prompt import build_prompt
from app.generator.provider import LLMProvider, ProviderError
from app.parser.models import APISpec, Endpoint
from app.runner.models import TestCase


def _stable_key(baseline_key: str, mutation) -> tuple:
    try:
        normalized_value = json.dumps(mutation.mutated_value, sort_keys=True)
    except (TypeError, ValueError):
        normalized_value = repr(mutation.mutated_value)
    return (baseline_key, mutation.location, normalized_value)


def deduplicate_against(
    candidates: list[MutatedTestCase], existing: list[MutatedTestCase]
) -> tuple[list[MutatedTestCase], int]:
    """
    Removes any candidate whose (endpoint, location, mutated_value)
    already appears in `existing` — e.g. an LLM candidate proposing the
    exact same body.age=-1 the deterministic engine already generated —
    AND removes duplicates among the candidates themselves, keeping the
    first occurrence (deterministic order preserved). Returns
    (deduplicated_candidates, count_removed).
    """
    seen = {_stable_key(m.baseline_key, m.mutation) for m in existing}
    deduped: list[MutatedTestCase] = []
    removed = 0
    for candidate in candidates:
        key = _stable_key(candidate.baseline_key, candidate.mutation)
        if key in seen:
            removed += 1
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped, removed


async def generate_combined_mutations(
    endpoint: Endpoint,
    baseline_test_case: TestCase,
    provider: Optional[LLMProvider],
    fuzz_config: Optional[MutationConfig] = None,
    generator_config: Optional[GeneratorConfig] = None,
) -> CombinedGenerationResult:
    fuzz_config = fuzz_config or MutationConfig()
    generator_config = generator_config or GeneratorConfig()

    deterministic = generate_mutations_for_test_case(endpoint, baseline_test_case, fuzz_config)

    llm_accepted: list[MutatedTestCase] = []
    llm_rejected: list = []
    llm_error: Optional[str] = None

    if provider is not None:
        context = build_endpoint_context(endpoint, baseline_test_case)
        prompt = build_prompt(context, generator_config.max_candidates_per_endpoint)
        try:
            raw_text = await provider.generate(prompt, max_output_tokens=generator_config.max_output_tokens)
        except ProviderError as exc:
            llm_error = f"{type(exc).__name__}: {exc}"
        else:
            response, parse_error = parse_llm_response(raw_text)
            if parse_error is not None:
                llm_error = parse_error
            else:
                llm_accepted, llm_rejected = validate_candidates(response, endpoint, baseline_test_case, generator_config)

    deduped_llm, duplicates_removed = deduplicate_against(llm_accepted, deterministic)

    combined = (deterministic + deduped_llm)[: fuzz_config.max_mutations_per_endpoint]

    return CombinedGenerationResult(
        deterministic_count=len(deterministic),
        llm_candidate_count=len(llm_accepted) + len(llm_rejected),
        llm_accepted_count=len(deduped_llm),
        llm_rejected=llm_rejected,
        duplicates_removed=duplicates_removed,
        llm_error=llm_error,
        mutations=combined,
    )


async def run_combined_fuzzing_pass(
    spec: APISpec,
    baseline_store: BaselineStore,
    settings: RunnerSettings,
    provider: Optional[LLMProvider],
    fuzz_config: Optional[MutationConfig] = None,
    generator_config: Optional[GeneratorConfig] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> CombinedScanSummary:
    """
    The LLM-aware counterpart to
    app.fuzzer.mutation_runner.run_fuzzing_pass. Same endpoint-skip and
    max_total_mutations behavior; additionally bounds the number of LLM
    calls made across the whole run (generator_config.max_total_llm_calls)
    — once that's hit, remaining endpoints fall back to deterministic-
    only for the rest of the pass rather than making unbounded calls.
    """
    fuzz_config = fuzz_config or MutationConfig()
    generator_config = generator_config or GeneratorConfig()

    summary = CombinedScanSummary()
    remaining_total = fuzz_config.max_total_mutations
    llm_calls_made = 0

    for endpoint in spec.endpoints:
        if remaining_total <= 0:
            break
        if endpoint.method.upper() in fuzz_config.skip_methods:
            continue

        baseline = baseline_store.get(endpoint.method, endpoint.path)
        if baseline is None or not baseline.result.executed:
            continue

        use_provider = provider if (provider is not None and llm_calls_made < generator_config.max_total_llm_calls) else None
        generation = await generate_combined_mutations(
            endpoint, baseline.test_case, use_provider, fuzz_config, generator_config
        )
        if use_provider is not None:
            llm_calls_made += 1

        key = f"{endpoint.method} {endpoint.path}"
        mutated_cases = generation.mutations[:remaining_total]
        endpoint_results = await execute_mutated_test_cases(mutated_cases, settings, client=client)
        if endpoint_results:
            summary.results_by_endpoint[key] = endpoint_results
            remaining_total -= len(endpoint_results)

        summary.record(endpoint_key=key, generation=generation)

    return summary
