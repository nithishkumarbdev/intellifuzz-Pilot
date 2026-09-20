"""
Wires the mutation engine (generation) to the existing HTTP runner
(execution). This is the only place that actually sends mutated
requests — mutation generation (deterministic engine or the Phase 6
LLM generator) never does I/O itself.

Also enforces run-wide safety limits: max_total_mutations across an
entire fuzzing pass, and skip_methods to keep dangerous/state-changing
methods out of a run entirely when configured. Per-field and per-
endpoint limits are already enforced inside the mutation engine.

MutationResult makes NO judgment about whether a result is
interesting, suspicious, or a vulnerability — that classification
starts in Phase 5's analyzer (behavioral observations, still no
severity) and continues in a later security-rules phase. This module
only answers "what happened", never "what does it mean".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from app.core.config import RunnerSettings
from app.fuzzer.baseline import BaselineStore
from app.fuzzer.mutations.engine import generate_mutations_for_test_case
from app.fuzzer.mutations.models import Mutation, MutatedTestCase, MutationConfig
from app.parser.models import APISpec, Endpoint
from app.runner.http_runner import execute_test_case
from app.runner.models import ErrorInfo, TestCase, TestResult
from app.runner.validation import ValidationError


@dataclass
class MutationResult:
    baseline_key: str
    mutation: Mutation
    result: TestResult
    source: str = "deterministic"  # "deterministic" | "llm" — see MutatedTestCase
    reason: Optional[str] = None
    confidence: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "baseline_key": self.baseline_key,
            "mutation": self.mutation.model_dump(),
            "result": self.result.model_dump(),
            "source": self.source,
            "reason": self.reason,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MutationResult":
        return cls(
            baseline_key=data["baseline_key"],
            mutation=Mutation.model_validate(data["mutation"]),
            result=TestResult.model_validate(data["result"]),
            source=data.get("source", "deterministic"),
            reason=data.get("reason"),
            confidence=data.get("confidence"),
        )


async def execute_mutated_test_cases(
    mutated_cases: list[MutatedTestCase],
    settings: RunnerSettings,
    client: Optional[httpx.AsyncClient] = None,
) -> list[MutationResult]:
    """
    The shared execution loop: given ANY list of already-generated
    MutatedTestCases — deterministic, LLM-origin, or a combined mix —
    execute each and return normalized results. Source-agnostic on
    purpose: this is what "the runner doesn't care where a mutation
    came from" (the generator phase's own core requirement) means in
    code — there is exactly one execution path, not two.
    """
    results: list[MutationResult] = []
    for mutated in mutated_cases:
        try:
            result = await execute_test_case(mutated.test_case, settings, client=client)
        except ValidationError as exc:
            # Mirrors baseline.py's own handling: shouldn't normally
            # happen since generation builds structurally valid cases
            # (LLM candidates are validated before ever reaching here),
            # but record it as evidence rather than crashing the run.
            result = TestResult(error=ErrorInfo(type="validation_error", message=str(exc)))
        results.append(
            MutationResult(
                baseline_key=mutated.baseline_key,
                mutation=mutated.mutation,
                result=result,
                source=mutated.source,
                reason=mutated.reason,
                confidence=mutated.confidence,
            )
        )
    return results


async def run_mutations_for_endpoint(
    endpoint: Endpoint,
    baseline_test_case: TestCase,
    settings: RunnerSettings,
    config: Optional[MutationConfig] = None,
    client: Optional[httpx.AsyncClient] = None,
    limit: Optional[int] = None,
) -> list[MutationResult]:
    config = config or MutationConfig()
    mutated_cases = generate_mutations_for_test_case(endpoint, baseline_test_case, config)
    if limit is not None:
        mutated_cases = mutated_cases[:limit]
    return await execute_mutated_test_cases(mutated_cases, settings, client=client)


async def run_fuzzing_pass(
    spec: APISpec,
    baseline_store: BaselineStore,
    settings: RunnerSettings,
    config: Optional[MutationConfig] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> dict[str, list[MutationResult]]:
    """
    Runs mutations for every endpoint that has a *successfully executed*
    baseline, in spec order, sequentially (no concurrency — same
    "correctness first" reasoning as Phases 2-3), stopping once
    max_total_mutations is reached. Returns results keyed by
    "METHOD path", matching BaselineStore's own key shape.

    Deterministic-only, unchanged since Phase 4. The LLM-aware
    counterpart (app.generator.pipeline.run_combined_fuzzing_pass)
    wraps the same building blocks (generate_mutations_for_test_case,
    execute_mutated_test_cases) rather than modifying this function.
    """
    config = config or MutationConfig()
    results_by_endpoint: dict[str, list[MutationResult]] = {}
    remaining = config.max_total_mutations

    for endpoint in spec.endpoints:
        if remaining <= 0:
            break
        if endpoint.method.upper() in config.skip_methods:
            continue

        baseline = baseline_store.get(endpoint.method, endpoint.path)
        if baseline is None or not baseline.result.executed:
            # Nothing meaningful to mutate from if the baseline itself
            # never got a response (e.g. connection error).
            continue

        key = f"{endpoint.method} {endpoint.path}"
        endpoint_results = await run_mutations_for_endpoint(
            endpoint, baseline.test_case, settings, config=config, client=client, limit=remaining
        )
        if endpoint_results:
            results_by_endpoint[key] = endpoint_results
            remaining -= len(endpoint_results)

    return results_by_endpoint
