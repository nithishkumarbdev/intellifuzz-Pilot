"""
Wires the mutation engine (generation) to the existing HTTP runner
(execution). This is the only place in Phase 4 that actually sends
mutated requests — the engine itself never does I/O.

Also enforces run-wide safety limits: max_total_mutations across an
entire fuzzing pass, and skip_methods to keep dangerous/state-changing
methods out of a run entirely when configured. Per-field and per-
endpoint limits are already enforced inside the mutation engine.

MutationResult makes NO judgment about whether a result is
interesting, suspicious, or a vulnerability — that classification is
explicitly out of scope until Phase 7 (anomaly detection) and Phase 8
(deterministic security rules). This phase only answers "what
happened", never "what does it mean".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx

from app.core.config import RunnerSettings
from app.fuzzer.baseline import BaselineStore
from app.fuzzer.mutations.engine import generate_mutations_for_test_case
from app.fuzzer.mutations.models import Mutation, MutationConfig
from app.parser.models import APISpec, Endpoint
from app.runner.http_runner import execute_test_case
from app.runner.models import ErrorInfo, TestCase, TestResult
from app.runner.validation import ValidationError


@dataclass
class MutationResult:
    baseline_key: str
    mutation: Mutation
    result: TestResult

    def to_dict(self) -> dict:
        return {
            "baseline_key": self.baseline_key,
            "mutation": self.mutation.model_dump(),
            "result": self.result.model_dump(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MutationResult":
        return cls(
            baseline_key=data["baseline_key"],
            mutation=Mutation.model_validate(data["mutation"]),
            result=TestResult.model_validate(data["result"]),
        )


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

    results: list[MutationResult] = []
    for mutated in mutated_cases:
        try:
            result = await execute_test_case(mutated.test_case, settings, client=client)
        except ValidationError as exc:
            # Mirrors baseline.py's own handling: shouldn't normally
            # happen since the engine builds structurally valid cases,
            # but record it as evidence rather than crashing the run.
            result = TestResult(error=ErrorInfo(type="validation_error", message=str(exc)))
        results.append(MutationResult(baseline_key=mutated.baseline_key, mutation=mutated.mutation, result=result))
    return results


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
