"""Shared helper for rules tests — not a test file itself (no test_
prefix), just a convenience wrapper so each test doesn't need to
hand-build the analyze() + RuleContext boilerplate."""

from __future__ import annotations

from typing import Any, Optional

from app.analyzer.analyzer import analyze
from app.fuzzer.mutations.models import Mutation, MutationType
from app.runner.models import RequestEcho, TestResult
from app.rules.rule import RuleContext


def make_result(
    status_code: Optional[int] = None,
    body: Any = None,
    body_is_json: bool = False,
    body_size: Optional[int] = None,
    response_time_ms: Optional[float] = None,
    request_body: Any = None,
    headers: Optional[dict] = None,
    error=None,
) -> TestResult:
    return TestResult(
        status_code=status_code,
        body=body,
        body_is_json=body_is_json,
        body_size=body_size,
        response_time_ms=response_time_ms,
        error=error,
        request=RequestEcho(
            method="GET", url="http://test/endpoint", headers=headers or {}, body=request_body
        ),
    )


def make_context(
    baseline_result: TestResult,
    mutation_result: TestResult,
    mutation: Mutation,
    baseline_key: str = "GET /endpoint",
    endpoint: str = "/endpoint",
    method: str = "GET",
    source: str = "deterministic",
) -> RuleContext:
    analysis = analyze(baseline_result, mutation, mutation_result, baseline_key)
    return RuleContext(
        baseline_key=baseline_key,
        endpoint=endpoint,
        method=method,
        mutation=mutation,
        source=source,
        reason=None,
        llm_confidence=None,
        analysis=analysis,
        baseline_result=baseline_result,
        mutation_result=mutation_result,
    )


def make_mutation(
    mutation_type: MutationType = MutationType.NEGATIVE,
    location: str = "body.field",
    field_name: str = "field",
    original_value: Any = None,
    mutated_value: Any = None,
) -> Mutation:
    return Mutation(
        mutation_type=mutation_type,
        location=location,
        field_name=field_name,
        original_value=original_value,
        mutated_value=mutated_value,
    )
