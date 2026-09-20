"""Shared helper for analyzer tests — not a test file itself (no
test_ prefix), just a convenience wrapper so each test doesn't need to
hand-build a Mutation just to call analyze()."""

from __future__ import annotations

from typing import Optional

from app.analyzer.analyzer import analyze
from app.analyzer.models import AnalysisConfig, AnalysisResult
from app.fuzzer.mutations.models import Mutation, MutationType
from app.runner.models import TestResult

DUMMY_MUTATION = Mutation(
    mutation_type=MutationType.NEGATIVE,
    location="body.age",
    field_name="age",
    original_value=25,
    mutated_value=-1,
)


def analyze_pair(
    baseline_result: TestResult,
    mutation_result: TestResult,
    mutation: Mutation = DUMMY_MUTATION,
    config: Optional[AnalysisConfig] = None,
) -> AnalysisResult:
    return analyze(baseline_result, mutation, mutation_result, "POST /example", config)
