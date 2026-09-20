"""
Wires the analyzer (analyzer.py) to the existing baseline/mutation
storage — the only place in Phase 5 that connects "where do baseline
and mutation results live" to "run the comparison". No new execution,
no new HTTP calls: this consumes results Phase 3/4 already produced
(fresh or reloaded from JSON — see examples/demo_analysis.py).
"""

from __future__ import annotations

from typing import Optional

from app.analyzer.analyzer import analyze
from app.analyzer.models import AnalysisConfig, AnalysisResult
from app.fuzzer.baseline import BaselineStore
from app.fuzzer.mutation_runner import MutationResult


def analyze_fuzzing_results(
    baseline_store: BaselineStore,
    results_by_endpoint: dict[str, list[MutationResult]],
    config: Optional[AnalysisConfig] = None,
) -> dict[str, list[AnalysisResult]]:
    """
    For every mutation result, look up its baseline (by the same
    "METHOD path" key BaselineStore and the mutation runner both use)
    and run the analyzer. Results for an endpoint whose baseline can't
    be found are skipped rather than raising — shouldn't normally
    happen since run_fuzzing_pass only produces results for endpoints
    it already found a usable baseline for, but reloaded/hand-built
    data shouldn't be able to crash this.
    """
    config = config or AnalysisConfig()
    analysis_by_endpoint: dict[str, list[AnalysisResult]] = {}

    for key, mutation_results in results_by_endpoint.items():
        method, path = key.split(" ", 1)
        baseline = baseline_store.get(method, path)
        if baseline is None:
            continue
        analysis_by_endpoint[key] = [
            analyze(baseline.result, mr.mutation, mr.result, mr.baseline_key, config) for mr in mutation_results
        ]

    return analysis_by_endpoint
