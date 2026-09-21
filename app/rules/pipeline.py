"""
Wires Phase 3/4/6's stored results through Phase 5's analyzer and this
phase's rule engine to produce a deduplicated Finding list.

Deliberately calls app.analyzer.analyzer.analyze() directly here
(rather than consuming app.analyzer.pipeline.analyze_fuzzing_results'
pre-computed output) so each RuleContext can carry both the
AnalysisResult AND the original MutationResult (for source/reason/
TestResult.request) together, without an error-prone zip-by-position
between two separately-produced lists. app/analyzer/pipeline.py itself
is untouched — this is additive, not a rewrite.
"""

from __future__ import annotations

from typing import Optional

from app.analyzer.analyzer import analyze
from app.analyzer.models import AnalysisConfig
from app.fuzzer.baseline import BaselineStore
from app.fuzzer.mutation_runner import MutationResult
from app.rules.engine import RuleEngine, default_rule_engine, deduplicate_findings
from app.rules.models import Finding
from app.rules.rule import RuleContext


def evaluate_fuzzing_results(
    baseline_store: BaselineStore,
    results_by_endpoint: dict[str, list[MutationResult]],
    rule_engine: Optional[RuleEngine] = None,
    analysis_config: Optional[AnalysisConfig] = None,
) -> list[Finding]:
    rule_engine = rule_engine or default_rule_engine()
    analysis_config = analysis_config or AnalysisConfig()

    all_findings: list[Finding] = []

    for key, mutation_results in results_by_endpoint.items():
        method, path = key.split(" ", 1)
        baseline = baseline_store.get(method, path)
        if baseline is None:
            # Shouldn't normally happen — the fuzzing pass only produces
            # results for endpoints it already found a usable baseline
            # for — but reloaded/hand-built data shouldn't crash this,
            # same defensive stance as app/analyzer/pipeline.py.
            continue

        for mutation_result in mutation_results:
            analysis = analyze(
                baseline.result, mutation_result.mutation, mutation_result.result, mutation_result.baseline_key, analysis_config
            )
            context = RuleContext(
                baseline_key=mutation_result.baseline_key,
                endpoint=path,
                method=method,
                mutation=mutation_result.mutation,
                source=mutation_result.source,
                reason=mutation_result.reason,
                llm_confidence=mutation_result.confidence,
                analysis=analysis,
                baseline_result=baseline.result,
                mutation_result=mutation_result.result,
            )
            all_findings.extend(rule_engine.evaluate(context))

    return deduplicate_findings(all_findings)
