"""
The rule interface and its input context.

A SecurityRule only ever answers one question: "does this specific
mutation's result match my pattern?" It never executes anything, never
looks at any other mutation's result, and never raises for a
non-matching context — only Optional[Finding] out, nothing else.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from app.analyzer.models import AnalysisResult
from app.fuzzer.mutations.models import Mutation
from app.runner.models import TestResult


@dataclass
class RuleContext:
    """Everything a rule might need for one (baseline, mutation result)
    pair. Deliberately carries both the Phase 5 AnalysisResult (the
    behavioral comparison) AND the raw TestResults (for reproduction
    info via TestResult.request, which AnalysisResult doesn't carry) —
    see app/rules/pipeline.py for why both are needed rather than one
    being derivable from the other."""

    baseline_key: str
    endpoint: str
    method: str
    mutation: Mutation
    source: str  # "deterministic" | "llm"
    reason: Optional[str]  # the LLM's own rationale, if source == "llm" — never used by any rule
    llm_confidence: Optional[float]  # the LLM's own self-reported confidence — never used by any rule; see models.py's module docstring
    analysis: AnalysisResult
    baseline_result: TestResult
    mutation_result: TestResult


class SecurityRule(ABC):
    rule_id: str
    title: str

    @abstractmethod
    def evaluate(self, context: RuleContext):
        """Returns a Finding if this rule's pattern matches this
        context, else None. Must never raise for a context that simply
        doesn't match — only for genuinely malformed input, which
        indicates a bug in the caller, not in the target being tested."""
        raise NotImplementedError
