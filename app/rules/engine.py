"""
The rule engine: a small registry of SecurityRules, run against one
RuleContext at a time, plus deterministic deduplication across many
findings.

Deliberately not a "framework" — no plugin discovery, no dynamic
loading, no rule priorities or conflict resolution. A plain list is
enough for five rules, and stays easy to extend by just adding another
SecurityRule subclass to default_rules().
"""

from __future__ import annotations

from typing import Optional

from app.rules.models import Finding
from app.rules.rule import RuleContext, SecurityRule
from app.rules.rules import (
    AuthEnforcementRegressionRule,
    AuthorizationBoundaryRule,
    BehaviorInconsistencyRule,
    SensitiveDataExposureRule,
    UnexpectedServerErrorRule,
)


def default_rules() -> list[SecurityRule]:
    return [
        UnexpectedServerErrorRule(),
        AuthEnforcementRegressionRule(),
        AuthorizationBoundaryRule(),
        SensitiveDataExposureRule(),
        BehaviorInconsistencyRule(),
    ]


class RuleEngine:
    def __init__(self, rules: Optional[list[SecurityRule]] = None):
        self._rules = rules if rules is not None else default_rules()

    def evaluate(self, context: RuleContext) -> list[Finding]:
        findings = []
        for rule in self._rules:
            finding = rule.evaluate(context)
            if finding is not None:
                findings.append(finding)
        return findings


def default_rule_engine() -> RuleEngine:
    return RuleEngine(default_rules())


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Multiple mutations at the same location often trigger the same
    underlying rule (quantity=-1, quantity=-999, quantity=999999999 all
    producing the same unexpected-5xx pattern) — collapse those into one
    representative finding rather than flooding the report. Keyed on
    (endpoint, rule_id, mutation location) — deliberately NOT on the
    specific mutated value, per the phase's own instruction. Keeps the
    first occurrence encountered (deterministic order), same convention
    Phase 6's mutation-level dedup already uses.
    """
    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = (finding.baseline_key, finding.rule_id, finding.mutation_location)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped
