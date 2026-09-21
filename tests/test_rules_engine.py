"""Tests for app.rules.engine."""

from __future__ import annotations

from app.fuzzer.mutations.models import MutationType
from app.rules.engine import RuleEngine, default_rule_engine, default_rules, deduplicate_findings
from app.rules.rule import SecurityRule
from tests.rules_helpers import make_context, make_mutation, make_result


def test_default_rules_returns_all_five():
    rules = default_rules()
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"INPUT-001", "AUTH-001", "AUTHZ-001", "DATA-001", "BEHAVIOR-001"}


def test_default_rule_engine_uses_default_rules():
    engine = default_rule_engine()
    assert len(engine._rules) == 5


def test_engine_runs_all_rules_and_collects_every_match():
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)
    context = make_context(baseline, mutation_result, make_mutation(location="body.age", mutated_value=-1))

    engine = default_rule_engine()
    findings = engine.evaluate(context)
    assert [f.rule_id for f in findings] == ["INPUT-001"]  # only the matching rule fires


def test_engine_with_empty_rule_list_produces_nothing():
    engine = RuleEngine(rules=[])
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=500)
    context = make_context(baseline, mutation_result, make_mutation())
    assert engine.evaluate(context) == []


def test_engine_with_custom_rule_list():
    class AlwaysFiresRule(SecurityRule):
        rule_id = "CUSTOM-001"
        title = "Always fires"

        def evaluate(self, context):
            from app.rules.rules import _build_finding
            from app.rules.models import Confidence, FindingCategory, Severity

            return _build_finding(
                context, self.rule_id, self.title, "test", FindingCategory.BEHAVIOR_INCONSISTENCY, Severity.INFO, Confidence.LOW
            )

    engine = RuleEngine(rules=[AlwaysFiresRule()])
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=200)
    context = make_context(baseline, mutation_result, make_mutation())
    findings = engine.evaluate(context)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM-001"


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _finding_for(mutated_value):
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)
    mutation = make_mutation(mutation_type=MutationType.NEGATIVE, location="body.quantity", mutated_value=mutated_value)
    context = make_context(baseline, mutation_result, mutation)
    return default_rule_engine().evaluate(context)[0]


def test_dedup_collapses_same_rule_same_location_different_values():
    """quantity=-1, quantity=-999, quantity=999999999 should all
    collapse into one finding, per the phase's own explicit example."""
    findings = [_finding_for(-1), _finding_for(-999), _finding_for(999_999_999)]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1


def test_dedup_keeps_different_locations_distinct():
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)

    finding_a = default_rule_engine().evaluate(
        make_context(baseline, mutation_result, make_mutation(location="body.quantity", mutated_value=-1))
    )[0]
    finding_b = default_rule_engine().evaluate(
        make_context(baseline, mutation_result, make_mutation(location="body.price", mutated_value=-1))
    )[0]

    deduped = deduplicate_findings([finding_a, finding_b])
    assert len(deduped) == 2


def test_dedup_keeps_different_endpoints_distinct():
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)

    finding_a = default_rule_engine().evaluate(
        make_context(baseline, mutation_result, make_mutation(), baseline_key="POST /orders", endpoint="/orders")
    )[0]
    finding_b = default_rule_engine().evaluate(
        make_context(baseline, mutation_result, make_mutation(), baseline_key="POST /users", endpoint="/users")
    )[0]

    deduped = deduplicate_findings([finding_a, finding_b])
    assert len(deduped) == 2


def test_dedup_keeps_different_rules_at_same_location_distinct():
    baseline = make_result(status_code=401)
    mutation_result_auth = make_result(status_code=200)
    mutation_result_5xx = make_result(status_code=500)
    mutation = make_mutation(location="query.debug", mutated_value="true")

    auth_finding = default_rule_engine().evaluate(make_context(baseline, mutation_result_auth, mutation))
    input_finding = default_rule_engine().evaluate(
        make_context(make_result(status_code=200), mutation_result_5xx, mutation)
    )

    deduped = deduplicate_findings(auth_finding + input_finding)
    assert {f.rule_id for f in deduped} == {"AUTH-001", "INPUT-001"}


def test_dedup_preserves_order_keeping_first_occurrence():
    findings = [_finding_for(-1), _finding_for(-2), _finding_for(-3)]
    deduped = deduplicate_findings(findings)
    assert deduped[0].reproduction.mutation_value == -1  # the FIRST one seen is kept
