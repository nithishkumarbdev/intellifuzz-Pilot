"""Tests for app.rules.models / the _stable_finding_id helper in rules.py."""

from __future__ import annotations

import json

from app.rules.rules import _stable_finding_id
from tests.rules_helpers import make_context, make_mutation, make_result


def test_stable_finding_id_is_deterministic():
    id1 = _stable_finding_id("INPUT-001", "POST /users", "body.age", -1)
    id2 = _stable_finding_id("INPUT-001", "POST /users", "body.age", -1)
    assert id1 == id2


def test_stable_finding_id_differs_for_different_values():
    id1 = _stable_finding_id("INPUT-001", "POST /users", "body.age", -1)
    id2 = _stable_finding_id("INPUT-001", "POST /users", "body.age", -999)
    assert id1 != id2


def test_stable_finding_id_differs_for_different_rules():
    id1 = _stable_finding_id("INPUT-001", "POST /users", "body.age", -1)
    id2 = _stable_finding_id("AUTH-001", "POST /users", "body.age", -1)
    assert id1 != id2


def test_finding_serializes_to_json_cleanly():
    from app.rules.rules import UnexpectedServerErrorRule

    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)
    context = make_context(baseline, mutation_result, make_mutation(location="body.age", mutated_value=-1))
    finding = UnexpectedServerErrorRule().evaluate(context)

    dumped = finding.model_dump(mode="json")
    reserialized = json.dumps(dumped)  # must not raise — every value plain JSON-safe
    assert json.loads(reserialized)["severity"] == "low"
    assert json.loads(reserialized)["rule_id"] == "INPUT-001"


def test_finding_has_all_traceability_fields():
    """endpoint -> baseline -> mutation -> mutated request -> response
    -> rule, per the phase's own explicit traceability requirement."""
    from app.rules.rules import UnexpectedServerErrorRule

    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)
    mutation = make_mutation(location="body.age", original_value=25, mutated_value=-1)
    context = make_context(baseline, mutation_result, mutation, baseline_key="POST /users", endpoint="/users", method="POST")
    finding = UnexpectedServerErrorRule().evaluate(context)

    assert finding.endpoint == "/users"
    assert finding.method == "POST"
    assert finding.baseline_key == "POST /users"
    assert finding.mutation_location == "body.age"
    assert finding.evidence.baseline_status == 201
    assert finding.evidence.mutation_status == 500
    assert finding.reproduction.mutation_value == -1
    assert finding.rule_id == "INPUT-001"
