"""
Tests for app.rules.rules — every rule, both directions: the pattern
it SHOULD catch, and cases specifically designed to make sure it
DOESN'T over-fire. The false-positive-resistance tests matter as much
as the detection tests here, per the phase's own explicit instruction.
"""

from __future__ import annotations

from app.fuzzer.mutations.models import MutationType
from app.rules.models import Confidence, FindingCategory, Severity
from app.rules.rules import (
    AuthEnforcementRegressionRule,
    AuthorizationBoundaryRule,
    BehaviorInconsistencyRule,
    SensitiveDataExposureRule,
    UnexpectedServerErrorRule,
)
from tests.rules_helpers import make_context, make_mutation, make_result

# ---------------------------------------------------------------------------
# Rule A — INPUT-001 (UnexpectedServerErrorRule)
# ---------------------------------------------------------------------------


def test_input_001_fires_on_baseline_success_mutation_5xx():
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(status_code=500, body_is_json=True, body_size=30)
    mutation = make_mutation(mutation_type=MutationType.NEGATIVE, location="body.age", mutated_value=-1)
    context = make_context(baseline, mutation_result, mutation)

    finding = UnexpectedServerErrorRule().evaluate(context)
    assert finding is not None
    assert finding.rule_id == "INPUT-001"
    assert finding.category == FindingCategory.INPUT_HANDLING
    assert finding.severity == Severity.LOW  # no error signature -> LOW
    assert finding.confidence == Confidence.LOW


def test_input_001_severity_bumped_when_error_signature_present():
    baseline = make_result(status_code=201, body_is_json=True, body_size=20)
    mutation_result = make_result(
        status_code=500, body={"error": "Traceback (most recent call last)"}, body_is_json=True, body_size=60
    )
    mutation = make_mutation(mutation_type=MutationType.NEGATIVE, location="body.age", mutated_value=-1)
    context = make_context(baseline, mutation_result, mutation)

    finding = UnexpectedServerErrorRule().evaluate(context)
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == Confidence.MEDIUM
    assert "Traceback" in finding.evidence.details["matched_patterns"]


def test_input_001_does_not_fire_when_baseline_itself_unhealthy():
    """A 500 baseline making another 500 isn't a NEW observation."""
    baseline = make_result(status_code=500)
    mutation_result = make_result(status_code=500)
    mutation = make_mutation()
    context = make_context(baseline, mutation_result, mutation)
    assert UnexpectedServerErrorRule().evaluate(context) is None


def test_input_001_does_not_fire_on_4xx():
    """A 400 rejection is normal, expected behavior for malformed
    input — must never be confused with a 500."""
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=400)
    mutation = make_mutation()
    context = make_context(baseline, mutation_result, mutation)
    assert UnexpectedServerErrorRule().evaluate(context) is None


def test_input_001_title_never_claims_confirmed_vulnerability():
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=500)
    context = make_context(baseline, mutation_result, make_mutation())
    finding = UnexpectedServerErrorRule().evaluate(context)
    assert finding.title.startswith("Potential")
    for banned in ("confirmed", "Confirmed", "CRITICAL", "compromised"):
        assert banned not in finding.title
        assert banned not in finding.description


# ---------------------------------------------------------------------------
# Rule B — AUTH-001 (AuthEnforcementRegressionRule)
# ---------------------------------------------------------------------------


def test_auth_001_fires_on_401_baseline_success_mutation():
    baseline = make_result(status_code=401)
    mutation_result = make_result(status_code=200, body={"data": "protected"}, body_is_json=True)
    mutation = make_mutation(location="query.role", mutated_value="admin")
    context = make_context(baseline, mutation_result, mutation)

    finding = AuthEnforcementRegressionRule().evaluate(context)
    assert finding is not None
    assert finding.rule_id == "AUTH-001"
    assert finding.category == FindingCategory.AUTHENTICATION
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.MEDIUM


def test_auth_001_fires_on_403_baseline_too():
    baseline = make_result(status_code=403)
    mutation_result = make_result(status_code=201)
    context = make_context(baseline, mutation_result, make_mutation())
    assert AuthEnforcementRegressionRule().evaluate(context) is not None


def test_auth_001_does_not_fire_when_mutation_still_rejected():
    """The rule requires the mutation to SUCCEED — a 401 baseline that
    stays 401 (or becomes 403/400) is exactly correct behavior."""
    baseline = make_result(status_code=401)
    mutation_result = make_result(status_code=401)
    context = make_context(baseline, mutation_result, make_mutation())
    assert AuthEnforcementRegressionRule().evaluate(context) is None


def test_auth_001_does_not_fire_when_baseline_was_never_auth_gated():
    """A baseline that was already 200 succeeding again isn't an
    'auth enforcement' signal — that's just normal, unrelated behavior."""
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=200)
    context = make_context(baseline, mutation_result, make_mutation())
    assert AuthEnforcementRegressionRule().evaluate(context) is None


def test_auth_001_never_includes_real_credentials_in_evidence():
    baseline = make_result(status_code=401, headers={"authorization": "***MASKED***"})
    mutation_result = make_result(status_code=200, headers={"authorization": "***MASKED***"})
    context = make_context(baseline, mutation_result, make_mutation())
    finding = AuthEnforcementRegressionRule().evaluate(context)
    assert "***MASKED***" not in str(finding.evidence.details)  # nothing credential-shaped leaked into evidence details


# ---------------------------------------------------------------------------
# Rule C — AUTHZ-001 (AuthorizationBoundaryRule)
# ---------------------------------------------------------------------------


def test_authz_001_fires_on_cross_resource_identifier_success():
    baseline = make_result(status_code=200, body={"id": 101}, body_is_json=True)
    mutation_result = make_result(status_code=200, body={"id": 102}, body_is_json=True)
    mutation = make_mutation(
        mutation_type=MutationType.BOUNDARY_NUMBER, location="path.user_id", original_value=101, mutated_value=102
    )
    context = make_context(baseline, mutation_result, mutation)

    finding = AuthorizationBoundaryRule().evaluate(context)
    assert finding is not None
    assert finding.rule_id == "AUTHZ-001"
    assert finding.category == FindingCategory.AUTHORIZATION
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.LOW  # can't prove it — high severity, low confidence, exactly per the phase's own example


def test_authz_001_does_not_fire_for_non_path_locations():
    """Only identifier-shaped PATH mutations count — a body or query
    field being changed isn't a 'cross-resource identifier' pattern."""
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=200)
    mutation = make_mutation(location="body.user_id", original_value=101, mutated_value=102)
    context = make_context(baseline, mutation_result, mutation)
    assert AuthorizationBoundaryRule().evaluate(context) is None


def test_authz_001_does_not_fire_when_mutation_is_rejected():
    """The whole point: if the target correctly returns 403/404 for the
    other resource, that's NOT a finding — that's the boundary working."""
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=404)
    mutation = make_mutation(location="path.user_id", original_value=101, mutated_value=999)
    context = make_context(baseline, mutation_result, mutation)
    assert AuthorizationBoundaryRule().evaluate(context) is None


def test_authz_001_does_not_fire_when_value_unchanged():
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=200)
    mutation = make_mutation(location="path.user_id", original_value=101, mutated_value=101)
    context = make_context(baseline, mutation_result, mutation)
    assert AuthorizationBoundaryRule().evaluate(context) is None


# ---------------------------------------------------------------------------
# Rule D — DATA-001 (SensitiveDataExposureRule)
# ---------------------------------------------------------------------------


def test_data_001_fires_on_new_sensitive_field_name():
    baseline = make_result(status_code=200, body={"id": 1, "name": "Alice"}, body_is_json=True, body_size=25)
    mutation_result = make_result(
        status_code=200, body={"id": 1, "name": "Alice", "api_key": "sk-abc"}, body_is_json=True, body_size=45
    )
    context = make_context(baseline, mutation_result, make_mutation())

    finding = SensitiveDataExposureRule().evaluate(context)
    assert finding is not None
    assert finding.rule_id == "DATA-001"
    assert finding.severity == Severity.HIGH
    assert finding.evidence.details["new_sensitive_field_names"] == ["api_key"]


def test_data_001_never_includes_the_actual_field_value():
    baseline = make_result(status_code=200, body={"id": 1}, body_is_json=True, body_size=10)
    mutation_result = make_result(
        status_code=200, body={"id": 1, "password": "hunter2"}, body_is_json=True, body_size=30
    )
    context = make_context(baseline, mutation_result, make_mutation())
    finding = SensitiveDataExposureRule().evaluate(context)
    assert "hunter2" not in str(finding.evidence.model_dump())
    assert "hunter2" not in finding.description


def test_data_001_does_not_fire_on_ordinary_new_field():
    baseline = make_result(status_code=200, body={"id": 1}, body_is_json=True, body_size=10)
    mutation_result = make_result(status_code=200, body={"id": 1, "nickname": "AC"}, body_is_json=True, body_size=25)
    context = make_context(baseline, mutation_result, make_mutation())
    assert SensitiveDataExposureRule().evaluate(context) is None


def test_data_001_does_not_fire_when_sensitive_field_already_in_baseline():
    """Only NEW fields count — a field already present in the baseline
    isn't something this specific mutation exposed."""
    baseline = make_result(status_code=200, body={"id": 1, "api_key": "already-there"}, body_is_json=True, body_size=30)
    mutation_result = make_result(
        status_code=200, body={"id": 1, "api_key": "already-there"}, body_is_json=True, body_size=30
    )
    context = make_context(baseline, mutation_result, make_mutation())
    assert SensitiveDataExposureRule().evaluate(context) is None


# ---------------------------------------------------------------------------
# Rule E — BEHAVIOR-001 (BehaviorInconsistencyRule)
# ---------------------------------------------------------------------------


def test_behavior_001_fires_on_missing_required_field_accepted():
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=201)
    mutation = make_mutation(mutation_type=MutationType.MISSING_FIELD, location="body.username", original_value="a")
    context = make_context(baseline, mutation_result, mutation)

    finding = BehaviorInconsistencyRule().evaluate(context)
    assert finding is not None
    assert finding.rule_id == "BEHAVIOR-001"
    assert finding.severity == Severity.LOW


def test_behavior_001_fires_on_null_accepted():
    baseline = make_result(status_code=200)
    mutation_result = make_result(status_code=200)
    mutation = make_mutation(mutation_type=MutationType.NULL, location="body.age", mutated_value=None)
    context = make_context(baseline, mutation_result, mutation)
    assert BehaviorInconsistencyRule().evaluate(context) is not None


def test_behavior_001_does_not_fire_when_rejected_correctly():
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=422)
    mutation = make_mutation(mutation_type=MutationType.NULL, location="body.age", mutated_value=None)
    context = make_context(baseline, mutation_result, mutation)
    assert BehaviorInconsistencyRule().evaluate(context) is None


def test_behavior_001_does_not_fire_for_ordinary_boundary_mutations():
    """NEGATIVE/ZERO/etc are valid-shaped values, not structurally
    invalid ones — this rule is specifically about null/missing/type-
    confused values, not every accepted boundary mutation."""
    baseline = make_result(status_code=201)
    mutation_result = make_result(status_code=201)
    mutation = make_mutation(mutation_type=MutationType.NEGATIVE, location="body.age", mutated_value=-1)
    context = make_context(baseline, mutation_result, mutation)
    assert BehaviorInconsistencyRule().evaluate(context) is None
