"""
Integration-level tests for app.analyzer.analyzer.analyze() — combining
status, timing, body, and error-signature analysis together, including
the phase spec's own worked examples (sections 29-31) verified exactly.
"""

from __future__ import annotations

from app.analyzer.analyzer import analyze
from app.analyzer.models import AnalysisConfig, AnomalyType
from app.fuzzer.mutations.models import Mutation, MutationType
from app.runner.models import TestResult
from tests.analyzer_helpers import analyze_pair


def _result(status_code=None, body=None, body_is_json=False, body_size=None, response_time_ms=None):
    return TestResult(
        status_code=status_code, body=body, body_is_json=body_is_json, body_size=body_size, response_time_ms=response_time_ms
    )


# ---------------------------------------------------------------------------
# Phase spec's own worked examples
# ---------------------------------------------------------------------------


def test_worked_example_unexpected_server_error_with_signature():
    """Section 29: POST /users, age=-1 mutation, baseline 201 -> 500
    with a traceback in the body. Expected observations: status_changed,
    unexpected_server_error, response_structure_changed (different
    shape entirely: {id,name} -> {error}), error_signature_detected.
    Explicitly NOT a severity label."""
    baseline = _result(status_code=201, body={"id": 101, "name": "Alice"}, body_is_json=True, body_size=30, response_time_ms=45)
    mutation_result = _result(
        status_code=500, body={"error": "Traceback (most recent call last): ..."}, body_is_json=True, body_size=340, response_time_ms=48
    )
    mutation = Mutation(mutation_type=MutationType.NEGATIVE, location="body.age", field_name="age", original_value=25, mutated_value=-1)

    analysis = analyze(baseline, mutation, mutation_result, "POST /users")

    anomaly_types = {a.type for a in analysis.anomalies}
    assert AnomalyType.STATUS_CHANGED in anomaly_types
    assert AnomalyType.UNEXPECTED_SERVER_ERROR in anomaly_types
    assert AnomalyType.RESPONSE_STRUCTURE_CHANGED in anomaly_types
    assert AnomalyType.ERROR_SIGNATURE_DETECTED in anomaly_types
    # No severity/confidence field exists anywhere on the model at all.
    assert not hasattr(analysis, "severity")
    assert not hasattr(analysis, "confidence")


def test_worked_example_id_mutation_status_change_only():
    """Section 30: GET /users/123 -> 200/45ms baseline, id=-1 mutation
    -> 404/42ms. Expected: ONLY status_changed (+ the categorical
    unexpected_client_error label) — explicitly NOT a vulnerability,
    no timing anomaly (42ms vs 45ms is negligible)."""
    baseline = _result(status_code=200, response_time_ms=45)
    mutation_result = _result(status_code=404, response_time_ms=42)
    mutation = Mutation(mutation_type=MutationType.NEGATIVE, location="path.id", field_name="id", original_value=123, mutated_value=-1)

    analysis = analyze(baseline, mutation, mutation_result, "GET /users/{id}")

    anomaly_types = {a.type for a in analysis.anomalies}
    assert anomaly_types == {AnomalyType.STATUS_CHANGED, AnomalyType.UNEXPECTED_CLIENT_ERROR}
    assert analysis.response_time_changed is False


def test_worked_example_sql_injection_style_mutation():
    """Section 31: GET /users/123 -> 200/50ms baseline, id="'" mutation
    -> 500/3100ms with 'SQL syntax' in the body. Expected: status_changed,
    unexpected_server_error, timing_anomaly, error_signature_detected."""
    baseline = _result(status_code=200, response_time_ms=50, body={"id": 123}, body_is_json=True, body_size=20)
    mutation_result = _result(
        status_code=500,
        response_time_ms=3100,
        body={"error": "You have an error in your SQL syntax"},
        body_is_json=True,
        body_size=60,
    )
    mutation = Mutation(mutation_type=MutationType.SPECIAL_CHARACTERS, location="path.id", field_name="id", original_value=123, mutated_value="'")

    analysis = analyze(baseline, mutation, mutation_result, "GET /users/{id}")

    anomaly_types = {a.type for a in analysis.anomalies}
    assert AnomalyType.STATUS_CHANGED in anomaly_types
    assert AnomalyType.UNEXPECTED_SERVER_ERROR in anomaly_types
    assert AnomalyType.TIMING_ANOMALY in anomaly_types
    assert AnomalyType.ERROR_SIGNATURE_DETECTED in anomaly_types


# ---------------------------------------------------------------------------
# Error signature: only NEW signatures are flagged
# ---------------------------------------------------------------------------


def test_signature_already_present_in_baseline_is_not_flagged_as_new():
    """If the baseline's own normal response already contains the word
    'error' in a legitimate field, that's not evidence that THIS
    mutation caused anything — only a signature that's new relative to
    the baseline counts."""
    baseline = _result(status_code=200, body={"error_log_url": "https://example.com/internal server error page"}, body_is_json=True, body_size=60)
    mutation_result = _result(status_code=200, body={"error_log_url": "https://example.com/internal server error page"}, body_is_json=True, body_size=60)
    analysis = analyze_pair(baseline, mutation_result)
    assert not any(a.type == AnomalyType.ERROR_SIGNATURE_DETECTED for a in analysis.anomalies)


def test_signature_new_in_mutation_is_flagged():
    baseline = _result(status_code=200, body={"ok": True}, body_is_json=True, body_size=10)
    mutation_result = _result(status_code=500, body={"error": "Traceback: ..."}, body_is_json=True, body_size=30)
    analysis = analyze_pair(baseline, mutation_result)
    assert any(a.type == AnomalyType.ERROR_SIGNATURE_DETECTED for a in analysis.anomalies)


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_analysis_is_deterministic():
    baseline = _result(status_code=201, body={"id": 1, "name": "Alice"}, body_is_json=True, body_size=30, response_time_ms=45)
    mutation_result = _result(status_code=500, body={"error": "Traceback"}, body_is_json=True, body_size=100, response_time_ms=3000)
    mutation = Mutation(mutation_type=MutationType.NEGATIVE, location="body.age", field_name="age", original_value=25, mutated_value=-1)

    first = analyze(baseline, mutation, mutation_result, "POST /users")
    second = analyze(baseline, mutation, mutation_result, "POST /users")

    assert first.model_dump() == second.model_dump()


# ---------------------------------------------------------------------------
# Traceability
# ---------------------------------------------------------------------------


def test_analysis_result_retains_full_mutation_and_baseline_relationship():
    mutation = Mutation(mutation_type=MutationType.MISSING_FIELD, location="body.username", field_name="username", original_value="alice", mutated_value=None)
    analysis = analyze_pair(_result(status_code=201), _result(status_code=422), mutation=mutation)
    assert analysis.baseline_key == "POST /example"
    assert analysis.mutation.mutation_type == MutationType.MISSING_FIELD
    assert analysis.mutation.location == "body.username"
    assert analysis.mutation.original_value == "alice"
