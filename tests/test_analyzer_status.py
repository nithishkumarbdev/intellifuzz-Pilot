"""Tests for status/category/auth/redirect logic in app.analyzer.analyzer."""

from __future__ import annotations

from app.analyzer.analyzer import categorize_status
from app.analyzer.models import AnomalyType, StatusCategory
from app.fuzzer.mutations.models import Mutation, MutationType
from app.runner.models import ErrorInfo, TestResult
from tests.analyzer_helpers import analyze_pair


def _result(status_code=None, error=None, headers=None):
    return TestResult(status_code=status_code, error=error, headers=headers or {})


# ---------------------------------------------------------------------------
# Status categorization
# ---------------------------------------------------------------------------


def test_categorize_2xx():
    assert categorize_status(_result(status_code=200)) == StatusCategory.SUCCESS


def test_categorize_3xx():
    assert categorize_status(_result(status_code=302)) == StatusCategory.REDIRECT


def test_categorize_4xx():
    assert categorize_status(_result(status_code=404)) == StatusCategory.CLIENT_ERROR


def test_categorize_5xx():
    assert categorize_status(_result(status_code=500)) == StatusCategory.SERVER_ERROR


def test_categorize_timeout():
    result = _result(error=ErrorInfo(type="timeout", message="timed out"))
    assert categorize_status(result) == StatusCategory.TIMEOUT


def test_categorize_network_error():
    result = _result(error=ErrorInfo(type="connection_error", message="refused"))
    assert categorize_status(result) == StatusCategory.NETWORK_ERROR


def test_categorize_unknown_when_no_status_and_no_error():
    assert categorize_status(_result()) == StatusCategory.UNKNOWN


# ---------------------------------------------------------------------------
# Status change detection (the required 200 -> X matrix)
# ---------------------------------------------------------------------------


def test_same_status_no_change():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=200))
    assert analysis.status_changed is False
    assert not any(a.type == AnomalyType.STATUS_CHANGED for a in analysis.anomalies)


def test_200_to_400():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=400))
    assert analysis.status_changed is True
    assert any(a.type == AnomalyType.STATUS_CHANGED for a in analysis.anomalies)
    assert any(a.type == AnomalyType.UNEXPECTED_CLIENT_ERROR for a in analysis.anomalies)


def test_200_to_401_flags_auth_change():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=401))
    assert any(a.type == AnomalyType.AUTHENTICATION_BEHAVIOR_CHANGED for a in analysis.anomalies)


def test_200_to_403_flags_auth_change():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=403))
    assert any(a.type == AnomalyType.AUTHENTICATION_BEHAVIOR_CHANGED for a in analysis.anomalies)


def test_401_to_200_also_flags_auth_change():
    """The reverse direction matters too — a mutation that REMOVES an
    auth requirement is just as much an authentication behavior change
    as one that adds one."""
    analysis = analyze_pair(_result(status_code=401), _result(status_code=200))
    assert any(a.type == AnomalyType.AUTHENTICATION_BEHAVIOR_CHANGED for a in analysis.anomalies)


def test_200_to_404():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=404))
    assert analysis.status_changed is True
    assert any(a.type == AnomalyType.UNEXPECTED_CLIENT_ERROR for a in analysis.anomalies)
    # 404 is not an auth status — must not also fire auth change.
    assert not any(a.type == AnomalyType.AUTHENTICATION_BEHAVIOR_CHANGED for a in analysis.anomalies)


def test_200_to_500_flags_unexpected_server_error():
    analysis = analyze_pair(_result(status_code=200), _result(status_code=500))
    assert any(a.type == AnomalyType.UNEXPECTED_SERVER_ERROR for a in analysis.anomalies)


def test_500_baseline_to_500_mutation_is_not_unexpected():
    """If the baseline ITSELF was already a 500 (an unstable/broken
    baseline), the mutation producing another 500 is not a NEW
    observation — nothing changed."""
    analysis = analyze_pair(_result(status_code=500), _result(status_code=500))
    assert analysis.status_changed is False
    assert not any(a.type == AnomalyType.UNEXPECTED_SERVER_ERROR for a in analysis.anomalies)


# ---------------------------------------------------------------------------
# Redirect
# ---------------------------------------------------------------------------


def test_redirect_change_detected_with_location():
    analysis = analyze_pair(
        _result(status_code=200), _result(status_code=302, headers={"location": "/login"})
    )
    redirect_anomalies = [a for a in analysis.anomalies if a.type == AnomalyType.REDIRECT_CHANGED]
    assert len(redirect_anomalies) == 1
    assert redirect_anomalies[0].evidence["location"] == "/login"


def test_no_redirect_anomaly_when_baseline_was_already_a_redirect():
    analysis = analyze_pair(_result(status_code=301), _result(status_code=302))
    assert not any(a.type == AnomalyType.REDIRECT_CHANGED for a in analysis.anomalies)


# ---------------------------------------------------------------------------
# Network errors / timeouts as structured observations
# ---------------------------------------------------------------------------


def test_timeout_result_produces_request_timeout_anomaly_no_status_comparison():
    analysis = analyze_pair(
        _result(status_code=200), _result(error=ErrorInfo(type="timeout", message="Request timed out"))
    )
    assert analysis.mutation_status is None
    assert analysis.mutation_status_category == StatusCategory.TIMEOUT
    timeout_anomalies = [a for a in analysis.anomalies if a.type == AnomalyType.REQUEST_TIMEOUT]
    assert len(timeout_anomalies) == 1
    assert analysis.status_changed is True


def test_connection_error_produces_network_error_anomaly():
    analysis = analyze_pair(
        _result(status_code=200), _result(error=ErrorInfo(type="connection_error", message="refused"))
    )
    assert any(a.type == AnomalyType.NETWORK_ERROR for a in analysis.anomalies)
    assert not any(a.type == AnomalyType.REQUEST_TIMEOUT for a in analysis.anomalies)
