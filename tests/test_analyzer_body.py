"""Tests for body/structure/size analysis in app.analyzer.analyzer."""

from __future__ import annotations

from app.analyzer.models import AnalysisConfig, AnomalyType
from app.runner.models import TestResult
from tests.analyzer_helpers import analyze_pair


def _result(body=None, body_is_json=False, body_size=None):
    return TestResult(status_code=200, body=body, body_is_json=body_is_json, body_size=body_size)


def test_identical_body_no_change():
    body = {"id": 1, "name": "Alice"}
    analysis = analyze_pair(
        _result(body=body, body_is_json=True, body_size=20), _result(body=dict(body), body_is_json=True, body_size=20)
    )
    assert analysis.body_changed is False
    assert analysis.body_size_changed is False
    assert analysis.body_structure_changed is False
    assert analysis.anomalies == []


def test_different_body_same_structure_and_size_flags_generic_body_changed():
    """Same keys, same size, different value — should only fire the
    generic RESPONSE_BODY_CHANGED, not structure or size (neither
    actually changed)."""
    analysis = analyze_pair(
        _result(body={"id": 1, "name": "Alice"}, body_is_json=True, body_size=20),
        _result(body={"id": 1, "name": "Bobby"}, body_is_json=True, body_size=20),
    )
    assert analysis.body_changed is True
    assert analysis.body_size_changed is False
    assert analysis.body_structure_changed is False
    assert [a.type for a in analysis.anomalies] == [AnomalyType.RESPONSE_BODY_CHANGED]


def test_empty_to_nonempty_body():
    analysis = analyze_pair(_result(body=None, body_size=0), _result(body={"error": "bad"}, body_is_json=True, body_size=17))
    assert analysis.body_changed is True
    assert analysis.body_size_changed is True


def test_json_to_text_flags_structure_changed():
    analysis = analyze_pair(
        _result(body={"id": 1}, body_is_json=True, body_size=8),
        _result(body="plain text error", body_is_json=False, body_size=16),
    )
    assert any(a.type == AnomalyType.RESPONSE_STRUCTURE_CHANGED for a in analysis.anomalies)
    evidence = next(a for a in analysis.anomalies if a.type == AnomalyType.RESPONSE_STRUCTURE_CHANGED).evidence
    assert evidence == {"baseline_is_json": True, "mutation_is_json": False}


def test_json_structure_changes_extra_key():
    analysis = analyze_pair(
        _result(body={"id": 1, "name": "Alice"}, body_is_json=True, body_size=25),
        _result(body={"id": 1, "name": "Alice", "debug": "trace"}, body_is_json=True, body_size=45),
    )
    structure_anomalies = [a for a in analysis.anomalies if a.type == AnomalyType.RESPONSE_STRUCTURE_CHANGED]
    assert len(structure_anomalies) == 1
    assert structure_anomalies[0].evidence["baseline_keys"] == ["id", "name"]
    assert structure_anomalies[0].evidence["mutation_keys"] == ["debug", "id", "name"]


def test_json_structure_changes_missing_key():
    analysis = analyze_pair(
        _result(body={"id": 1, "name": "Alice", "email": "a@x.com"}, body_is_json=True, body_size=40),
        _result(body={"id": 1, "name": "Alice"}, body_is_json=True, body_size=20),
    )
    assert any(a.type == AnomalyType.RESPONSE_STRUCTURE_CHANGED for a in analysis.anomalies)


# ---------------------------------------------------------------------------
# Body size
# ---------------------------------------------------------------------------


def test_same_size_not_flagged():
    analysis = analyze_pair(_result(body="abc", body_size=3), _result(body="xyz", body_size=3))
    assert analysis.body_size_changed is False


def test_increased_size_flagged():
    analysis = analyze_pair(_result(body="a", body_size=1), _result(body="a" * 500, body_size=500))
    assert analysis.body_size_changed is True
    size_anomaly = next(a for a in analysis.anomalies if a.type == AnomalyType.RESPONSE_SIZE_CHANGED)
    assert size_anomaly.evidence["difference_bytes"] == 499


def test_decreased_size_flagged():
    analysis = analyze_pair(_result(body="a" * 500, body_size=500), _result(body="a", body_size=1))
    assert analysis.body_size_changed is True
    size_anomaly = next(a for a in analysis.anomalies if a.type == AnomalyType.RESPONSE_SIZE_CHANGED)
    assert size_anomaly.evidence["difference_bytes"] == -499


def test_tiny_size_difference_below_threshold_not_flagged():
    analysis = analyze_pair(_result(body="a" * 100, body_size=100), _result(body="a" * 103, body_size=103))
    assert analysis.body_size_changed is False  # default threshold is 10 bytes


def test_size_threshold_is_configurable():
    config = AnalysisConfig(min_body_size_difference_bytes=1)
    analysis = analyze_pair(_result(body="a", body_size=100), _result(body="ab", body_size=103), config=config)
    assert analysis.body_size_changed is True


def test_missing_size_on_either_side_not_flagged():
    analysis = analyze_pair(_result(body="a", body_size=None), _result(body="a" * 500, body_size=500))
    assert analysis.body_size_changed is False
