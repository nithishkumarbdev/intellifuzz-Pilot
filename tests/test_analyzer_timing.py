"""Tests for timing analysis in app.analyzer.analyzer."""

from __future__ import annotations

from app.analyzer.models import AnalysisConfig, AnomalyType
from app.runner.models import TestResult
from tests.analyzer_helpers import analyze_pair


def _result(response_time_ms=None):
    return TestResult(status_code=200, response_time_ms=response_time_ms)


def test_negligible_change_not_flagged():
    """51ms vs 48ms — the phase's own example of what should NOT be
    flagged, despite technically being a 'change'."""
    analysis = analyze_pair(_result(48), _result(51))
    assert analysis.response_time_changed is False
    assert not any(a.type == AnomalyType.TIMING_ANOMALY for a in analysis.anomalies)


def test_significant_absolute_and_multiplier_change_flagged():
    """50ms vs 3000ms — the phase's own example of what SHOULD be
    flagged."""
    analysis = analyze_pair(_result(50), _result(3000))
    assert analysis.response_time_changed is True
    timing_anomalies = [a for a in analysis.anomalies if a.type == AnomalyType.TIMING_ANOMALY]
    assert len(timing_anomalies) == 1
    evidence = timing_anomalies[0].evidence
    assert evidence["baseline_response_time_ms"] == 50
    assert evidence["mutation_response_time_ms"] == 3000
    assert evidence["difference_ms"] == 2950
    assert evidence["ratio"] == 60.0


def test_high_ratio_but_tiny_absolute_difference_not_flagged():
    """1ms -> 5ms is a 5x multiplier but a trivially small absolute
    difference — both thresholds must clear, not just one."""
    analysis = analyze_pair(_result(1), _result(5))
    assert analysis.response_time_changed is False


def test_large_absolute_difference_but_low_ratio_not_flagged():
    """5000ms -> 5300ms is a 300ms absolute difference (clears the
    default 200ms bar) but only a ~1.06x ratio — nowhere near the
    default 3x multiplier bar, so this should NOT be flagged as a
    timing anomaly. Guards against only checking one of the two
    configured thresholds."""
    analysis = analyze_pair(_result(5000), _result(5300))
    assert analysis.response_time_changed is False


def test_missing_timing_on_either_side_produces_no_timing_anomaly():
    analysis = analyze_pair(_result(None), _result(3000))
    assert analysis.response_time_changed is False
    assert analysis.response_time_difference_ms is None
    assert not any(a.type == AnomalyType.TIMING_ANOMALY for a in analysis.anomalies)


def test_thresholds_are_configurable():
    config = AnalysisConfig(min_time_difference_ms=10, min_time_multiplier=1.5)
    analysis = analyze_pair(_result(48), _result(51), config=config)
    # Same 48->51 pair that was ignored under default thresholds should
    # now trip much more sensitive configured thresholds... but 51/48
    # is only ~1.06x, still below 1.5x, so let's use a case that clears
    # BOTH the lowered bars specifically.
    assert analysis.response_time_changed is False  # confirms ratio still gates it

    analysis2 = analyze_pair(_result(40), _result(70), config=config)  # diff=30 (>=10), ratio=1.75 (>=1.5)
    assert analysis2.response_time_changed is True


def test_zero_baseline_time_with_nonzero_mutation_time_is_flagged():
    """Edge case: baseline somehow recorded as 0ms. Ratio is undefined
    in the normal sense (division by zero) — treated as effectively
    infinite so a real mutation delay still gets flagged rather than
    crashing or being silently ignored."""
    analysis = analyze_pair(_result(0), _result(500))
    assert analysis.response_time_changed is True
    timing_anomaly = next(a for a in analysis.anomalies if a.type == AnomalyType.TIMING_ANOMALY)
    assert timing_anomaly.evidence["ratio"] is None  # infinite ratio isn't a meaningful number to report


def test_zero_baseline_and_zero_mutation_time_not_flagged():
    analysis = analyze_pair(_result(0), _result(0))
    assert analysis.response_time_changed is False
