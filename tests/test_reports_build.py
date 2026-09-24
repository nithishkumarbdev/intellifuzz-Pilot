"""Tests for app.reports.build.build_report."""

from __future__ import annotations

from datetime import datetime, timezone

from app.reports.build import build_report
from app.rules.models import Confidence, Severity
from tests.reports_helpers import make_finding


def test_metadata_basic_fields():
    findings = [make_finding()]
    report = build_report(findings, target_base_url="http://x", spec_title="My API")
    assert report.metadata.project_name == "IntelliFuzz"
    assert report.metadata.target_base_url == "http://x"
    assert report.metadata.spec_title == "My API"
    assert report.metadata.total_findings == 1


def test_metadata_omits_target_when_not_given():
    report = build_report([make_finding()])
    assert report.metadata.target_base_url is None


def test_generated_at_is_injectable_for_deterministic_tests():
    fixed = datetime(2026, 3, 15, 12, 30, 0, tzinfo=timezone.utc)
    report = build_report([make_finding()], generated_at=fixed)
    assert report.metadata.generated_at == "2026-03-15T12:30:00Z"
    assert report.metadata.report_id == "report-20260315T123000"


def test_severity_counts_correct():
    findings = [
        make_finding(finding_id="F1", severity=Severity.HIGH),
        make_finding(finding_id="F2", severity=Severity.HIGH),
        make_finding(finding_id="F3", severity=Severity.LOW),
    ]
    report = build_report(findings)
    assert report.metadata.severity_counts == {"HIGH": 2, "MEDIUM": 0, "LOW": 1, "INFO": 0}


def test_rule_counts_correct():
    findings = [
        make_finding(finding_id="F1", rule_id="INPUT-001"),
        make_finding(finding_id="F2", rule_id="INPUT-001"),
        make_finding(finding_id="F3", rule_id="AUTHZ-001"),
    ]
    report = build_report(findings)
    assert report.metadata.rule_counts == {"AUTHZ-001": 1, "INPUT-001": 2}


def test_empty_findings_list_is_valid():
    report = build_report([])
    assert report.metadata.total_findings == 0
    assert report.findings == []
    assert report.metadata.severity_counts == {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}


# ---------------------------------------------------------------------------
# Deterministic ordering
# ---------------------------------------------------------------------------


def test_findings_sorted_severity_high_first():
    findings = [
        make_finding(finding_id="F-LOW", severity=Severity.LOW),
        make_finding(finding_id="F-HIGH", severity=Severity.HIGH),
        make_finding(finding_id="F-MEDIUM", severity=Severity.MEDIUM),
    ]
    report = build_report(findings)
    assert [f.finding_id for f in report.findings] == ["F-HIGH", "F-MEDIUM", "F-LOW"]


def test_findings_sorted_by_endpoint_within_same_severity():
    findings = [
        make_finding(finding_id="F1", severity=Severity.HIGH, endpoint="/zzz"),
        make_finding(finding_id="F2", severity=Severity.HIGH, endpoint="/aaa"),
    ]
    report = build_report(findings)
    assert [f.endpoint for f in report.findings] == ["/aaa", "/zzz"]


def test_findings_sorted_by_rule_id_within_same_severity_and_endpoint():
    findings = [
        make_finding(finding_id="F1", severity=Severity.HIGH, endpoint="/x", rule_id="ZZZ-001"),
        make_finding(finding_id="F2", severity=Severity.HIGH, endpoint="/x", rule_id="AAA-001"),
    ]
    report = build_report(findings)
    assert [f.rule_id for f in report.findings] == ["AAA-001", "ZZZ-001"]


def test_sorting_does_not_mutate_input_list():
    findings = [
        make_finding(finding_id="F-LOW", severity=Severity.LOW),
        make_finding(finding_id="F-HIGH", severity=Severity.HIGH),
    ]
    original_order = [f.finding_id for f in findings]
    build_report(findings)
    assert [f.finding_id for f in findings] == original_order  # unchanged
