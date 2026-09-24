"""Tests for app.reports.markdown_reporter."""

from __future__ import annotations

from app.reports.build import build_report
from app.reports.markdown_reporter import render_markdown
from app.rules.models import Severity
from tests.reports_helpers import make_finding


def test_title_exists():
    output = render_markdown(build_report([make_finding()]))
    assert output.startswith("# IntelliFuzz Security Report")


def test_summary_section_exists():
    output = render_markdown(build_report([make_finding()], target_base_url="http://x"))
    assert "## Summary" in output
    assert "http://x" in output
    assert "| Severity | Count |" in output


def test_finding_appears_with_id_and_title():
    finding = make_finding(finding_id="F-42", title="Potential something weird")
    output = render_markdown(build_report([finding]))
    assert "F-42" in output
    assert "Potential something weird" in output


def test_evidence_section_appears():
    finding = make_finding(evidence_details={"matched_patterns": ["Traceback"]})
    output = render_markdown(build_report([finding]))
    assert "#### Evidence" in output
    assert "Traceback" in output


def test_reproduction_section_appears():
    finding = make_finding(reproduction_body={"age": -1})
    output = render_markdown(build_report([finding]))
    assert "#### Reproduction" in output
    assert "body.age" in output


def test_severity_and_confidence_and_rule_shown():
    finding = make_finding(severity=Severity.HIGH, rule_id="AUTHZ-001")
    output = render_markdown(build_report([finding]))
    assert "**Severity:** HIGH" in output
    assert "**Rule:** AUTHZ-001" in output


def test_empty_report_says_no_findings_not_that_api_is_secure():
    output = render_markdown(build_report([]))
    assert "No security findings were generated." in output
    assert "secure" not in output.lower().replace("does not prove the api is secure", "")


def test_disclaimer_always_present():
    output_with = render_markdown(build_report([make_finding()]))
    output_without = render_markdown(build_report([]))
    assert "signal for human review" in output_with
    assert "signal for human review" in output_without


def test_rule_counts_table_present_when_findings_exist():
    output = render_markdown(build_report([make_finding(rule_id="INPUT-001")]))
    assert "| Rule | Count |" in output
    assert "INPUT-001" in output


def test_rule_counts_table_omitted_when_no_findings():
    output = render_markdown(build_report([]))
    assert "| Rule | Count |" not in output


# ---------------------------------------------------------------------------
# Large body handling
# ---------------------------------------------------------------------------


def test_large_body_is_truncated_not_dumped_whole():
    huge_body = {"data": "x" * 5000}
    finding = make_finding(reproduction_body=huge_body)
    output = render_markdown(build_report([finding]))
    assert len(output) < 6000  # nowhere near the raw 5000-char payload duplicated in full
    assert "truncated" in output


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


def test_masked_header_preserved_no_raw_secret():
    finding = make_finding(reproduction_headers={"x-api-token": "***MASKED***"})
    output = render_markdown(build_report([finding]))
    assert "***MASKED***" in output
    assert "alice-token" not in output
