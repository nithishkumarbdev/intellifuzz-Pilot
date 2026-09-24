"""Tests for app.reports.html_reporter."""

from __future__ import annotations

from app.reports.build import build_report
from app.reports.html_reporter import render_html
from app.rules.models import Severity
from tests.reports_helpers import make_finding


def test_valid_html_document_structure():
    output = render_html(build_report([make_finding()]))
    assert output.startswith("<!DOCTYPE html>")
    assert "<html" in output
    assert "</html>" in output
    assert "<head>" in output and "</head>" in output
    assert "<body>" in output and "</body>" in output


def test_no_javascript_framework_or_external_scripts():
    """Standalone, per the phase's explicit requirement — no build
    step, nothing that requires network access to render."""
    output = render_html(build_report([make_finding()]))
    assert "<script" not in output
    assert "react" not in output.lower()


def test_summary_appears():
    output = render_html(build_report([make_finding()], target_base_url="http://x"))
    assert "Summary" in output
    assert "http://x" in output


def test_severity_information_appears():
    output = render_html(build_report([make_finding(severity=Severity.HIGH)]))
    assert "HIGH" in output


def test_finding_card_appears():
    finding = make_finding(finding_id="F-99", title="Potential something")
    output = render_html(build_report([finding]))
    assert "F-99" in output
    assert "Potential something" in output


def test_empty_report_says_no_findings():
    output = render_html(build_report([]))
    assert "No security findings were generated." in output


def test_disclaimer_present():
    output = render_html(build_report([]))
    assert "signal for human review" in output


# ---------------------------------------------------------------------------
# HTML escaping (XSS safety) — data ultimately derives from the fuzzed
# target's own responses or an LLM's proposed values, so it must never
# be trusted as safe-to-embed HTML.
# ---------------------------------------------------------------------------


def test_malicious_script_in_title_is_escaped():
    finding = make_finding(title="<script>alert('xss')</script>")
    output = render_html(build_report([finding]))
    assert "<script>alert" not in output
    assert "&lt;script&gt;" in output


def test_malicious_script_in_evidence_details_is_escaped():
    finding = make_finding(evidence_details={"matched_field": "<img src=x onerror=alert(1)>"})
    output = render_html(build_report([finding]))
    assert "<img src=x onerror" not in output
    assert "&lt;img" in output


def test_malicious_script_in_reproduction_body_is_escaped():
    finding = make_finding(reproduction_body={"comment": "<script>steal()</script>"})
    output = render_html(build_report([finding]))
    assert "<script>steal" not in output


def test_malicious_script_in_endpoint_is_escaped():
    finding = make_finding(endpoint="/users/<script>alert(1)</script>")
    output = render_html(build_report([finding]))
    assert "<script>alert(1)</script>" not in output


# ---------------------------------------------------------------------------
# Large body handling
# ---------------------------------------------------------------------------


def test_large_body_is_truncated():
    finding = make_finding(reproduction_body={"data": "y" * 5000})
    output = render_html(build_report([finding]))
    assert "truncated" in output


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


def test_masked_header_preserved_no_raw_secret_in_html():
    finding = make_finding(reproduction_headers={"x-api-token": "***MASKED***"})
    output = render_html(build_report([finding]))
    assert "***MASKED***" in output
    assert "alice-token" not in output
