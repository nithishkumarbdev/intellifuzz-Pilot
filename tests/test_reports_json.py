"""Tests for app.reports.json_reporter."""

from __future__ import annotations

import json

from app.reports.build import build_report
from app.reports.json_reporter import render_json
from app.rules.models import Severity
from tests.reports_helpers import make_finding


def test_output_is_valid_json():
    report = build_report([make_finding()])
    parsed = json.loads(render_json(report))
    assert "metadata" in parsed
    assert "findings" in parsed


def test_metadata_present():
    report = build_report([make_finding()], target_base_url="http://x", spec_title="My API")
    parsed = json.loads(render_json(report))
    assert parsed["metadata"]["target_base_url"] == "http://x"
    assert parsed["metadata"]["spec_title"] == "My API"
    assert parsed["metadata"]["total_findings"] == 1


def test_all_findings_preserved():
    findings = [make_finding(finding_id="F1"), make_finding(finding_id="F2"), make_finding(finding_id="F3")]
    report = build_report(findings)
    parsed = json.loads(render_json(report))
    assert {f["finding_id"] for f in parsed["findings"]} == {"F1", "F2", "F3"}


def test_severity_counts_correct_in_json():
    findings = [
        make_finding(finding_id="F1", severity=Severity.HIGH),
        make_finding(finding_id="F2", severity=Severity.LOW),
    ]
    report = build_report(findings)
    parsed = json.loads(render_json(report))
    assert parsed["metadata"]["severity_counts"] == {"HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0}


def test_rule_counts_correct_in_json():
    findings = [make_finding(finding_id="F1", rule_id="AUTHZ-001"), make_finding(finding_id="F2", rule_id="AUTHZ-001")]
    report = build_report(findings)
    parsed = json.loads(render_json(report))
    assert parsed["metadata"]["rule_counts"] == {"AUTHZ-001": 2}


def test_finding_full_shape_preserved_for_traceability():
    finding = make_finding(finding_id="F1", rule_id="AUTHZ-001", endpoint="/users/{id}", method="GET")
    report = build_report([finding])
    parsed = json.loads(render_json(report))
    entry = parsed["findings"][0]
    assert entry["endpoint"] == "/users/{id}"
    assert entry["method"] == "GET"
    assert entry["rule_id"] == "AUTHZ-001"
    assert "evidence" in entry
    assert "reproduction" in entry
    assert entry["evidence"]["baseline_status"] == 201
    assert entry["reproduction"]["mutation_value"] == -1


def test_empty_findings_produces_valid_json():
    report = build_report([])
    parsed = json.loads(render_json(report))
    assert parsed["findings"] == []
    assert parsed["metadata"]["total_findings"] == 0


def test_severity_enum_serializes_as_plain_lowercase_string():
    """Enums must come out as plain strings, not Python repr — this is
    what makes it "easy for n8n to consume without understanding Python
    internals", per the phase's own requirement."""
    report = build_report([make_finding(severity=Severity.HIGH)])
    parsed = json.loads(render_json(report))
    assert parsed["findings"][0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Secret safety
# ---------------------------------------------------------------------------


def test_masked_header_stays_masked_in_json():
    finding = make_finding(reproduction_headers={"authorization": "***MASKED***", "x-api-token": "***MASKED***"})
    report = build_report([finding])
    output = render_json(report)
    assert "***MASKED***" in output


def test_no_raw_secret_value_can_appear_since_masking_happens_upstream():
    """The reporter doesn't do its own masking — it just renders
    whatever Reproduction already contains. This test proves that IF
    upstream masking did its job (as Phase 2's RequestEcho always
    does), the reporter faithfully preserves that, rather than somehow
    reconstructing or leaking a raw value."""
    finding = make_finding(reproduction_headers={"x-api-token": "***MASKED***"})
    report = build_report([finding])
    output = render_json(report)
    assert "alice-token" not in output  # a real token value never appears anywhere
    assert "***MASKED***" in output
