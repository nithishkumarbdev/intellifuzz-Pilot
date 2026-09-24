"""Tests for app.reports.service.ReportService."""

from __future__ import annotations

import json

import pytest

from app.reports.service import ReportService
from tests.reports_helpers import make_finding


def test_generates_all_three_formats_by_default(tmp_path):
    written = ReportService().generate([make_finding()], output_dir=str(tmp_path))
    assert set(written.keys()) == {"json", "markdown", "html"}
    for path in written.values():
        assert path.exists()
        assert path.stat().st_size > 0


def test_generates_only_requested_formats(tmp_path):
    written = ReportService().generate([make_finding()], output_dir=str(tmp_path), formats=["json"])
    assert set(written.keys()) == {"json"}
    assert (tmp_path / "security-report.json").exists()
    assert not (tmp_path / "security-report.md").exists()
    assert not (tmp_path / "security-report.html").exists()


def test_unknown_format_raises():
    with pytest.raises(ValueError, match="Unknown report format"):
        ReportService().generate([make_finding()], output_dir="/tmp/whatever", formats=["pdf"])


def test_custom_base_filename(tmp_path):
    written = ReportService().generate(
        [make_finding()], output_dir=str(tmp_path), formats=["json"], base_filename="my-scan"
    )
    assert written["json"].name == "my-scan.json"


def test_output_dir_created_if_missing(tmp_path):
    target_dir = tmp_path / "nested" / "reports"
    assert not target_dir.exists()
    ReportService().generate([make_finding()], output_dir=str(target_dir), formats=["json"])
    assert target_dir.exists()


def test_all_three_formats_use_the_same_findings(tmp_path):
    """The 'one source of truth' requirement, verified concretely: the
    same finding_id must appear in all three outputs."""
    finding = make_finding(finding_id="F-CONSISTENCY-CHECK")
    written = ReportService().generate([finding], output_dir=str(tmp_path))

    json_content = written["json"].read_text()
    md_content = written["markdown"].read_text()
    html_content = written["html"].read_text()

    assert "F-CONSISTENCY-CHECK" in json_content
    assert "F-CONSISTENCY-CHECK" in md_content
    assert "F-CONSISTENCY-CHECK" in html_content

    parsed = json.loads(json_content)
    assert parsed["metadata"]["total_findings"] == 1


def test_passes_target_and_spec_title_through(tmp_path):
    written = ReportService().generate(
        [make_finding()], output_dir=str(tmp_path), formats=["json"], target_base_url="http://x", spec_title="My API"
    )
    parsed = json.loads(written["json"].read_text())
    assert parsed["metadata"]["target_base_url"] == "http://x"
    assert parsed["metadata"]["spec_title"] == "My API"


def test_empty_findings_list_generates_valid_reports(tmp_path):
    written = ReportService().generate([], output_dir=str(tmp_path))
    for path in written.values():
        assert path.exists()
    parsed = json.loads(written["json"].read_text())
    assert parsed["metadata"]["total_findings"] == 0
