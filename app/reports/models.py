"""
The report model: metadata + the (sorted) finding list. Every renderer
(json_reporter, markdown_reporter, html_reporter) reads from exactly
this - no reporter maintains its own copy of finding data, per the
phase's own explicit "one source of truth" requirement.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from app.rules.models import Finding

DISCLAIMER = (
    "A report containing zero findings does not prove the API is secure. It means no findings "
    "were produced by the currently implemented rules and test set. Every finding above is a "
    "signal for human review, not a confirmed vulnerability."
)


class ReportMetadata(BaseModel):
    project_name: str = "IntelliFuzz"
    report_id: str
    generated_at: str
    target_base_url: Optional[str] = None
    spec_title: Optional[str] = None
    total_findings: int
    severity_counts: dict[str, int]
    rule_counts: dict[str, int]
    disclaimer: str = DISCLAIMER


class Report(BaseModel):
    metadata: ReportMetadata
    findings: list[Finding]
