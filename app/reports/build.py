"""
Turns a raw list[Finding] into a Report: computed metadata (counts,
timestamp, report_id) plus a deterministically-sorted finding view.
This is the ONLY place report metadata gets computed — every renderer
just reads the result.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.reports.formatting import SEVERITY_DISPLAY_ORDER, sort_findings
from app.reports.models import Report, ReportMetadata
from app.rules.models import Finding


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {name.upper(): 0 for name in SEVERITY_DISPLAY_ORDER}
    for finding in findings:
        counts[finding.severity.value.upper()] += 1
    return counts


def _rule_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
    return dict(sorted(counts.items()))


def build_report(
    findings: list[Finding],
    target_base_url: Optional[str] = None,
    spec_title: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> Report:
    """
    `generated_at` is injectable (defaults to now, UTC) so tests can
    assert exact output — same "explicit config, never a hidden global"
    pattern this project has used for RunnerSettings/MutationConfig
    since Phase 2. A report's timestamp/report_id are inherently
    point-in-time and not expected to be identical across separate
    runs; what IS deterministic is the finding ORDERING and every other
    field, given the same findings and the same generated_at.
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    generated_at_iso = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    report_id = f"report-{generated_at.strftime('%Y%m%dT%H%M%S')}"

    sorted_findings = sort_findings(findings)

    metadata = ReportMetadata(
        report_id=report_id,
        generated_at=generated_at_iso,
        target_base_url=target_base_url,
        spec_title=spec_title,
        total_findings=len(sorted_findings),
        severity_counts=_severity_counts(sorted_findings),
        rule_counts=_rule_counts(sorted_findings),
    )
    return Report(metadata=metadata, findings=sorted_findings)
