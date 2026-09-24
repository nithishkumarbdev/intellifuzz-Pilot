"""
Human-readable Markdown report - meant to be attached to an issue,
sent to a developer, committed as a CI artifact, or read during a demo.
"""

from __future__ import annotations

from app.reports.formatting import SEVERITY_DISPLAY_ORDER, safe_excerpt
from app.reports.models import Report
from app.rules.models import Finding


def _finding_section(finding: Finding) -> list[str]:
    lines = [
        f"### {finding.finding_id} — {finding.title}",
        "",
        f"**Severity:** {finding.severity.value.upper()}  ",
        f"**Confidence:** {finding.confidence.value.upper()}  ",
        f"**Rule:** {finding.rule_id}  ",
        f"**Endpoint:** {finding.method} {finding.endpoint}  ",
        f"**Source:** {finding.source}",
        "",
        finding.description,
        "",
        "#### Evidence",
        "",
        f"- Baseline status: {finding.evidence.baseline_status}",
        f"- Mutation status: {finding.evidence.mutation_status}",
    ]
    if finding.evidence.baseline_body_size is not None:
        lines.append(f"- Baseline body size: {finding.evidence.baseline_body_size} bytes")
    if finding.evidence.mutation_body_size is not None:
        lines.append(f"- Mutation body size: {finding.evidence.mutation_body_size} bytes")
    for key, value in finding.evidence.details.items():
        lines.append(f"- {key}: {safe_excerpt(value, max_len=200)}")

    lines += [
        "",
        "#### Reproduction",
        "",
        f"```\n{finding.reproduction.method} {finding.reproduction.url}\n```",
        f"- Mutation: `{finding.mutation_location}` → `{finding.reproduction.mutation_value!r}`",
    ]
    if finding.reproduction.headers:
        lines.append(f"- Headers: `{finding.reproduction.headers}`")
    if finding.reproduction.body is not None:
        lines.append(f"- Body: `{safe_excerpt(finding.reproduction.body)}`")

    lines += ["", "---", ""]
    return lines


def render_markdown(report: Report) -> str:
    lines = ["# IntelliFuzz Security Report", "", "## Summary", ""]
    if report.metadata.target_base_url:
        lines.append(f"**Target:** {report.metadata.target_base_url}  ")
    if report.metadata.spec_title:
        lines.append(f"**Spec:** {report.metadata.spec_title}  ")
    lines.append(f"**Generated:** {report.metadata.generated_at}  ")
    lines.append(f"**Total findings:** {report.metadata.total_findings}")
    lines += ["", "| Severity | Count |", "|----------|------:|"]
    for severity in SEVERITY_DISPLAY_ORDER:
        lines.append(f"| {severity.upper():<8} | {report.metadata.severity_counts.get(severity.upper(), 0)} |")
    lines.append("")

    if report.metadata.rule_counts:
        lines += ["| Rule | Count |", "|------|------:|"]
        for rule_id, count in report.metadata.rule_counts.items():
            lines.append(f"| {rule_id} | {count} |")
        lines.append("")

    lines += ["## Findings", ""]
    if not report.findings:
        lines.append("No security findings were generated.")
        lines.append("")
    else:
        for finding in report.findings:
            lines += _finding_section(finding)

    lines.append(report.metadata.disclaimer)
    return "\n".join(lines)
