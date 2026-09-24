"""
Standalone HTML report — opens directly in a browser, no server, no JS
framework, no build step.

Every value rendered into the page goes through _esc() (html.escape).
This isn't in the phase spec explicitly, but it's a real, obvious
requirement once you notice where finding data ultimately comes from:
mutation values, matched field names, and reproduction bodies are all
derived from the FUZZED TARGET's own responses (or an LLM's proposed
values) — untrusted input from this report generator's point of view.
Rendering any of that unescaped into HTML would make the report itself
an XSS vector when opened in a browser. Masking (Phase 2's RequestEcho)
handles secrets; escaping here handles this separate concern.
"""

from __future__ import annotations

import html as html_module

from app.reports.formatting import SEVERITY_DISPLAY_ORDER, safe_excerpt
from app.reports.models import Report
from app.rules.models import Finding

SEVERITY_COLORS = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2980b9",
    "INFO": "#7f8c8d",
}

STYLE = """
:root { color-scheme: light; }
body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; max-width: 900px;
       margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; background: #fff; line-height: 1.5; }
h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 0.5rem; }
h3 { margin-bottom: 0.3rem; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #ddd; padding: 0.4rem 1rem; text-align: left; }
.finding { border: 1px solid #ddd; border-left: 6px solid #999; border-radius: 4px;
           padding: 1rem; margin: 1rem 0; }
.severity-badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px;
                   color: #fff; font-weight: bold; font-size: 0.8rem; letter-spacing: 0.03em; }
.meta { color: #555; font-size: 0.9rem; }
.evidence, .reproduction { background: #f7f7f7; padding: 0.75rem; border-radius: 4px;
                            font-size: 0.88rem; overflow-x: auto; margin-top: 0.5rem; }
.disclaimer { margin-top: 2rem; padding: 1rem; background: #fff8e1;
              border-left: 4px solid #d68910; font-size: 0.9rem; }
code { font-family: ui-monospace, Consolas, monospace; word-break: break-word; }
@media (max-width: 600px) { body { margin: 1rem auto; } .finding { padding: 0.75rem; } }
"""


def _esc(value) -> str:
    if value is None:
        return ""
    return html_module.escape(str(value))


def _finding_card(finding: Finding) -> str:
    color = SEVERITY_COLORS.get(finding.severity.value.upper(), "#999")
    details_items = "".join(
        f"<li>{_esc(key)}: {_esc(safe_excerpt(value, max_len=200))}</li>" for key, value in finding.evidence.details.items()
    )
    body_html = ""
    if finding.reproduction.body is not None:
        body_html = f"<p>Body: <code>{_esc(safe_excerpt(finding.reproduction.body))}</code></p>"
    headers_html = ""
    if finding.reproduction.headers:
        headers_html = f"<p>Headers: <code>{_esc(finding.reproduction.headers)}</code></p>"

    return f"""
  <div class="finding" style="border-left-color: {color};">
    <span class="severity-badge" style="background: {color};">{_esc(finding.severity.value.upper())}</span>
    <h3>{_esc(finding.finding_id)} &mdash; {_esc(finding.title)}</h3>
    <p class="meta">
      <strong>Confidence:</strong> {_esc(finding.confidence.value.upper())} &nbsp;
      <strong>Rule:</strong> {_esc(finding.rule_id)} &nbsp;
      <strong>Endpoint:</strong> {_esc(finding.method)} {_esc(finding.endpoint)} &nbsp;
      <strong>Source:</strong> {_esc(finding.source)}
    </p>
    <p>{_esc(finding.description)}</p>
    <div class="evidence">
      <strong>Evidence</strong>
      <ul>
        <li>Baseline status: {_esc(finding.evidence.baseline_status)}</li>
        <li>Mutation status: {_esc(finding.evidence.mutation_status)}</li>
        {details_items}
      </ul>
    </div>
    <div class="reproduction">
      <strong>Reproduction</strong>
      <p><code>{_esc(finding.reproduction.method)} {_esc(finding.reproduction.url)}</code></p>
      <p>Mutation: <code>{_esc(finding.mutation_location)}</code> &rarr;
         <code>{_esc(finding.reproduction.mutation_value)}</code></p>
      {headers_html}
      {body_html}
    </div>
  </div>
"""


def render_html(report: Report) -> str:
    severity_rows = "".join(
        f"<tr><td>{severity.upper()}</td><td>{report.metadata.severity_counts.get(severity.upper(), 0)}</td></tr>"
        for severity in SEVERITY_DISPLAY_ORDER
    )
    findings_html = (
        "".join(_finding_card(f) for f in report.findings)
        if report.findings
        else "<p>No security findings were generated.</p>"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IntelliFuzz Security Report</title>
<style>{STYLE}</style>
</head>
<body>
  <h1>IntelliFuzz Security Assessment Report</h1>
  <p class="meta">
    <strong>Target:</strong> {_esc(report.metadata.target_base_url or "unavailable")}<br>
    <strong>Generated:</strong> {_esc(report.metadata.generated_at)}<br>
    <strong>Total findings:</strong> {report.metadata.total_findings}
  </p>

  <h2>Summary</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {severity_rows}
  </table>

  <h2>Findings</h2>
  {findings_html}

  <div class="disclaimer">{_esc(report.metadata.disclaimer)}</div>
</body>
</html>"""
