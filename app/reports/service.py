"""
The single entry point for reporting: findings -> one or more files on
disk, all rendered from the same Report object (built once). Nothing
downstream of build_report() computes its own copy of any metadata.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from app.reports.build import build_report
from app.reports.html_reporter import render_html
from app.reports.json_reporter import render_json
from app.reports.markdown_reporter import render_markdown
from app.rules.models import Finding

_RENDERERS = {
    "json": (render_json, "json"),
    "markdown": (render_markdown, "md"),
    "html": (render_html, "html"),
}


class ReportService:
    def generate(
        self,
        findings: list[Finding],
        output_dir: str,
        formats: Optional[list[str]] = None,
        target_base_url: Optional[str] = None,
        spec_title: Optional[str] = None,
        base_filename: str = "security-report",
    ) -> dict[str, Path]:
        formats = formats or ["json", "markdown", "html"]
        unknown = [f for f in formats if f not in _RENDERERS]
        if unknown:
            raise ValueError(f"Unknown report format(s) {unknown}. Supported: {sorted(_RENDERERS)}")

        report = build_report(findings, target_base_url=target_base_url, spec_title=spec_title)

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        written: dict[str, Path] = {}
        for fmt in formats:
            renderer, extension = _RENDERERS[fmt]
            content = renderer(report)
            path = output_path / f"{base_filename}.{extension}"
            path.write_text(content)
            written[fmt] = path
        return written
