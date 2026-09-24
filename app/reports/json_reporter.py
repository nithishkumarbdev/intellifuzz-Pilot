"""
Machine-readable JSON report. Deliberately thin: Report is already a
pydantic model carrying everything, so this is just
model_dump(mode="json") + json.dumps - no separate JSON-specific data
model to keep in sync with the others.
"""

from __future__ import annotations

import json

from app.reports.models import Report


def render_json(report: Report) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2)
