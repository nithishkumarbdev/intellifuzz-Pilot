"""
Small, shared helpers used by every reporter (json/markdown/html) so
sorting and body-excerpting logic isn't duplicated three times.
"""

from __future__ import annotations

import json
from typing import Any

from app.rules.models import Finding

# Worst-first, matching the security-report convention the phase spec's
# own examples use.
SEVERITY_DISPLAY_ORDER = ["high", "medium", "low", "info"]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """
    Returns a NEW list — never mutates the input — sorted by severity
    (HIGH first), then endpoint, then rule_id, then finding_id. This is
    a reporting-only view; it has no bearing on the findings' actual
    semantics or on any other consumer of the original list.
    """
    severity_rank = {name: i for i, name in enumerate(SEVERITY_DISPLAY_ORDER)}
    return sorted(
        findings,
        key=lambda f: (severity_rank.get(f.severity.value, len(SEVERITY_DISPLAY_ORDER)), f.endpoint, f.rule_id, f.finding_id),
    )


def safe_excerpt(value: Any, max_len: int = 300) -> str:
    """
    Never places a huge/raw payload into a report. Strings are used as-
    is (truncated); anything else is JSON-stringified first. This is a
    length safeguard, not a secret-masking mechanism — masking already
    happened upstream, in the runner's own RequestEcho (Phase 2), before
    this value ever reached a Finding.
    """
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    if len(text) > max_len:
        return text[:max_len] + "... (truncated)"
    return text
