"""Shared helper for reports tests - not a test file itself."""

from __future__ import annotations

from typing import Any, Optional

from app.fuzzer.mutations.models import MutationType
from app.rules.models import Confidence, Evidence, Finding, FindingCategory, Reproduction, Severity


def make_finding(
    finding_id: str = "F-001",
    rule_id: str = "INPUT-001",
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    endpoint: str = "/users",
    method: str = "POST",
    category: FindingCategory = FindingCategory.INPUT_HANDLING,
    title: str = "Potential test finding",
    description: str = "A test finding.",
    evidence_details: Optional[dict[str, Any]] = None,
    reproduction_headers: Optional[dict[str, str]] = None,
    reproduction_body: Any = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        rule_id=rule_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        endpoint=endpoint,
        method=method,
        baseline_key=f"{method} {endpoint}",
        mutation_type=MutationType.NEGATIVE,
        mutation_location="body.age",
        source="deterministic",
        evidence=Evidence(baseline_status=201, mutation_status=500, details=evidence_details or {}),
        reproduction=Reproduction(
            method=method,
            url=f"http://test{endpoint}",
            headers=reproduction_headers or {},
            body=reproduction_body,
            mutation_location="body.age",
            mutation_value=-1,
        ),
    )
