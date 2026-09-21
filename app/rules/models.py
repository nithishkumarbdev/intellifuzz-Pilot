"""
The security finding model — the first place in this project a
severity label is ever assigned.

Two scales that must never be conflated, per the project's own
long-standing rule ("LLM confidence != security severity", carried
over from Phase 6's `MutatedTestCase.confidence` — an LLM's own
self-reported confidence in its test idea, which is never read by
anything in this module):

- `Severity` — how bad this WOULD be if the pattern indicates a real
  issue. Based on the finding's category and the strength of the
  evidence, never on how sure we are that it's genuinely exploitable.
- `Confidence` — how sure the RULE is that this pattern is genuinely
  present and worth a human looking at, based on what the fuzzer can
  and can't independently verify. A HIGH-severity, LOW-confidence
  finding (e.g. a plausible-looking cross-resource access the fuzzer
  cannot prove is actually unauthorized) is a completely normal,
  valid combination — not a contradiction.

Every finding is a *signal*, never a verdict. Titles and descriptions
are written accordingly ("Potential X", never "X confirmed") — see
each rule's own docstring in rules.py for why.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.fuzzer.mutations.models import MutationType


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    INPUT_HANDLING = "input_handling"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_EXPOSURE = "data_exposure"
    BEHAVIOR_INCONSISTENCY = "behavior_inconsistency"


class Evidence(BaseModel):
    """Concrete, structural facts only — mirrors Anomaly.evidence's own
    philosophy from Phase 5. Never a raw response body, never a
    secret's actual value — only status codes, sizes, and named
    signals (matched patterns, new field NAMES, the mutated
    identifier's value where that value itself isn't sensitive)."""

    baseline_status: Optional[int] = None
    mutation_status: Optional[int] = None
    baseline_body_size: Optional[int] = None
    mutation_body_size: Optional[int] = None
    details: dict[str, Any] = Field(default_factory=dict)


class Reproduction(BaseModel):
    """Enough to reproduce the exact request that triggered this
    finding. Built directly from the runner's own RequestEcho (Phase
    2), which is already masked — no re-masking logic duplicated
    here."""

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    mutation_location: str
    mutation_value: Optional[Any] = None


class Finding(BaseModel):
    finding_id: str  # deterministic — see rules.py's _stable_finding_id
    rule_id: str
    title: str
    description: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence

    endpoint: str
    method: str
    baseline_key: str

    mutation_type: MutationType
    mutation_location: str
    source: str  # "deterministic" | "llm" — carried through from MutatedTestCase/MutationResult

    evidence: Evidence
    reproduction: Reproduction
