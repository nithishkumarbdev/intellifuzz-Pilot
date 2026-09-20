"""
Data models for response analysis. This module defines the *vocabulary*
of observations the analyzer can make — never their meaning. An
AnalysisResult answers "what changed between the baseline and this
mutation's result", never "is this a vulnerability" or "how severe is
it". That judgment is explicitly out of scope until later phases
(deterministic security rules, then finding classification).

No confidence scores here either — every observation carries concrete
evidence (status codes, byte counts, matched substrings) instead of a
probabilistic number that would imply an accuracy this deterministic
comparison never claims to have.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.fuzzer.mutations.models import Mutation


class AnomalyType(str, Enum):
    STATUS_CHANGED = "status_changed"
    UNEXPECTED_SERVER_ERROR = "unexpected_server_error"
    UNEXPECTED_CLIENT_ERROR = "unexpected_client_error"
    AUTHENTICATION_BEHAVIOR_CHANGED = "authentication_behavior_changed"
    REDIRECT_CHANGED = "redirect_changed"
    RESPONSE_BODY_CHANGED = "response_body_changed"
    RESPONSE_STRUCTURE_CHANGED = "response_structure_changed"
    RESPONSE_SIZE_CHANGED = "response_size_changed"
    TIMING_ANOMALY = "timing_anomaly"
    ERROR_SIGNATURE_DETECTED = "error_signature_detected"
    REQUEST_TIMEOUT = "request_timeout"
    NETWORK_ERROR = "network_error"


class StatusCategory(str, Enum):
    INFORMATIONAL = "1xx"
    SUCCESS = "2xx"
    REDIRECT = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    UNKNOWN = "unknown"


class Anomaly(BaseModel):
    """One observation, with concrete evidence — never a severity or a
    confidence score. `evidence` deliberately holds only structural
    facts (codes, sizes, matched patterns), never raw response bodies,
    so analysis output can't become a secret-leak mechanism."""

    type: AnomalyType
    evidence: dict[str, Any] = Field(default_factory=dict)


class AnalysisConfig(BaseModel):
    """Deterministic thresholds — no magic numbers scattered through the
    analyzer itself. A timing anomaly requires BOTH the absolute
    difference and the ratio to clear their thresholds, so "51ms vs
    48ms" (tiny absolute diff) and "1ms vs 3ms" (huge ratio, tiny
    absolute diff) are both correctly ignored, per the phase's own
    example."""

    min_time_difference_ms: float = 200.0
    min_time_multiplier: float = 3.0
    min_body_size_difference_bytes: int = 10


class AnalysisResult(BaseModel):
    """Normalized comparison of one mutation's result against its
    baseline. Every `*_changed` boolean corresponds 1:1 to whether a
    matching Anomaly was appended — so the flags and the evidence list
    never disagree with each other."""

    baseline_key: str
    mutation: Mutation

    baseline_status: Optional[int] = None
    mutation_status: Optional[int] = None
    baseline_status_category: StatusCategory = StatusCategory.UNKNOWN
    mutation_status_category: StatusCategory = StatusCategory.UNKNOWN
    status_changed: bool = False

    baseline_response_time_ms: Optional[float] = None
    mutation_response_time_ms: Optional[float] = None
    response_time_changed: bool = False
    response_time_difference_ms: Optional[float] = None
    response_time_ratio: Optional[float] = None

    baseline_body_size: Optional[int] = None
    mutation_body_size: Optional[int] = None
    body_size_changed: bool = False
    body_changed: bool = False
    body_structure_changed: bool = False

    anomalies: list[Anomaly] = Field(default_factory=list)
