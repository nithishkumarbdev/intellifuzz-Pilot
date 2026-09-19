"""
Data models for the API Runner.

TestCase  -> what to execute. Generic, not tied to OpenAPI or any
             specific target. This is also the exact shape later
             phases (mutation engine, LLM generator) will produce —
             they never talk HTTP directly, they just build TestCases.

TestResult -> what happened. Normalized so that later phases (baseline
              comparison, anomaly detection, rules engine) always get
              the same shape regardless of what the target actually
              returned (JSON, plain text, an error, nothing at all).
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class TestCase(BaseModel):
    """A single, fully-specified HTTP test to run against a target API."""

    method: str
    path: str  # may contain {placeholders}, e.g. "/users/{user_id}"
    path_params: dict[str, Any] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None


class ErrorInfo(BaseModel):
    """Populated only when the request could not be completed at all
    (connection refused, timed out, invalid URL, ...). A normal HTTP
    error response (404, 500) is NOT an ErrorInfo — it's a perfectly
    valid TestResult with that status_code set."""

    type: str  # "timeout" | "connection_error" | "invalid_url" | "unexpected_error"
    message: str


class RequestEcho(BaseModel):
    """
    What was actually sent, kept on the result for reproducibility and
    evidence. Sensitive headers (Authorization, API keys, cookies) are
    masked before this is ever stored or logged.
    """

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None


class TestResult(BaseModel):
    """Normalized outcome of executing one TestCase."""

    status_code: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    body_is_json: bool = False
    response_time_ms: Optional[float] = None
    body_size: Optional[int] = None
    error: Optional[ErrorInfo] = None
    request: Optional[RequestEcho] = None

    @property
    def executed(self) -> bool:
        """True if we got *a* response from the target, regardless of
        status code. False only when the request itself couldn't be
        completed (see ErrorInfo). A 404 or 500 still counts as
        executed=True — judging what a status code *means* is the
        analyzer's job in a later phase, not the runner's."""
        return self.error is None
