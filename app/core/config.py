"""
Runner configuration.

Deliberately a plain dataclass rather than pydantic-settings: we have
four settings and don't need schema validation, env-file layering, or
nested config sections yet. Adding a whole settings library for this
would be exactly the kind of unnecessary dependency the project rules
warn against. If config genuinely grows more complex later, revisit.

Settings are always passed explicitly into the functions that need
them (never read from a global at call time) — this is what makes the
runner trivially testable: tests build a RunnerSettings by hand
instead of mutating environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class RunnerSettings:
    base_url: str
    request_timeout_seconds: float = 10.0
    # A single default auth header, injected only when the test case
    # doesn't already specify that header itself — see request_builder.
    auth_header_name: Optional[str] = None
    auth_header_value: Optional[str] = None


def load_settings() -> RunnerSettings:
    """Build RunnerSettings from environment variables, with sane local defaults."""
    return RunnerSettings(
        base_url=os.getenv("FUZZER_TARGET_BASE_URL", "http://localhost:8001"),
        request_timeout_seconds=float(os.getenv("FUZZER_REQUEST_TIMEOUT_SECONDS", "10")),
        auth_header_name=os.getenv("FUZZER_AUTH_HEADER_NAME"),
        auth_header_value=os.getenv("FUZZER_AUTH_HEADER_VALUE"),
    )
