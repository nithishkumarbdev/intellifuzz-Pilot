"""
Turns a validated TestCase into a PreparedRequest: a fully-resolved,
ready-to-send description of an HTTP request. No I/O happens here —
that's the http_runner's job. Keeping this pure means it's trivial to
unit test path-param substitution, URL joining, and header merging
without needing a network at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

from app.core.config import RunnerSettings
from app.runner.models import TestCase


@dataclass
class PreparedRequest:
    method: str
    url: str  # fully resolved, base_url + path with {placeholders} substituted — no query string
    query_params: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    json_body: Optional[Any] = None
    has_body: bool = False


def _resolve_path(path: str, path_params: dict[str, Any]) -> str:
    resolved = path
    for name, value in path_params.items():
        placeholder = "{" + name + "}"
        if placeholder in resolved:
            # URL-encode the substituted value — this matters once the
            # fuzzer starts mutating path params with special characters
            # (e.g. "../", spaces, unicode); we want a well-formed
            # request sent, not a client-side crash.
            resolved = resolved.replace(placeholder, quote(str(value), safe=""))
    return resolved


def build_request(test_case: TestCase, settings: RunnerSettings) -> PreparedRequest:
    """Assumes test_case has already passed validate_test_case()."""
    resolved_path = _resolve_path(test_case.path, test_case.path_params)
    path_part = resolved_path if resolved_path.startswith("/") else f"/{resolved_path}"
    url = f"{settings.base_url.rstrip('/')}{path_part}"

    # Test-case headers always win over the configured default auth
    # header. A fuzzer deliberately testing "what happens with no auth"
    # or "what happens with a mutated token" must never have that
    # intent silently overridden by a default.
    headers = dict(test_case.headers)
    if (
        settings.auth_header_name
        and settings.auth_header_name not in headers
        and settings.auth_header_value is not None
    ):
        headers[settings.auth_header_name] = settings.auth_header_value

    return PreparedRequest(
        method=test_case.method.upper(),
        url=url,
        query_params=dict(test_case.query_params),
        headers=headers,
        json_body=test_case.body,
        has_body=test_case.body is not None,
    )
