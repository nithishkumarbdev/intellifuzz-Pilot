"""
Executes a validated TestCase and returns a normalized TestResult.

The httpx.AsyncClient is injected rather than hard-created here. Two
reasons, both deliberate:

1. Testability — tests can hand in a client wired to httpx.ASGITransport
   pointed at an in-process FastAPI app, so most functional tests need
   no real socket, no background process, and can't be flaky.
2. Reuse — a future caller (e.g. the fuzzer running many test cases)
   can share one client/connection pool instead of opening a new
   connection per request.

If no client is given, we create a short-lived one scoped to this call
and close it ourselves.
"""

from __future__ import annotations

import time
from typing import Optional

import httpx

from app.core.config import RunnerSettings
from app.runner.models import ErrorInfo, RequestEcho, TestCase, TestResult
from app.runner.request_builder import PreparedRequest, build_request
from app.runner.validation import validate_test_case

# Headers whose values must never appear in logs, error messages, or
# stored evidence in plaintext.
SENSITIVE_HEADER_NAMES = {"authorization", "x-api-key", "x-api-token", "cookie", "set-cookie"}


def _mask_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: ("***MASKED***" if name.lower() in SENSITIVE_HEADER_NAMES else value)
        for name, value in headers.items()
    }


def _error_result(
    prepared: PreparedRequest, error_type: str, message: str, elapsed_ms: Optional[float]
) -> TestResult:
    return TestResult(
        status_code=None,
        response_time_ms=elapsed_ms,
        error=ErrorInfo(type=error_type, message=message),
        request=RequestEcho(
            method=prepared.method,
            url=prepared.url,
            headers=_mask_headers(prepared.headers),
            body=prepared.json_body,
        ),
    )


async def execute_test_case(
    test_case: TestCase,
    settings: RunnerSettings,
    client: Optional[httpx.AsyncClient] = None,
) -> TestResult:
    """
    Raises validation.ValidationError if the test case is structurally
    invalid — callers (e.g. the API layer) should catch that separately
    from execution failures, since it means "we never sent anything"
    rather than "the target didn't respond."
    """
    validate_test_case(test_case)
    prepared = build_request(test_case, settings)

    owns_client = client is None
    active_client = client or httpx.AsyncClient(timeout=settings.request_timeout_seconds)

    start = time.perf_counter()
    try:
        try:
            response = await active_client.request(
                method=prepared.method,
                url=prepared.url,
                headers=prepared.headers,
                params=prepared.query_params,
                json=prepared.json_body if prepared.has_body else None,
            )
        except httpx.TimeoutException as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return _error_result(prepared, "timeout", str(exc) or "Request timed out", elapsed_ms)
        except httpx.ConnectError as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return _error_result(prepared, "connection_error", str(exc) or "Connection failed", elapsed_ms)
        except httpx.InvalidURL as exc:
            return _error_result(prepared, "invalid_url", str(exc), None)
        except httpx.HTTPError as exc:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return _error_result(prepared, "unexpected_error", str(exc), elapsed_ms)
        except Exception as exc:  # noqa: BLE001 - last-resort: any other client-side failure
            # should become a graceful ErrorInfo, not crash the whole scan.
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return _error_result(prepared, "unexpected_error", str(exc), elapsed_ms)
    finally:
        if owns_client:
            await active_client.aclose()

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    body_json = None
    is_json = False
    try:
        body_json = response.json()
        is_json = True
    except ValueError:
        pass

    return TestResult(
        status_code=response.status_code,
        headers=dict(response.headers),
        body=body_json if is_json else response.text,
        body_is_json=is_json,
        response_time_ms=elapsed_ms,
        body_size=len(response.content),
        error=None,
        request=RequestEcho(
            method=prepared.method,
            url=prepared.url,
            headers=_mask_headers(prepared.headers),
            body=test_case.body,
        ),
    )
