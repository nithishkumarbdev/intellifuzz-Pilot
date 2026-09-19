"""
Tests that genuinely need a real socket: timeout and connection-error
handling. httpx does not enforce its client-level timeout against an
in-process ASGITransport (there's no real I/O for it to interrupt), so
these specifically use `live_vulnerable_api_url` (a real local server,
started in a background thread for the test session) and
`unused_port_url` (a real port nothing is listening on).

Neither depends on anything outside this machine.
"""

from __future__ import annotations

from app.core.config import RunnerSettings
from app.runner.http_runner import execute_test_case
from app.runner.models import TestCase


async def test_timeout_is_normalized_not_raised(live_vulnerable_api_url):
    settings = RunnerSettings(base_url=live_vulnerable_api_url, request_timeout_seconds=0.3)
    result = await execute_test_case(
        TestCase(method="GET", path="/slow", query_params={"delay": 2}), settings
    )
    assert result.executed is False
    assert result.error is not None
    assert result.error.type == "timeout"
    assert result.status_code is None
    # We should still know roughly how long we waited before giving up,
    # and it should be close to the configured timeout, not the full 2s.
    assert result.response_time_ms is not None
    assert result.response_time_ms < 1000


async def test_connection_refused_is_normalized_not_raised(unused_port_url):
    settings = RunnerSettings(base_url=unused_port_url, request_timeout_seconds=2)
    result = await execute_test_case(TestCase(method="GET", path="/health"), settings)
    assert result.executed is False
    assert result.error is not None
    assert result.error.type == "connection_error"
    assert result.status_code is None


async def test_fast_request_against_live_server_still_works_normally(live_vulnerable_api_url):
    """Sanity check that the live-server fixture itself behaves like any
    other target for a normal, fast request — i.e. real sockets don't
    change the happy path."""
    settings = RunnerSettings(base_url=live_vulnerable_api_url)
    result = await execute_test_case(TestCase(method="GET", path="/health"), settings)
    assert result.executed
    assert result.status_code == 200
    assert result.body == {"status": "ok"}
