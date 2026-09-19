"""
Tests for the fuzzer's own /execute endpoint (app.api.routes).

Uses FastAPI's dependency_overrides to swap the real get_http_client
dependency for one backed by httpx.ASGITransport pointed at the
in-process vulnerable-api app. This proves the full stack — FastAPI
route -> validation -> request builder -> runner -> normalized result —
works together, with no real server and no real network involved.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from app.api.dependencies import get_http_client, get_settings
from app.core.config import RunnerSettings
from app.main import app


@pytest.fixture
def fuzzer_client(vulnerable_api_app):
    async def _override_get_http_client():
        transport = ASGITransport(app=vulnerable_api_app)
        client = AsyncClient(transport=transport, base_url="http://vulnerable-api-test")
        try:
            yield client
        finally:
            await client.aclose()

    def _override_get_settings():
        return RunnerSettings(base_url="http://vulnerable-api-test")

    app.dependency_overrides[get_http_client] = _override_get_http_client
    app.dependency_overrides[get_settings] = _override_get_settings

    transport = ASGITransport(app=app)
    client = AsyncClient(transport=transport, base_url="http://fuzzer-test")
    yield client

    app.dependency_overrides.clear()


async def test_health_endpoint(fuzzer_client):
    async with fuzzer_client as client:
        r = await client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_execute_endpoint_happy_path(fuzzer_client):
    async with fuzzer_client as client:
        r = await client.post("/execute", json={"method": "GET", "path": "/health"})
    assert r.status_code == 200
    body = r.json()
    assert body["status_code"] == 200
    assert body["body"] == {"status": "ok"}


async def test_execute_endpoint_with_path_params_and_headers(fuzzer_client):
    async with fuzzer_client as client:
        r = await client.post(
            "/execute",
            json={
                "method": "GET",
                "path": "/users/{user_id}",
                "path_params": {"user_id": 1},
                "headers": {"x-api-token": "alice-token"},
            },
        )
    assert r.status_code == 200
    assert r.json()["body"]["username"] == "alice"


async def test_execute_endpoint_rejects_invalid_test_case_with_400(fuzzer_client):
    """Missing a required path_param is a validation error — the request
    never reaches the target at all, so it must be a 400, not whatever
    the target might have returned."""
    async with fuzzer_client as client:
        r = await client.post("/execute", json={"method": "GET", "path": "/users/{user_id}"})
    assert r.status_code == 400
    assert "path_params" in r.json()["detail"]


async def test_execute_endpoint_rejects_bad_method_with_400(fuzzer_client):
    async with fuzzer_client as client:
        r = await client.post("/execute", json={"method": "TRACE", "path": "/health"})
    assert r.status_code == 400


async def test_execute_endpoint_surfaces_target_404_as_normal_200_response(fuzzer_client):
    """The fuzzer's own endpoint returns 200 (it successfully executed
    the test) even though the TARGET returned 404 — those are different
    things and must not be conflated."""
    async with fuzzer_client as client:
        r = await client.post(
            "/execute",
            json={
                "method": "GET",
                "path": "/users/{user_id}",
                "path_params": {"user_id": 999999},
                "headers": {"x-api-token": "alice-token"},
            },
        )
    assert r.status_code == 200
    assert r.json()["status_code"] == 404
