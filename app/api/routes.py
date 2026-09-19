"""
The fuzzer's own backend API.

For Phase 2 this is intentionally small: one endpoint that takes a
structured TestCase and returns a normalized TestResult. This is the
seam later phases plug into — the mutation engine and LLM generator
will produce TestCases; n8n will eventually call an endpoint like this
(or a higher-level /scans endpoint built on top of it) to drive a scan.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import get_http_client, get_settings
from app.core.config import RunnerSettings
from app.runner.http_runner import execute_test_case
from app.runner.models import TestCase, TestResult
from app.runner.validation import ValidationError

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/execute", response_model=TestResult)
async def execute(
    test_case: TestCase,
    settings: RunnerSettings = Depends(get_settings),
    client: httpx.AsyncClient = Depends(get_http_client),
) -> TestResult:
    try:
        return await execute_test_case(test_case, settings, client=client)
    except ValidationError as exc:
        # A structurally invalid test case never gets sent anywhere —
        # this is a 400 (bad input), distinct from any status code the
        # target itself might return.
        raise HTTPException(status_code=400, detail=str(exc)) from exc
