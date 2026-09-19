"""
FastAPI dependencies for the fuzzer's own backend API.

get_http_client is the important one: it's what lets tests swap in an
httpx.ASGITransport-backed client (pointed at an in-process target app)
instead of a real network client, via FastAPI's dependency_overrides.
"""

from __future__ import annotations

from functools import lru_cache
from typing import AsyncGenerator

import httpx

from app.core.config import RunnerSettings, load_settings


@lru_cache
def get_settings() -> RunnerSettings:
    return load_settings()


async def get_http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    settings = get_settings()
    client = httpx.AsyncClient(timeout=settings.request_timeout_seconds)
    try:
        yield client
    finally:
        await client.aclose()
