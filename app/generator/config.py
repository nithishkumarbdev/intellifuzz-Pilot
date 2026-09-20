"""
LLM configuration and provider construction.

Same philosophy as app.core.config.RunnerSettings: a plain dataclass,
loaded from environment variables, always passed explicitly rather
than read from a global. `build_provider()` is the one place that
turns settings into a live LLMProvider — and it returns None (never
raises) whenever the LLM isn't usably configured, because the whole
point of this phase is that the LLM is optional: a missing API key
degrades a scan to deterministic-only, it never breaks it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from app.generator.prompt import heuristic_offline_response
from app.generator.provider import FakeLLMProvider, LLMProvider, OpenAICompatibleProvider


@dataclass
class LLMSettings:
    provider: str = "fake"  # "fake" | "openai_compatible"
    model: str = "gpt-4o-mini"
    api_key: Optional[str] = None
    base_url: str = "https://api.openai.com/v1"
    timeout_seconds: float = 30.0


def load_llm_settings() -> LLMSettings:
    return LLMSettings(
        provider=os.getenv("LLM_PROVIDER", "fake"),
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        api_key=os.getenv("LLM_API_KEY"),
        base_url=os.getenv("LLM_BASE_URL", "https://api.openai.com/v1"),
        timeout_seconds=float(os.getenv("LLM_TIMEOUT_SECONDS", "30")),
    )


def build_provider(settings: LLMSettings) -> Optional[LLMProvider]:
    """
    Returns None whenever the LLM isn't usably configured — never
    raises. Callers treat None as "skip LLM generation for this run",
    exactly like any other provider failure.
    """
    if settings.provider == "fake":
        # LLM_PROVIDER=fake explicitly requests the offline, endpoint-
        # aware heuristic provider — used for demos, CI, and interviews
        # where a real API key isn't available or desired.
        return FakeLLMProvider(response_fn=heuristic_offline_response)

    if settings.provider == "openai_compatible":
        if not settings.api_key:
            return None
        return OpenAICompatibleProvider(
            base_url=settings.base_url,
            api_key=settings.api_key,
            model=settings.model,
            timeout_seconds=settings.timeout_seconds,
        )

    return None
