"""
The LLM provider abstraction, its failure modes, and two
implementations:

- FakeLLMProvider / FailingLLMProvider — test doubles, no network,
  used by the whole test suite and by the offline demo. The project
  must never require a real API key to run its tests (or even to
  demonstrate the full pipeline).
- OpenAICompatibleProvider — a real provider, built on httpx (already
  a project dependency, so this adds no new one) against the
  OpenAI-compatible chat-completions shape. That shape is
  intentionally the most portable choice: it works unmodified against
  OpenAI itself, OpenRouter, and most local model gateways (Ollama's
  OpenAI-compat mode, vLLM, etc.), which is what "provider-agnostic"
  concretely buys us without a provider-specific SDK per vendor. Adding
  a second real provider (e.g. Anthropic's native Messages API, which
  uses a different shape) later is a small, additive change against
  this same LLMProvider interface — not attempted here to keep this
  phase's scope to "at least one real provider", per its own definition
  of done.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

import httpx


class ProviderError(Exception):
    """Base class for any LLM provider failure. Always caught by the
    generation pipeline — an LLM failure degrades a scan to
    deterministic-only, it never aborts it."""


class ProviderTimeout(ProviderError):
    pass


class ProviderUnavailable(ProviderError):
    pass


class ProviderAuthError(ProviderError):
    pass


class LLMProvider(ABC):
    """A provider only ever does one thing: turn a prompt string into a
    raw text response. It has no knowledge of endpoints, TestCases, or
    the fuzzer at all — that separation is what keeps candidate
    validation (candidates.py) provider-agnostic too."""

    @abstractmethod
    async def generate(self, prompt: str, *, max_output_tokens: int = 1024) -> str:
        """Returns the raw text response. Raises a ProviderError
        subclass on failure — never returns None, never silently
        swallows an error."""
        raise NotImplementedError


class FakeLLMProvider(LLMProvider):
    """A fully controllable test double — no network, fully
    deterministic given its configuration. Exactly one of
    `response_fn` or `fixed_response` must be given."""

    def __init__(self, response_fn: Optional[Callable[[str], str]] = None, fixed_response: Optional[str] = None):
        if (response_fn is None) == (fixed_response is None):
            raise ValueError("FakeLLMProvider needs exactly one of response_fn or fixed_response")
        self._response_fn = response_fn
        self._fixed_response = fixed_response

    async def generate(self, prompt: str, *, max_output_tokens: int = 1024) -> str:
        if self._response_fn is not None:
            return self._response_fn(prompt)
        return self._fixed_response  # type: ignore[return-value]


class FailingLLMProvider(LLMProvider):
    """A test double that always raises a configured ProviderError —
    used to test failure-isolation (an LLM failure must never break
    deterministic fuzzing)."""

    def __init__(self, error: ProviderError):
        self._error = error

    async def generate(self, prompt: str, *, max_output_tokens: int = 1024) -> str:
        raise self._error


class OpenAICompatibleProvider(LLMProvider):
    """Real provider: calls POST {base_url}/chat/completions with the
    standard OpenAI request/response shape. The security-boundary
    system prompt is injected here, inside the provider, rather than
    left to whatever the caller passes as `prompt` — so it can't be
    accidentally dropped by a caller that forgets to include it."""

    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: float = 30.0):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds

    async def generate(self, prompt: str, *, max_output_tokens: int = 1024) -> str:
        from app.generator.prompt import SYSTEM_PROMPT  # local import: avoids a provider<->prompt import cycle

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_output_tokens,
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(
                    f"{self._base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ProviderTimeout(str(exc) or "LLM request timed out") from exc
        except httpx.ConnectError as exc:
            raise ProviderUnavailable(str(exc) or "Could not reach LLM provider") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(str(exc)) from exc

        if response.status_code == 401:
            raise ProviderAuthError("LLM provider rejected the API key")
        if response.status_code == 429:
            raise ProviderError("LLM provider rate-limited this request")
        if response.status_code >= 400:
            raise ProviderError(f"LLM provider returned HTTP {response.status_code}: {response.text[:200]}")

        try:
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError(f"Unexpected response shape from LLM provider: {exc}") from exc
