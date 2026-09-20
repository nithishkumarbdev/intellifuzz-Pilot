"""
Tests for app.generator.provider — the provider abstraction and its
implementations. No real API key or network access anywhere in this
file, including for OpenAICompatibleProvider: its HTTP calls are
intercepted via httpx's own mock transport.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.generator.provider import (
    FailingLLMProvider,
    FakeLLMProvider,
    OpenAICompatibleProvider,
    ProviderAuthError,
    ProviderError,
    ProviderTimeout,
    ProviderUnavailable,
)


# ---------------------------------------------------------------------------
# FakeLLMProvider
# ---------------------------------------------------------------------------


async def test_fake_provider_fixed_response():
    provider = FakeLLMProvider(fixed_response="hello")
    assert await provider.generate("any prompt") == "hello"


async def test_fake_provider_response_fn_sees_the_prompt():
    provider = FakeLLMProvider(response_fn=lambda prompt: f"echo: {prompt}")
    assert await provider.generate("test") == "echo: test"


def test_fake_provider_requires_exactly_one_config():
    with pytest.raises(ValueError):
        FakeLLMProvider()
    with pytest.raises(ValueError):
        FakeLLMProvider(response_fn=lambda p: p, fixed_response="both")


# ---------------------------------------------------------------------------
# FailingLLMProvider
# ---------------------------------------------------------------------------


async def test_failing_provider_raises_configured_error():
    provider = FailingLLMProvider(ProviderTimeout("simulated"))
    with pytest.raises(ProviderTimeout):
        await provider.generate("prompt")


# ---------------------------------------------------------------------------
# OpenAICompatibleProvider — HTTP mocked, no real network
# ---------------------------------------------------------------------------


_RealAsyncClient = httpx.AsyncClient


def _mock_client(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return _RealAsyncClient(transport=transport)


async def test_openai_compatible_valid_response(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"tests": []}'}}]})

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="fake-key", model="fake-model")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    result = await provider.generate("some prompt")
    assert result == '{"tests": []}'


async def test_openai_compatible_sends_system_and_user_messages(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="fake-key", model="fake-model")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    await provider.generate("USER PROMPT HERE", max_output_tokens=500)

    messages = captured["body"]["messages"]
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert messages[1]["content"] == "USER PROMPT HERE"
    assert captured["body"]["max_tokens"] == 500


async def test_openai_compatible_auth_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid api key"})

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="bad-key", model="fake-model")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    with pytest.raises(ProviderAuthError):
        await provider.generate("prompt")


async def test_openai_compatible_rate_limited(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="rate limited")

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="k", model="m")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    with pytest.raises(ProviderError):
        await provider.generate("prompt")


async def test_openai_compatible_malformed_response_shape(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="k", model="m")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    with pytest.raises(ProviderError):
        await provider.generate("prompt")


async def test_openai_compatible_connection_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="k", model="m")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    with pytest.raises(ProviderUnavailable):
        await provider.generate("prompt")


async def test_openai_compatible_timeout(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    provider = OpenAICompatibleProvider(base_url="https://fake.test/v1", api_key="k", model="m")
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: _mock_client(handler))

    with pytest.raises(ProviderTimeout):
        await provider.generate("prompt")


# ---------------------------------------------------------------------------
# Every provider satisfies the same interface (contract check)
# ---------------------------------------------------------------------------


def test_all_providers_are_llm_provider_instances():
    from app.generator.provider import LLMProvider

    assert isinstance(FakeLLMProvider(fixed_response="x"), LLMProvider)
    assert isinstance(FailingLLMProvider(ProviderError("x")), LLMProvider)
    assert isinstance(OpenAICompatibleProvider(base_url="https://x", api_key="k", model="m"), LLMProvider)
