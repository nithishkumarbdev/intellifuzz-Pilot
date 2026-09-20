"""
Tests for app.generator.config — proving the LLM is genuinely optional:
missing configuration must degrade to None (skip LLM generation), never
raise.
"""

from __future__ import annotations

from app.generator.config import LLMSettings, build_provider, load_llm_settings
from app.generator.provider import FakeLLMProvider, OpenAICompatibleProvider


def test_default_settings_are_fake_provider():
    settings = LLMSettings()
    assert settings.provider == "fake"


def test_load_llm_settings_defaults_when_env_unset(monkeypatch):
    for var in ("LLM_PROVIDER", "LLM_MODEL", "LLM_API_KEY", "LLM_BASE_URL", "LLM_TIMEOUT_SECONDS"):
        monkeypatch.delenv(var, raising=False)
    settings = load_llm_settings()
    assert settings.provider == "fake"
    assert settings.api_key is None


def test_load_llm_settings_reads_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.setenv("LLM_API_KEY", "test-key-not-real")
    monkeypatch.setenv("LLM_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "45")

    settings = load_llm_settings()
    assert settings.provider == "openai_compatible"
    assert settings.model == "gpt-4o"
    assert settings.api_key == "test-key-not-real"
    assert settings.base_url == "https://example.test/v1"
    assert settings.timeout_seconds == 45.0


def test_build_provider_fake_returns_fake_provider():
    provider = build_provider(LLMSettings(provider="fake"))
    assert isinstance(provider, FakeLLMProvider)


def test_build_provider_openai_compatible_without_key_returns_none():
    """The core 'LLM is optional' contract: a real provider requested
    but missing its API key must degrade gracefully to no LLM at all —
    never raise, never crash a scan."""
    provider = build_provider(LLMSettings(provider="openai_compatible", api_key=None))
    assert provider is None


def test_build_provider_openai_compatible_with_key_returns_real_provider():
    provider = build_provider(LLMSettings(provider="openai_compatible", api_key="not-a-real-key"))
    assert isinstance(provider, OpenAICompatibleProvider)


def test_build_provider_unknown_provider_name_returns_none():
    provider = build_provider(LLMSettings(provider="something_unrecognized"))
    assert provider is None
