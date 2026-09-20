"""Tests for app.generator.prompt."""

from __future__ import annotations

import json

from app.generator.prompt import CONTEXT_MARKER, SYSTEM_PROMPT, build_prompt, heuristic_offline_response


def _sample_context():
    return {
        "method": "POST",
        "path": "/users",
        "path_parameters": [],
        "query_parameters": [],
        "request_body_fields": [
            {"name": "username", "required": True, "schema": {"type": "string"}},
            {"name": "age", "required": True, "schema": {"type": "integer"}},
        ],
        "baseline_request": {"path_params": {}, "query_params": {}, "body": {"username": "test", "age": 1}},
        "baseline_status_code": 201,
    }


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------


def test_prompt_contains_the_context_json():
    context = _sample_context()
    prompt = build_prompt(context, max_candidates=5)
    assert json.dumps(context, indent=2) in prompt


def test_prompt_respects_max_candidates_setting():
    prompt = build_prompt(_sample_context(), max_candidates=3)
    assert "at most 3 tests" in prompt


def test_prompt_does_not_include_the_system_prompt_text():
    """The system prompt is injected separately by OpenAICompatibleProvider
    (as an actual system-role message), never concatenated into the same
    string as the untrusted context — verified here by checking the
    user-facing prompt text doesn't duplicate it."""
    prompt = build_prompt(_sample_context(), max_candidates=5)
    assert SYSTEM_PROMPT not in prompt


def test_system_prompt_tells_model_to_treat_context_as_data():
    assert "DATA" in SYSTEM_PROMPT
    assert "ignore" in SYSTEM_PROMPT.lower()


# ---------------------------------------------------------------------------
# heuristic_offline_response
# ---------------------------------------------------------------------------


def test_heuristic_response_is_valid_json_matching_schema():
    context = _sample_context()
    prompt = build_prompt(context, max_candidates=5)
    raw = heuristic_offline_response(prompt)
    parsed = json.loads(raw)
    assert parsed["endpoint"] == {"method": "POST", "path": "/users"}
    assert isinstance(parsed["tests"], list)


def test_heuristic_response_proposes_something_for_each_body_field():
    context = _sample_context()
    prompt = build_prompt(context, max_candidates=5)
    parsed = json.loads(heuristic_offline_response(prompt))
    locations = {t["target_location"] for t in parsed["tests"]}
    assert "body.username" in locations
    assert "body.age" in locations


def test_heuristic_response_respects_max_candidates():
    context = _sample_context()
    context["request_body_fields"] = [
        {"name": f"field_{i}", "required": True, "schema": {"type": "string"}} for i in range(10)
    ]
    prompt = build_prompt(context, max_candidates=5)
    parsed = json.loads(heuristic_offline_response(prompt, max_candidates=2))
    assert len(parsed["tests"]) <= 2


def test_heuristic_response_enum_field_proposes_enum_mutation():
    context = _sample_context()
    context["request_body_fields"] = [
        {"name": "status", "required": True, "schema": {"type": "string", "enum": ["active", "inactive"]}}
    ]
    prompt = build_prompt(context, max_candidates=5)
    parsed = json.loads(heuristic_offline_response(prompt))
    status_test = next(t for t in parsed["tests"] if t["target_location"] == "body.status")
    assert status_test["mutation_type"] == "semantic_enum"


def test_heuristic_response_handles_garbage_prompt_gracefully():
    """If the prompt doesn't contain a valid embedded context (shouldn't
    happen in practice, but the fake provider must not crash), returns
    an empty-but-valid response rather than raising."""
    parsed = json.loads(heuristic_offline_response("this is not a real prompt at all"))
    assert parsed["tests"] == []
