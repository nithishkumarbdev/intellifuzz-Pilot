"""
Turns raw LLM text output into executable MutatedTestCases, or rejects
it. This module is the concrete enforcement of the phase's core rule:
LLM proposes, application validates, deterministic engine executes.

Nothing here ever raises on bad model output — a malformed response is
just an empty accepted list plus a parse-error string, handled exactly
like any other provider failure by the caller (pipeline.py).

Security boundaries enforced here, all independent of what the model
claims about itself:
- The model's echoed endpoint must match the endpoint we actually
  asked about, or the ENTIRE batch is rejected. This is what prevents
  a prompt-injection attempt hidden in OpenAPI description text from
  redirecting candidates at a different endpoint — we don't trust the
  model's self-report, we check it.
- A candidate's target_location must resolve to a field that actually
  exists on THIS endpoint (path/query param or body field) or it's
  rejected. This is what prevents the model from inventing a field
  that was never in the spec.
- Only "path" / "query" / "body" locations are accepted — never
  "header", keeping this generator out of auth-header fuzzing (out of
  scope, same as Phase 4's own deterministic engine).
- The model can never supply a host, scheme, or base URL — there's no
  field in the schema for it, and even if the model tried, nothing
  here reads or uses anything but target_location and proposed_value.
  The target always comes from `endpoint` (our own parsed spec) and
  `settings.base_url` (application configuration), never from LLM
  output.
- Value TYPE mismatches (e.g. a string proposed for an integer field)
  are deliberately NOT rejected — that's often exactly the point of an
  interesting test case, not a validation failure.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import ValidationError as PydanticValidationError

from app.fuzzer.mutations.models import MutatedTestCase, Mutation, MutationType
from app.generator.models import GeneratorConfig, LLMGenerationResponse, LLMTestCandidateRaw, RejectedCandidate
from app.parser.models import Endpoint
from app.runner.models import TestCase

SUPPORTED_LOCATION_KINDS = {"path", "query", "body"}


def parse_llm_response(raw_text: str) -> tuple[Optional[LLMGenerationResponse], Optional[str]]:
    """Returns (parsed_response, None) on success, or (None, error_message)
    on any failure — invalid JSON, wrong shape, missing fields. Never
    raises."""
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"invalid JSON: {exc}"

    try:
        parsed = LLMGenerationResponse.model_validate(data)
    except PydanticValidationError as exc:
        return None, f"response did not match the expected schema: {exc}"

    return parsed, None


def _known_field_names(endpoint: Endpoint) -> dict[str, set[str]]:
    return {
        "path": {p.name for p in endpoint.path_parameters},
        "query": {p.name for p in endpoint.query_parameters},
        "body": {f.name for f in endpoint.request_body.fields} if endpoint.request_body else set(),
    }


def _apply_candidate(baseline_test_case: TestCase, kind: str, field_name: str, value: Any) -> tuple[TestCase, Any]:
    """Returns (mutated_test_case, original_value)."""
    mutated_case = baseline_test_case.model_copy(deep=True)
    original_value = None

    if kind == "path":
        original_value = mutated_case.path_params.get(field_name)
        mutated_case.path_params[field_name] = value
    elif kind == "query":
        original_value = mutated_case.query_params.get(field_name)
        mutated_case.query_params[field_name] = value
    else:  # body
        body = mutated_case.body if isinstance(mutated_case.body, dict) else {}
        original_value = body.get(field_name)
        body = dict(body)
        body[field_name] = value
        mutated_case.body = body

    return mutated_case, original_value


def validate_candidates(
    response: LLMGenerationResponse,
    endpoint: Endpoint,
    baseline_test_case: TestCase,
    config: Optional[GeneratorConfig] = None,
) -> tuple[list[MutatedTestCase], list[RejectedCandidate]]:
    config = config or GeneratorConfig()
    baseline_key = f"{endpoint.method} {endpoint.path}"

    # Endpoint echo must match exactly what we asked about — reject the
    # WHOLE batch if it doesn't. See module docstring.
    if response.endpoint.method.upper() != endpoint.method.upper() or response.endpoint.path != endpoint.path:
        detail = f"expected {endpoint.method} {endpoint.path}, got {response.endpoint.method} {response.endpoint.path}"
        return [], [RejectedCandidate(raw=raw, reason="endpoint_mismatch", detail=detail) for raw in response.tests]

    known = _known_field_names(endpoint)
    accepted: list[MutatedTestCase] = []
    rejected: list[RejectedCandidate] = []

    in_bounds_candidates = response.tests[: config.max_candidates_per_endpoint]
    over_limit_candidates = response.tests[config.max_candidates_per_endpoint :]

    for raw in in_bounds_candidates:
        location = raw.target_location or ""
        if "." not in location:
            rejected.append(RejectedCandidate(raw=raw, reason="malformed_location", detail=location))
            continue

        kind, field_name = location.split(".", 1)
        if kind not in SUPPORTED_LOCATION_KINDS:
            rejected.append(RejectedCandidate(raw=raw, reason="unsupported_location_kind", detail=kind))
            continue

        if field_name not in known[kind]:
            rejected.append(RejectedCandidate(raw=raw, reason="unknown_field", detail=location))
            continue

        mutated_case, original_value = _apply_candidate(baseline_test_case, kind, field_name, raw.proposed_value)
        mutation = Mutation(
            mutation_type=MutationType.LLM_SUGGESTED,
            location=location,
            field_name=field_name,
            original_value=original_value,
            mutated_value=raw.proposed_value,
        )
        accepted.append(
            MutatedTestCase(
                baseline_key=baseline_key,
                mutation=mutation,
                test_case=mutated_case,
                source="llm",
                reason=raw.reason,
                confidence=raw.confidence,
            )
        )

    for raw in over_limit_candidates:
        rejected.append(
            RejectedCandidate(raw=raw, reason="exceeds_max_candidates", detail=raw.target_location or "")
        )

    return accepted, rejected
