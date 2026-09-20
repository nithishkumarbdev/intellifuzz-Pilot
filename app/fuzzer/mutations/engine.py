"""
The mutation engine: takes an Endpoint (Phase 1) and its baseline
TestCase (Phase 3), and produces a deterministic, ordered list of
MutatedTestCases — one logical field changed per mutation, per the
project's own "traceable test cases" requirement.

This module only GENERATES test cases. It never executes an HTTP
request and never inspects a response — see mutation_runner.py for
execution, and (in later phases) the analyzer/rules engine for
interpretation. Keeping this boundary sharp is the whole point of the
phase.
"""

from __future__ import annotations

from typing import Optional

from app.fuzzer.mutations.models import MutatedTestCase, Mutation, MutationConfig, MutationType
from app.fuzzer.mutations.value_mutations import generate_value_mutations
from app.fuzzer.valid_values import generate_valid_value
from app.parser.models import Endpoint
from app.runner.models import TestCase


def generate_mutations_for_test_case(
    endpoint: Endpoint,
    baseline_test_case: TestCase,
    config: Optional[MutationConfig] = None,
) -> list[MutatedTestCase]:
    config = config or MutationConfig()
    baseline_key = f"{endpoint.method} {endpoint.path}"
    mutations: list[MutatedTestCase] = []

    def emit(mutation_type: MutationType, location: str, field_name: str, original, mutated_value, mutated_case: TestCase) -> None:
        mutations.append(
            MutatedTestCase(
                baseline_key=baseline_key,
                mutation=Mutation(
                    mutation_type=mutation_type,
                    location=location,
                    field_name=field_name,
                    original_value=original,
                    mutated_value=mutated_value,
                ),
                test_case=mutated_case,
            )
        )

    # -----------------------------------------------------------------
    # Path parameters — always present in a valid baseline (the OpenAPI
    # spec itself requires them), so no synthesis needed here.
    # -----------------------------------------------------------------
    for param in endpoint.path_parameters:
        if param.name not in baseline_test_case.path_params:
            continue  # shouldn't happen for a valid baseline; skip rather than guess
        original = baseline_test_case.path_params[param.name]
        for mutation_type, mutated_value in generate_value_mutations(param.schema_, original, config):
            mutated_case = baseline_test_case.model_copy(deep=True)
            mutated_case.path_params[param.name] = mutated_value
            emit(mutation_type, f"path.{param.name}", param.name, original, mutated_value, mutated_case)

    # -----------------------------------------------------------------
    # Query parameters — ALL declared params are mutation candidates,
    # not just the required ones the baseline included (Phase 3 only
    # fills required query params; optional ones are still worth
    # fuzzing when a client would supply them). A value is synthesized
    # for any optional param absent from the baseline.
    # -----------------------------------------------------------------
    for param in endpoint.query_parameters:
        present = param.name in baseline_test_case.query_params
        original = baseline_test_case.query_params[param.name] if present else generate_valid_value(param.schema_)

        for mutation_type, mutated_value in generate_value_mutations(param.schema_, original, config):
            mutated_case = baseline_test_case.model_copy(deep=True)
            mutated_case.query_params[param.name] = mutated_value
            emit(mutation_type, f"query.{param.name}", param.name, original, mutated_value, mutated_case)

        if param.required and present:
            mutated_case = baseline_test_case.model_copy(deep=True)
            del mutated_case.query_params[param.name]
            emit(MutationType.MISSING_FIELD, f"query.{param.name}", param.name, original, None, mutated_case)

    # -----------------------------------------------------------------
    # Body fields — same "all declared fields, synthesize if absent"
    # approach as query params, since Phase 3's baseline only includes
    # required body fields (e.g. PATCH /users/{user_id}'s UserUpdate
    # fields are all optional; without this, that endpoint would get
    # zero body mutations at all).
    # -----------------------------------------------------------------
    if endpoint.request_body is not None and endpoint.request_body.fields:
        baseline_body: dict = baseline_test_case.body if isinstance(baseline_test_case.body, dict) else {}

        for field in endpoint.request_body.fields:
            present = field.name in baseline_body
            original = baseline_body[field.name] if present else generate_valid_value(field.schema_)

            for mutation_type, mutated_value in generate_value_mutations(field.schema_, original, config):
                mutated_body = dict(baseline_body)
                mutated_body[field.name] = mutated_value
                mutated_case = baseline_test_case.model_copy(deep=True)
                mutated_case.body = mutated_body
                emit(mutation_type, f"body.{field.name}", field.name, original, mutated_value, mutated_case)

            if field.required and present:
                mutated_body = dict(baseline_body)
                del mutated_body[field.name]
                mutated_case = baseline_test_case.model_copy(deep=True)
                mutated_case.body = mutated_body
                emit(MutationType.MISSING_FIELD, f"body.{field.name}", field.name, original, None, mutated_case)

        # Unexpected field — one mutation testing the whole body's
        # tolerance for an unknown field, per the project's own scoping
        # (one extra field, not a combinatorial explosion of them).
        mutated_body = dict(baseline_body)
        mutated_body["unexpected_fuzz_field"] = "fuzz"
        mutated_case = baseline_test_case.model_copy(deep=True)
        mutated_case.body = mutated_body
        emit(MutationType.UNEXPECTED_FIELD, "body", "unexpected_fuzz_field", None, "fuzz", mutated_case)

    return mutations[: config.max_mutations_per_endpoint]
