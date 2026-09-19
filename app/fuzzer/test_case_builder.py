"""
Turns a parsed Endpoint (Phase 1) into a "normal", valid TestCase
(Phase 2's input type) — a request a well-behaved client would send.

Auth handling assumption (explicitly called out, per the project's own
"never pretend auth can be fully inferred from the spec" principle):
OpenAPI's `security` field is often absent even on endpoints that
genuinely require auth, if the API used a plain header parameter
instead of a formal security scheme (this is true of our own
vulnerable-api — see Phase 1/2 notes). So rather than relying solely
on `endpoint.security`, we also recognize a header *parameter* whose
name matches the configured auth header and treat it as "this needs
auth", regardless of whether the spec marked it required. This is a
heuristic, not a guarantee — it's documented here rather than hidden.
"""

from __future__ import annotations

from app.core.config import RunnerSettings
from app.fuzzer.valid_values import generate_valid_value
from app.parser.models import Endpoint, ParamLocation
from app.runner.models import TestCase


def build_baseline_test_case(endpoint: Endpoint, settings: RunnerSettings) -> TestCase:
    path_params: dict = {}
    query_params: dict = {}
    headers: dict = {}

    for param in endpoint.parameters:
        if param.location == ParamLocation.PATH:
            # Path params are always required by the OpenAPI spec itself;
            # always fill them.
            path_params[param.name] = generate_valid_value(param.schema_)

        elif param.location == ParamLocation.QUERY:
            # Keep the baseline request minimal and predictable: only
            # include query params the spec actually requires. Optional
            # ones are legitimately absent in a "normal" request.
            if param.required:
                query_params[param.name] = generate_valid_value(param.schema_)

        elif param.location == ParamLocation.HEADER:
            is_configured_auth_header = (
                settings.auth_header_name is not None
                and param.name.lower() == settings.auth_header_name.lower()
            )
            if is_configured_auth_header:
                if settings.auth_header_value is not None:
                    headers[param.name] = settings.auth_header_value
                elif param.required:
                    # No credential configured but the header is required —
                    # send *something* type-correct so the request is at
                    # least well-formed; it will likely fail auth, and
                    # that's honest: we don't have real credentials.
                    headers[param.name] = generate_valid_value(param.schema_)
            elif param.required:
                headers[param.name] = generate_valid_value(param.schema_)

    body = None
    if endpoint.request_body is not None:
        body = {
            field.name: generate_valid_value(field.schema_)
            for field in endpoint.request_body.fields
            if field.required
        }

    return TestCase(
        method=endpoint.method,
        path=endpoint.path,
        path_params=path_params,
        query_params=query_params,
        headers=headers,
        body=body,
    )
