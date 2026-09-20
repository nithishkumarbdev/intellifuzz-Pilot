"""
Builds the structured context sent to the LLM for exactly one
endpoint. Two things this deliberately does NOT include, on purpose,
not by oversight:

1. Headers of any kind — including the auth header's actual VALUE
   (e.g. a real bearer token). The baseline TestCase's `.headers` dict
   is never read here at all. If header-aware test generation is ever
   needed, it should carry header NAMES only, added deliberately later
   — not by accident of including the whole dict.
2. Any other endpoint's information. One endpoint per call keeps the
   prompt small (token/cost control) and keeps "only propose tests for
   the endpoint you were asked about" enforceable (candidates.py
   independently verifies the model's echoed endpoint matches this
   one).
"""

from __future__ import annotations

from typing import Any, Optional

from app.parser.models import Endpoint, Parameter
from app.runner.models import TestCase, TestResult


def _schema_dict(schema) -> dict[str, Any]:
    return schema.model_dump(exclude_none=True, exclude_defaults=True)


def _param_context(param: Parameter) -> dict[str, Any]:
    return {
        "name": param.name,
        "required": param.required,
        "schema": _schema_dict(param.schema_),
    }


def build_endpoint_context(
    endpoint: Endpoint,
    baseline_test_case: TestCase,
    baseline_result: Optional[TestResult] = None,
) -> dict[str, Any]:
    """Structured, LLM-safe context for one endpoint + its baseline
    request. No headers, no other endpoints, no secrets."""
    request_body_fields = []
    if endpoint.request_body is not None:
        request_body_fields = [
            {"name": f.name, "required": f.required, "schema": _schema_dict(f.schema_)}
            for f in endpoint.request_body.fields
        ]

    return {
        "method": endpoint.method,
        "path": endpoint.path,
        "path_parameters": [_param_context(p) for p in endpoint.path_parameters],
        "query_parameters": [_param_context(p) for p in endpoint.query_parameters],
        "request_body_fields": request_body_fields,
        "baseline_request": {
            "path_params": baseline_test_case.path_params,
            "query_params": baseline_test_case.query_params,
            "body": baseline_test_case.body,
        },
        "baseline_status_code": baseline_result.status_code if baseline_result else None,
    }
