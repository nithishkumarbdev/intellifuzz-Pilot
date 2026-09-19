"""
Validates a TestCase before it's ever executed.

This module matters more than its size suggests: it's the checkpoint
that later phases (especially LLM-generated test cases, in Phase 5+)
must pass through before touching a real target. "Never trust raw
input" starts here, even though today the only caller is a human or
a script — not yet an LLM.
"""

from __future__ import annotations

import re

from app.runner.models import TestCase

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
PATH_PARAM_PATTERN = re.compile(r"\{([^{}]+)\}")


class ValidationError(Exception):
    """Raised when a TestCase is structurally invalid and must not be executed."""


def validate_test_case(test_case: TestCase) -> None:
    method = test_case.method.upper()
    if method not in ALLOWED_METHODS:
        raise ValidationError(
            f"Unsupported HTTP method '{test_case.method}'. Allowed: {sorted(ALLOWED_METHODS)}"
        )

    if not test_case.path.startswith("/"):
        raise ValidationError(f"Path must start with '/': {test_case.path!r}")

    required_placeholders = set(PATH_PARAM_PATTERN.findall(test_case.path))
    provided = set(test_case.path_params.keys())
    missing = required_placeholders - provided
    if missing:
        raise ValidationError(
            f"Path {test_case.path!r} requires path_params {sorted(missing)}, "
            f"but only {sorted(provided)} were provided"
        )

    for name, value in test_case.headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValidationError(
                f"Header {name!r} must be a string name/value pair, got value of type {type(value).__name__}"
            )
