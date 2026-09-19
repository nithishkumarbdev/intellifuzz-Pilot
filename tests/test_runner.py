"""
Tests for app.runner.* — validation, request building, and execution.

Most tests use `asgi_client` (in-process, no real socket) since what's
under test here is "did we build and send the right request, and parse
the response correctly" — not raw network behavior. Timeout and
connection-error tests live in test_runner_network_errors.py, since
those genuinely need real sockets.
"""

from __future__ import annotations

import pytest

from app.core.config import RunnerSettings
from app.runner.http_runner import execute_test_case
from app.runner.models import TestCase
from app.runner.validation import ValidationError, validate_test_case

SETTINGS = RunnerSettings(base_url="http://vulnerable-api-test")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validation_rejects_unknown_method():
    with pytest.raises(ValidationError, match="Unsupported HTTP method"):
        validate_test_case(TestCase(method="FETCH", path="/health"))


def test_validation_rejects_path_without_leading_slash():
    with pytest.raises(ValidationError, match="must start with"):
        validate_test_case(TestCase(method="GET", path="health"))


def test_validation_rejects_missing_path_param():
    with pytest.raises(ValidationError, match="requires path_params"):
        validate_test_case(TestCase(method="GET", path="/users/{user_id}"))


def test_validation_accepts_valid_case():
    validate_test_case(TestCase(method="GET", path="/users/{user_id}", path_params={"user_id": 1}))


def test_validation_rejects_non_string_header_value():
    # Pydantic already enforces str types at TestCase *construction*
    # time, so to actually exercise validate_test_case's own defensive
    # check we mutate the headers dict in place afterward — simulating
    # a future mutation engine that manipulates fields directly rather
    # than going through the constructor (a very plausible scenario
    # once we're deliberately generating type-confused test cases).
    test_case = TestCase(method="GET", path="/health")
    test_case.headers["X-Count"] = 5  # type: ignore[assignment]
    with pytest.raises(ValidationError, match="must be a string"):
        validate_test_case(test_case)


# ---------------------------------------------------------------------------
# Basic HTTP methods
# ---------------------------------------------------------------------------


async def test_get_health(asgi_client):
    result = await execute_test_case(TestCase(method="GET", path="/health"), SETTINGS, client=asgi_client)
    assert result.executed
    assert result.status_code == 200
    assert result.body == {"status": "ok"}
    assert result.body_is_json is True


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE"])
async def test_all_methods_reach_target_correctly(asgi_client, method):
    body = {"hello": "world"} if method in ("POST", "PUT", "PATCH") else None
    result = await execute_test_case(
        TestCase(method=method, path="/echo", body=body), SETTINGS, client=asgi_client
    )
    assert result.status_code == 200
    assert result.body["method"] == method
    assert result.body["body"] == body


# ---------------------------------------------------------------------------
# Path parameters
# ---------------------------------------------------------------------------


async def test_path_parameter_resolution(asgi_client):
    result = await execute_test_case(
        TestCase(
            method="GET",
            path="/users/{user_id}",
            path_params={"user_id": 1},
            headers={"x-api-token": "alice-token"},
        ),
        SETTINGS,
        client=asgi_client,
    )
    assert result.status_code == 200
    assert result.body["username"] == "alice"
    assert result.request.url == "http://vulnerable-api-test/users/1"


async def test_path_parameter_missing_target_returns_404_not_a_runner_error(asgi_client):
    """A 404 from the target is a normal, successfully-executed result —
    not an ErrorInfo. This is the distinction section 18 of the spec
    insists on: runner records what happened, doesn't judge it."""
    result = await execute_test_case(
        TestCase(
            method="GET",
            path="/users/{user_id}",
            path_params={"user_id": 9999},
            headers={"x-api-token": "alice-token"},
        ),
        SETTINGS,
        client=asgi_client,
    )
    assert result.executed
    assert result.error is None
    assert result.status_code == 404


async def test_path_parameter_with_special_characters_is_url_encoded(asgi_client):
    """Proves path params are properly URL-encoded before being sent —
    matters once the mutation engine starts feeding in things like
    '../' or spaces as path param values. What the runner controls is
    the encoding; how the target's router then responds to that is
    target-specific and not something to assert on here."""
    result = await execute_test_case(
        TestCase(method="GET", path="/users/{user_id}", path_params={"user_id": "../admin"}),
        SETTINGS,
        client=asgi_client,
    )
    assert result.executed
    # The slash must be percent-encoded (%2F), not sent as a literal '/'
    # that would change the request's path structure.
    assert result.request.url == "http://vulnerable-api-test/users/..%2Fadmin"
    assert "/users/../admin" not in result.request.url


# ---------------------------------------------------------------------------
# Query parameters
# ---------------------------------------------------------------------------


async def test_query_parameters_reach_target(asgi_client):
    result = await execute_test_case(
        TestCase(method="GET", path="/echo", query_params={"limit": 10, "offset": 20}),
        SETTINGS,
        client=asgi_client,
    )
    assert result.status_code == 200
    # Query params always arrive as strings over the wire — that's normal
    # HTTP, not a bug in the runner.
    assert result.body["query_params"] == {"limit": "10", "offset": "20"}


# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------


async def test_custom_headers_reach_target(asgi_client):
    result = await execute_test_case(
        TestCase(method="GET", path="/echo", headers={"x-custom-header": "hello"}),
        SETTINGS,
        client=asgi_client,
    )
    assert result.body["headers"]["x-custom-header"] == "hello"


async def test_configured_auth_header_is_injected_when_not_overridden(asgi_client):
    settings_with_auth = RunnerSettings(
        base_url="http://vulnerable-api-test",
        auth_header_name="x-api-token",
        auth_header_value="bob-token",
    )
    result = await execute_test_case(
        TestCase(method="GET", path="/echo"), settings_with_auth, client=asgi_client
    )
    assert result.body["headers"]["x-api-token"] == "bob-token"


async def test_test_case_header_overrides_configured_default_auth(asgi_client):
    """A fuzzer testing 'what happens with a different/missing token'
    must win over the configured default — see request_builder's
    docstring for why this matters."""
    settings_with_auth = RunnerSettings(
        base_url="http://vulnerable-api-test",
        auth_header_name="x-api-token",
        auth_header_value="bob-token",
    )
    result = await execute_test_case(
        TestCase(method="GET", path="/echo", headers={"x-api-token": "alice-token"}),
        settings_with_auth,
        client=asgi_client,
    )
    assert result.body["headers"]["x-api-token"] == "alice-token"


async def test_sensitive_headers_are_masked_in_result(asgi_client):
    result = await execute_test_case(
        TestCase(method="GET", path="/echo", headers={"x-api-token": "alice-token"}),
        SETTINGS,
        client=asgi_client,
    )
    # The real value was sent to the target (proven above) but must never
    # appear in the stored/echoed request evidence.
    assert result.request.headers["x-api-token"] == "***MASKED***"


# ---------------------------------------------------------------------------
# JSON bodies
# ---------------------------------------------------------------------------


async def test_post_json_body_reaches_target(asgi_client):
    payload = {"username": "newuser", "email": "n@example.com", "age": 30}
    result = await execute_test_case(
        TestCase(method="POST", path="/users", body=payload), SETTINGS, client=asgi_client
    )
    assert result.status_code == 201
    assert result.body["username"] == "newuser"
    assert result.body["age"] == 30


async def test_put_updates_resource(asgi_client):
    result = await execute_test_case(
        TestCase(
            method="PUT",
            path="/users/{user_id}",
            path_params={"user_id": 1},
            headers={"x-api-token": "alice-token"},
            body={"username": "alice2", "email": "alice2@example.com", "age": 40},
        ),
        SETTINGS,
        client=asgi_client,
    )
    assert result.status_code == 200
    assert result.body["username"] == "alice2"


async def test_patch_partial_update(asgi_client):
    result = await execute_test_case(
        TestCase(
            method="PATCH",
            path="/users/{user_id}",
            path_params={"user_id": 2},
            headers={"x-api-token": "bob-token"},
            body={"age": 99},
        ),
        SETTINGS,
        client=asgi_client,
    )
    assert result.status_code == 200
    assert result.body["age"] == 99
    assert result.body["username"] == "bob"  # untouched by partial update


async def test_delete_returns_no_content(asgi_client):
    result = await execute_test_case(
        TestCase(
            method="DELETE",
            path="/users/{user_id}",
            path_params={"user_id": 2},
            headers={"x-api-token": "bob-token"},
        ),
        SETTINGS,
        client=asgi_client,
    )
    assert result.status_code == 204


# ---------------------------------------------------------------------------
# Response handling
# ---------------------------------------------------------------------------


async def test_non_json_response_does_not_crash(asgi_client):
    result = await execute_test_case(TestCase(method="GET", path="/text"), SETTINGS, client=asgi_client)
    assert result.executed
    assert result.status_code == 200
    assert result.body_is_json is False
    assert "plain text" in result.body


async def test_response_time_and_size_are_recorded(asgi_client):
    result = await execute_test_case(TestCase(method="GET", path="/health"), SETTINGS, client=asgi_client)
    assert result.response_time_ms is not None
    assert result.response_time_ms >= 0
    assert result.body_size is not None
    assert result.body_size > 0
