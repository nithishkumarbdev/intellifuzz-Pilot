"""
Tests for app.parser.openapi_parser.

Uses the real vulnerable-api's generated OpenAPI spec (examples/vulnerable-api-openapi.json)
as the "happy path" fixture, plus hand-built malformed specs to check
that parsing fails loudly and specifically instead of silently
producing a wrong/partial result.
"""

from pathlib import Path

import pytest

from app.parser.models import ParamLocation
from app.parser.openapi_parser import ParserError, parse_openapi_spec

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"
VULN_API_SPEC = EXAMPLES_DIR / "vulnerable-api-openapi.json"


@pytest.fixture(scope="module")
def parsed_vuln_api():
    return parse_openapi_spec(VULN_API_SPEC)


def test_parses_basic_metadata(parsed_vuln_api):
    assert parsed_vuln_api.title == "Vulnerable Shop API"
    assert parsed_vuln_api.version == "1.0.0"


def test_discovers_all_endpoints(parsed_vuln_api):
    paths_and_methods = {(e.path, e.method) for e in parsed_vuln_api.endpoints}
    assert ("/health", "GET") in paths_and_methods
    assert ("/users/{user_id}", "GET") in paths_and_methods
    assert ("/users", "POST") in paths_and_methods
    assert ("/login", "POST") in paths_and_methods
    assert ("/admin/stats", "GET") in paths_and_methods
    assert ("/orders", "POST") in paths_and_methods
    assert ("/orders/{order_id}", "GET") in paths_and_methods
    # vulnerable-api grew in Phase 2 (PUT/PATCH/DELETE on /users/{user_id},
    # plus /slow, /text, /echo test-scaffolding endpoints) — 17 operations
    # total. The exact number matters less than proving the parser finds
    # every operation, not just GETs or just the original Phase 1 set.
    assert parsed_vuln_api.endpoint_count() == 17


def test_extracts_path_parameters(parsed_vuln_api):
    get_user = next(e for e in parsed_vuln_api.endpoints if e.path == "/users/{user_id}" and e.method == "GET")
    assert len(get_user.path_parameters) == 1
    param = get_user.path_parameters[0]
    assert param.name == "user_id"
    assert param.location == ParamLocation.PATH
    assert param.required is True
    assert param.schema_.type == "integer"


def test_resolves_request_body_ref(parsed_vuln_api):
    """
    POST /users has requestBody -> content -> application/json -> schema
    -> $ref: '#/components/schemas/UserCreate'. This test proves the
    $ref resolver actually walks that chain instead of returning an
    empty/unresolved body.
    """
    create_user = next(e for e in parsed_vuln_api.endpoints if e.path == "/users" and e.method == "POST")
    assert create_user.request_body is not None
    field_names = {f.name for f in create_user.request_body.fields}
    assert field_names == {"username", "email", "age"}

    age_field = next(f for f in create_user.request_body.fields if f.name == "age")
    assert age_field.schema_.type == "integer"
    assert age_field.required is True


def test_endpoint_with_no_security_is_detectable(parsed_vuln_api):
    """
    /admin/stats declares no security requirement in the spec (VULN #4).
    The parser should faithfully represent that as an empty security
    requirement — this is exactly the kind of signal later phases
    (the rules engine) will key off of, so it must not be silently
    defaulted to "secure".
    """
    admin_stats = next(e for e in parsed_vuln_api.endpoints if e.path == "/admin/stats")
    assert admin_stats.security.scheme_names == []


def test_resolves_anyof_optional_header_param(parsed_vuln_api):
    """
    FastAPI/Pydantic v2 represents `Optional[str]` header params as
    `anyOf: [{type: string}, {type: null}]` rather than a flat `type`
    key. The parser must unwrap that instead of leaving type=None.
    """
    get_user = next(e for e in parsed_vuln_api.endpoints if e.path == "/users/{user_id}" and e.method == "GET")
    token_param = next(p for p in get_user.parameters if p.name == "x-api-token")
    assert token_param.location == ParamLocation.HEADER
    assert token_param.required is False
    assert token_param.schema_.type == "string"
    assert token_param.schema_.nullable is True


def test_missing_openapi_key_is_rejected():
    with pytest.raises(ParserError, match="Not a recognizable OpenAPI"):
        parse_openapi_spec({"info": {"title": "x", "version": "1"}, "paths": {}})


def test_missing_info_title_is_rejected():
    with pytest.raises(ParserError, match="info.title"):
        parse_openapi_spec({"openapi": "3.0.0", "info": {}, "paths": {}})


def test_missing_paths_is_rejected():
    with pytest.raises(ParserError, match="paths"):
        parse_openapi_spec({"openapi": "3.0.0", "info": {"title": "x", "version": "1"}})


def test_broken_ref_is_rejected():
    bad_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Broken", "version": "1"},
        "paths": {
            "/thing": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/DoesNotExist"}
                            }
                        }
                    }
                }
            }
        },
    }
    with pytest.raises(ParserError, match="Broken \\$ref"):
        parse_openapi_spec(bad_spec)


def test_nonexistent_file_is_rejected():
    with pytest.raises(ParserError, match="not found"):
        parse_openapi_spec("/tmp/this-file-does-not-exist-xyz.json")


def test_endpoint_with_no_parameters_or_body(parsed_vuln_api):
    health = next(e for e in parsed_vuln_api.endpoints if e.path == "/health")
    assert health.parameters == []
    assert health.request_body is None
