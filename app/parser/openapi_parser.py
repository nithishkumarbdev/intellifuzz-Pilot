"""
OpenAPI/Swagger -> normalized APISpec.

Supports OpenAPI 3.x, JSON or YAML, loaded from a file path or an
already-parsed dict. Resolves local `$ref` pointers (the only kind
OpenAPI actually uses — refs to other files are out of scope for V1,
per the "practical subset" rule).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

import yaml

from app.parser.models import (
    APISpec,
    Endpoint,
    FieldSchema,
    Parameter,
    ParamLocation,
    RequestBody,
    RequestBodyField,
    SecurityRequirement,
    SecurityScheme,
)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


class ParserError(Exception):
    """Raised when a spec is missing required structure or is malformed."""


def load_spec_file(path: Union[str, Path]) -> dict[str, Any]:
    """Load a JSON or YAML OpenAPI file into a raw dict."""
    path = Path(path)
    if not path.exists():
        raise ParserError(f"Spec file not found: {path}")

    text = path.read_text()
    try:
        if path.suffix.lower() in (".yaml", ".yml"):
            data = yaml.safe_load(text)
        else:
            # Default to JSON, but fall back to YAML since YAML is a
            # superset of JSON and some specs use .json content with
            # a non-.json extension.
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ParserError(f"Could not parse {path} as JSON or YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ParserError(f"Spec file {path} did not parse to a JSON/YAML object")
    return data


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    """
    Resolve a local `$ref` like '#/components/schemas/UserCreate' by
    walking the root document. Only local refs are supported (V1 scope).
    """
    if not ref.startswith("#/"):
        raise ParserError(f"Unsupported $ref (only local refs are supported): {ref}")

    node: Any = root
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, dict) or part not in node:
            raise ParserError(f"Broken $ref, could not resolve segment '{part}' in: {ref}")
        node = node[part]
    return node


def _deref(node: dict[str, Any], root: dict[str, Any], _depth: int = 0) -> dict[str, Any]:
    """Follow a `$ref` chain until we hit a real schema object."""
    if _depth > 20:
        raise ParserError("Exceeded max $ref resolution depth (possible circular $ref)")
    if isinstance(node, dict) and "$ref" in node:
        return _deref(_resolve_ref(node["$ref"], root), root, _depth + 1)
    return node


def _parse_field_schema(schema_node: dict[str, Any], root: dict[str, Any]) -> FieldSchema:
    schema_node = _deref(schema_node or {}, root)

    # Pydantic v2 / newer OpenAPI generators represent `Optional[X]` as
    # `anyOf: [{type: X}, {type: null}]` rather than a flat `type` key
    # with `nullable: true`. Unwrap that so downstream code (mutator,
    # fuzzer, rules) only ever has to deal with one flat shape.
    nullable = bool(schema_node.get("nullable", False))
    variants = schema_node.get("anyOf") or schema_node.get("oneOf")
    if variants:
        non_null_variant = None
        for variant in variants:
            variant = _deref(variant, root)
            if variant.get("type") == "null":
                nullable = True
            elif non_null_variant is None:
                non_null_variant = variant
        if non_null_variant is not None:
            schema_node = {**non_null_variant, **{k: v for k, v in schema_node.items() if k not in ("anyOf", "oneOf")}}

    return FieldSchema(
        type=schema_node.get("type"),
        format=schema_node.get("format"),
        enum=schema_node.get("enum"),
        minimum=schema_node.get("minimum"),
        maximum=schema_node.get("maximum"),
        min_length=schema_node.get("minLength"),
        max_length=schema_node.get("maxLength"),
        default=schema_node.get("default"),
        example=schema_node.get("example"),
        nullable=nullable,
    )


def _parse_parameters(raw_params: list[dict[str, Any]], root: dict[str, Any]) -> list[Parameter]:
    parameters = []
    for raw in raw_params:
        raw = _deref(raw, root)
        try:
            location = ParamLocation(raw["in"])
        except (KeyError, ValueError):
            # Unknown/unsupported parameter location — skip rather than
            # fail the whole spec (a single odd parameter shouldn't
            # block parsing the rest of the API).
            continue
        parameters.append(
            Parameter(
                name=raw["name"],
                location=location,
                required=bool(raw.get("required", False)),
                schema=_parse_field_schema(raw.get("schema", {}), root),
                description=raw.get("description"),
            )
        )
    return parameters


def _parse_request_body(raw_body: dict[str, Any] | None, root: dict[str, Any]) -> RequestBody | None:
    if not raw_body:
        return None
    raw_body = _deref(raw_body, root)
    content = raw_body.get("content", {})

    # Prefer application/json; fall back to whatever's first if absent.
    content_type = "application/json" if "application/json" in content else next(iter(content), None)
    if content_type is None:
        return None

    body_schema = _deref(content[content_type].get("schema", {}), root)
    fields = []
    if body_schema.get("type") == "object" or "properties" in body_schema:
        required_names = set(body_schema.get("required", []))
        for field_name, field_schema in body_schema.get("properties", {}).items():
            fields.append(
                RequestBodyField(
                    name=field_name,
                    required=field_name in required_names,
                    schema=_parse_field_schema(field_schema, root),
                )
            )

    return RequestBody(
        required=bool(raw_body.get("required", False)),
        content_type=content_type,
        fields=fields,
    )


def _parse_security_schemes(raw: dict[str, Any]) -> dict[str, SecurityScheme]:
    schemes = {}
    for name, raw_scheme in raw.get("components", {}).get("securitySchemes", {}).items():
        schemes[name] = SecurityScheme(
            name=name,
            type=raw_scheme.get("type", "unknown"),
            scheme=raw_scheme.get("scheme"),
            location=raw_scheme.get("in"),
            key_name=raw_scheme.get("name"),
        )
    return schemes


def _parse_security(raw_security: list[dict[str, list[str]]] | None) -> SecurityRequirement:
    if not raw_security:
        return SecurityRequirement(scheme_names=[])
    scheme_names = []
    for requirement in raw_security:
        scheme_names.extend(requirement.keys())
    return SecurityRequirement(scheme_names=scheme_names)


def parse_openapi_spec(source: Union[str, Path, dict[str, Any]]) -> APISpec:
    """
    Parse an OpenAPI spec (file path or already-loaded dict) into a
    normalized APISpec.

    Raises ParserError for structurally invalid specs (missing required
    top-level keys, unparseable content, broken $refs).
    """
    root: dict[str, Any]
    if isinstance(source, dict):
        root = source
    else:
        root = load_spec_file(source)

    if "openapi" not in root and "swagger" not in root:
        raise ParserError("Not a recognizable OpenAPI/Swagger document (missing 'openapi' or 'swagger' key)")

    info = root.get("info")
    if not isinstance(info, dict) or "title" not in info:
        raise ParserError("Spec is missing required 'info.title'")

    paths = root.get("paths")
    if not isinstance(paths, dict):
        raise ParserError("Spec is missing required 'paths' object")

    base_url = None
    servers = root.get("servers")
    if isinstance(servers, list) and servers:
        base_url = servers[0].get("url")

    endpoints: list[Endpoint] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            try:
                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method.upper(),
                        operation_id=operation.get("operationId"),
                        summary=operation.get("summary"),
                        parameters=_parse_parameters(operation.get("parameters", []), root),
                        request_body=_parse_request_body(operation.get("requestBody"), root),
                        security=_parse_security(operation.get("security")),
                    )
                )
            except ParserError:
                raise
            except Exception as exc:  # noqa: BLE001 - deliberately broad: one bad
                # operation shouldn't take down parsing of the whole spec, but
                # we still want to know what went wrong.
                raise ParserError(f"Failed to parse operation {method.upper()} {path}: {exc}") from exc

    return APISpec(
        title=info["title"],
        version=info.get("version", "unknown"),
        base_url=base_url,
        endpoints=endpoints,
        security_schemes=_parse_security_schemes(root),
    )
