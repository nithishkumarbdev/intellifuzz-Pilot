"""
Normalized representation of an API, independent of OpenAPI syntax.

Every other component (fuzzer, mutator, LLM generator, rules engine)
should only ever import from here — never touch raw OpenAPI dicts again
once parsing is done. That's the whole point of this module: OpenAPI
is messy (refs, nested schemas, multiple valid ways to express the same
thing); this normalized shape is not.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ParamLocation(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"


class FieldSchema(BaseModel):
    """
    A minimal, practical subset of JSON Schema — just enough to generate
    and mutate values sensibly. We deliberately do NOT try to model every
    JSON Schema keyword (V1 practical subset, per project scope).
    """

    type: Optional[str] = None  # "string" | "integer" | "number" | "boolean" | "array" | "object"
    format: Optional[str] = None  # e.g. "email", "int64", "date-time"
    enum: Optional[list[Any]] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    default: Optional[Any] = None
    example: Optional[Any] = None
    nullable: bool = False


class Parameter(BaseModel):
    """A single path/query/header/cookie parameter on an operation."""

    name: str
    location: ParamLocation
    required: bool = False
    schema_: FieldSchema = Field(default_factory=FieldSchema, alias="schema")
    description: Optional[str] = None

    model_config = {"populate_by_name": True}


class RequestBodyField(BaseModel):
    """One field inside a JSON request body."""

    name: str
    required: bool = False
    schema_: FieldSchema = Field(default_factory=FieldSchema, alias="schema")

    model_config = {"populate_by_name": True}


class RequestBody(BaseModel):
    required: bool = False
    content_type: str = "application/json"
    fields: list[RequestBodyField] = Field(default_factory=list)


class SecurityRequirement(BaseModel):
    """
    Which auth scheme(s) this operation expects, by name (matches a key
    in APISpec.security_schemes). Empty list = no auth declared for this
    operation, which is itself useful signal (e.g. VULN #4 in our test
    API — /admin/stats declares no security at all).
    """

    scheme_names: list[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    path: str
    method: str  # "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | ...
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    parameters: list[Parameter] = Field(default_factory=list)
    request_body: Optional[RequestBody] = None
    security: SecurityRequirement = Field(default_factory=SecurityRequirement)

    @property
    def path_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParamLocation.PATH]

    @property
    def query_parameters(self) -> list[Parameter]:
        return [p for p in self.parameters if p.location == ParamLocation.QUERY]


class SecurityScheme(BaseModel):
    name: str
    type: str  # "http" | "apiKey" | "oauth2" | ...
    scheme: Optional[str] = None  # e.g. "bearer" for http-bearer
    location: Optional[str] = None  # for apiKey: "header" | "query" | "cookie"
    key_name: Optional[str] = None  # for apiKey: the header/query/cookie name


class APISpec(BaseModel):
    title: str
    version: str
    base_url: Optional[str] = None
    endpoints: list[Endpoint] = Field(default_factory=list)
    security_schemes: dict[str, SecurityScheme] = Field(default_factory=dict)

    def endpoint_count(self) -> int:
        return len(self.endpoints)
