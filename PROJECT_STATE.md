# Project State

Tracks what's actually built and working, updated after each phase.
This is the source of truth for "where are we" — not the master prompt.

## Done

### Phase 1 — API Spec Parser ✅
- `app/parser/models.py` — normalized Pydantic models (`APISpec`, `Endpoint`,
  `Parameter`, `RequestBody`, `SecurityScheme`, etc.)
- `app/parser/openapi_parser.py` — parses OpenAPI 3.x JSON/YAML (file path or
  dict) into `APISpec`. Resolves local `$ref` chains, unwraps `anyOf`/`oneOf`
  optional-field schemas (Pydantic v2 style), extracts path/query/header
  params, request body fields, and per-operation security requirements.
- 12 passing tests in `tests/test_parser.py`.
- `examples/demo_parse.py` — runnable demo.

### Phase 2 — Generic API Runner ✅
- `app/runner/models.py` — `TestCase` (input: method/path/path_params/
  query_params/headers/body) and `TestResult` (normalized output:
  status_code/headers/body/body_is_json/response_time_ms/body_size/error/
  request echo). Deliberately generic — not tied to OpenAPI, not tied to
  any specific target or provider.
- `app/runner/validation.py` — validates a `TestCase` before it's ever
  executed (method allow-list, path shape, required path_params present,
  header value types). `ValidationError` is raised for anything invalid.
  This is the checkpoint LLM-generated test cases will have to pass
  through starting in Phase 5.
- `app/runner/request_builder.py` — pure function, no I/O: `TestCase` +
  `RunnerSettings` → `PreparedRequest` (resolved URL with path params
  URL-encoded and substituted, merged headers). Test-case headers always
  win over the configured default auth header — a fuzzer testing "what
  happens without auth" must not have that silently overridden.
- `app/runner/http_runner.py` — `execute_test_case()`, the only piece
  that does real I/O. Accepts an optional injected `httpx.AsyncClient`
  (real network client if omitted) — this is what makes almost the
  entire test suite able to run against an in-process ASGI target with
  no real socket. Normalizes timeouts, connection errors, invalid URLs,
  and any other client-side exception into `ErrorInfo` rather than
  raising — one failed request never crashes a future scan. Masks
  sensitive headers (Authorization, X-API-Key, X-API-Token, Cookie,
  Set-Cookie) in the stored request echo.
- `app/core/config.py` — `RunnerSettings` (base_url, timeout, optional
  default auth header), loaded from env vars via `load_settings()`, but
  always passed explicitly into functions rather than read from a
  global — makes everything trivially testable with hand-built settings.
- `app/api/dependencies.py` + `app/api/routes.py` + `app/main.py` — the
  fuzzer's own FastAPI backend. `POST /execute` takes a `TestCase`,
  returns a `TestResult`; `ValidationError` → HTTP 400 (never sent
  anywhere) vs. the target's own status code, which is just data in a
  normal 200 response from `/execute`.
- `vulnerable-api/` extended: added `PUT`/`PATCH`/`DELETE` on
  `/users/{user_id}` (same IDOR class as the existing GET), a `/slow`
  endpoint (real `asyncio.sleep`, for timeout testing), a `/text`
  endpoint (non-JSON body), and an `/echo` endpoint (pure test
  scaffolding — echoes method/query/headers/body back, used to prove
  every request component the runner builds actually arrives intact).
- **Testing strategy** (this mattered enough to document): most
  functional tests use `httpx.ASGITransport` pointed directly at the
  in-process vulnerable-api app — no real socket, no background
  process, fast and deterministic. Verified empirically that this does
  NOT enforce httpx's client-level timeout (no real I/O for it to
  interrupt) — so timeout and connection-error tests specifically use
  a real vulnerable-api instance bound to a real local port, started in
  a background thread by a session-scoped pytest fixture
  (`tests/conftest.py`), plus a genuinely-unused port for connection
  refusal. All of this is local-only; nothing external.
- 46 tests total, all passing: 12 parser + 25 runner (validation,
  all 5 HTTP methods, path param resolution incl. URL-encoding,
  query params, custom + auth headers incl. override precedence and
  masking, JSON bodies on POST/PUT/PATCH, DELETE, non-JSON responses,
  timing/size capture) + 3 network-error (timeout, connection refused,
  live-server sanity) + 6 FastAPI `/execute` endpoint tests.
- `examples/demo_run.py` — runnable demo against a live vulnerable-api;
  shows the IDOR (VULN #1) and missing-auth (VULN #4) findings already
  visible in raw runner evidence, with zero "intelligence" applied yet.

### Phase 3 — Baseline Testing ✅
- `app/fuzzer/valid_values.py` — deterministic "happy path" value
  generation from a `FieldSchema` (example > default > enum > type-based,
  respecting min/max/length constraints).
- `app/fuzzer/test_case_builder.py` — `build_baseline_test_case(endpoint,
  settings)`: parsed `Endpoint` → valid `TestCase`. Documented auth
  heuristic: recognizes a header *parameter* matching the configured auth
  header name as needing auth, even when the spec marks it optional
  (true of our own vulnerable-api, since a plain FastAPI `Header()` param
  never registers as a formal OpenAPI security scheme) — otherwise every
  baseline would 401 by default.
- `app/fuzzer/baseline.py` — `Baseline` (test case + result), `BaselineStore`
  (in-memory, keyed by method+path, with `to_json`/`from_json`/
  `save_to_file`/`load_from_file` — no database), `capture_baselines()`
  orchestrating capture across an entire `APISpec` sequentially.
- 27 new tests (15 value-generator + 6 test-case-builder + 6 baseline
  capture/persistence), full suite now 73 passing.
- Found and fixed a real cross-test state-pollution bug while building
  this phase's integration test: `asgi_client` was sharing one
  session-scoped vulnerable-api instance across the whole test suite, so
  a DELETE in one test file silently broke an unrelated test elsewhere.
  Fixed by giving state-mutating tests a fresh app instance per test in
  `tests/conftest.py` (see Known gaps below for the general lesson).
- `examples/demo_baseline.py` — captures baselines for all 17 endpoints
  against a live vulnerable-api, prints a summary, and persists to
  `reports/baselines-demo.json`. Also surfaced a genuine limitation live:
  `GET /orders/{order_id}` baselines to 404 because deterministic value
  generation has no way to know real seeded order IDs are 101/102, not 1
  (documented in Known gaps, not silently ignored).

## Known gaps (not blocking, tracked for later phases)
- Parser only follows local `$ref`s (no external file refs) — fine for V1 scope.
- `FieldSchema` covers a practical JSON Schema subset (no `allOf`, no nested
  array item schemas yet) — will extend if a later phase's mutator needs more.
- Runner supports one configured auth header, not full OpenAPI security
  scheme awareness (bearer vs apiKey vs oauth2 flows) — deliberately kept
  simple per the "don't pretend every auth vulnerability can be inferred
  from the spec" principle; will revisit if Phase 4+ needs more.
- No retries (intentional — state-changing requests + reproducibility).
- No concurrency yet (intentional — correctness first, per spec).
- **Baseline value generation has no semantic knowledge of the target's
  actual data.** It's purely schema-driven (type/format/bounds), so an
  integer ID defaults to `1` regardless of what IDs actually exist —
  demonstrated live in the demo: `GET /orders/{order_id}` baselines to a
  404 because real seeded orders are `101`/`102`, not `1`. This is an
  honest limitation of deterministic generation, not a bug — it's
  exactly the kind of gap Phase 5's LLM-assisted generation and/or
  discovering real IDs from other endpoints' responses could close later.
- **Baseline capture has no state-isolation or ordering strategy.** It
  runs sequentially in whatever order the spec listed endpoints, so a
  state-changing baseline (e.g. `DELETE /users/{user_id}`) can affect a
  later baseline that happens to reference the same default-generated
  ID. For our own vulnerable-api this doesn't currently break anything
  cross-endpoint (verified: full capture runs clean), but it's a real
  constraint to design around once mutation testing (Phase 4) runs many
  more requests per endpoint. Documented in `app/fuzzer/baseline.py`.
  (This exact issue also showed up as *test*-suite pollution during
  Phase 3 — fixed by giving state-mutating tests a fresh vulnerable-api
  instance per test in `tests/conftest.py`, rather than one shared
  instance. Worth remembering as a general lesson: anything that shares
  mutable state across supposedly-independent test cases will eventually
  produce a flaky, order-dependent failure.)

## Next
### Phase 4 — Deterministic Fuzzing (Mutation Engine)
Take a baseline `TestCase` and systematically produce mutated variants —
nulls, empty values, wrong types, boundary numbers, long strings, missing
required fields, unexpected extra fields — run each through the runner,
and keep the result alongside its baseline for comparison. Still no LLM
here; this proves the fuzzing engine works on its own first, per the
project's own phase ordering.
