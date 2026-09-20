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

### Phase 4 — Deterministic Fuzzing & Mutation Engine ✅
- `app/fuzzer/mutations/models.py` — `MutationType` (20 kinds across
  string/number/boolean/null/enum/array/object/structural categories),
  `Mutation` (metadata: type, location, field_name, original/mutated
  value), `MutatedTestCase` (mutation + resulting `TestCase`, tied to
  `baseline_key`), `MutationConfig` (`max_mutations_per_field=8`,
  `max_mutations_per_endpoint=40`, `max_total_mutations=500`,
  `long_string_length=500`, `skip_methods` for excluding e.g. `DELETE`
  from a run entirely).
- `app/fuzzer/mutations/value_mutations.py` — per-type deterministic
  mutators (string/integer/number/boolean/array/object) plus universal
  enum and null handling. Fixed, documented ordering; truncated to
  `max_mutations_per_field` from the end (never random sampling), so
  generation is fully deterministic — verified by an explicit
  determinism test (run twice, compare).
- `app/fuzzer/mutations/engine.py` — `generate_mutations_for_test_case()`
  walks an `Endpoint`'s path params, query params, and body fields,
  producing one mutation per logical field change. Pure generation only
  — no I/O, no result interpretation. Key design decision: mutates
  *all* declared fields, not just the ones Phase 3's baseline happened
  to include (baseline only fills required fields) — synthesizing a
  valid starting value via `generate_valid_value()` for any optional
  field the baseline omitted. Without this, `PATCH /users/{user_id}`
  (whose `UserUpdate` fields are *all* optional) would get zero body
  mutations, which would be a real gap for exactly the kind of endpoint
  (partial update) worth fuzzing most.
- `app/fuzzer/mutation_runner.py` — `run_mutations_for_endpoint()` and
  `run_fuzzing_pass()`: execution orchestration, wiring the engine's
  output to the existing (unmodified) `execute_test_case()`. Enforces
  `max_total_mutations` and `skip_methods` across a whole spec;
  endpoints whose baseline never executed are skipped (nothing
  meaningful to mutate from). `MutationResult` makes no vulnerability
  judgment — pure evidence, exactly per the phase's core principle.
- `vulnerable-api/app/main.py` — added `PUT /users/{user_id}/tags`
  (fields: `tags: list[str]`, `metadata: dict`) purely so the mutation
  engine's array/object mutations have a real target to exercise
  end-to-end; our other body schemas were all flat strings/ints.
- **Found and fixed a real near-infinite-hang bug while building the
  integration tests** (not a test bug — a genuine architectural gap):
  a numeric mutation with no declared bounds can produce a large value
  (999,999,999); executed against `/slow`'s `await asyncio.sleep(delay)`,
  that's a ~31-year hang. Combined with `ASGITransport` not enforcing
  httpx's client timeout (established in Phase 2), this hung a test past
  any reasonable limit. Root cause, not just the symptom: any
  timeout-dependent correctness (this, and Phase 2's original
  timeout/connection-error tests) requires a *real* socket — ASGITransport
  is fast and deterministic for request-construction correctness, but
  provides no timeout protection at all. Fixed by using the real
  live-server fixture (with a short configured timeout) for any test that
  runs mutations across the full spec; `/slow`'s own baseline capture then
  legitimately times out and is excluded before any mutation is attempted
  against it, via the same "skip endpoints with a failed baseline" logic
  already in `run_fuzzing_pass`. No special-casing of `/slow` needed.
  Documented in `tests/test_mutation_runner.py`.
- 40 new tests (21 value-mutators + 12 engine + 7 execution/integration,
  including the required end-to-end OpenAPI → baseline → mutation →
  runner → results test), full suite now **113 passing**.
- `examples/demo_fuzz.py` — full deterministic fuzzing pass against a
  live vulnerable-api: 18 endpoints, 128 mutations executed across 9
  endpoints with usable baselines, JSON report saved. Confirms two
  things live: `POST /users`'s `age=-1` mutation returns 201 (accepted —
  ties back to VULN #2, weak input validation; Phase 4 makes no
  vulnerability claim, just records the evidence), and `/slow`'s
  large-delay mutation comes back as a clean timeout `ErrorInfo` rather
  than hanging the demo.

### Phase 5 — Response Analysis & Anomaly Detection ✅
- `app/analyzer/models.py` — `AnomalyType` (12 kinds, matching the
  phase spec's own vocabulary exactly: status_changed,
  unexpected_server_error, unexpected_client_error,
  authentication_behavior_changed, redirect_changed,
  response_body_changed, response_structure_changed,
  response_size_changed, timing_anomaly, error_signature_detected,
  request_timeout, network_error), `StatusCategory` (1xx-5xx +
  timeout/network_error/unknown), `Anomaly` (type + evidence dict —
  facts only, never raw response bodies, so analysis output can't
  become a secret-leak mechanism), `AnalysisConfig`
  (`min_time_difference_ms=200`, `min_time_multiplier=3.0`,
  `min_body_size_difference_bytes=10`), `AnalysisResult` (every
  `*_changed` boolean corresponds 1:1 to whether a matching `Anomaly`
  was appended — no field ever disagrees with the evidence list).
  **No severity, no confidence score, anywhere in this model** — by
  design, not omission.
- `app/analyzer/signatures.py` — 8-entry, case-insensitive, explicitly
  conservative error-signature list (Traceback, SQLException, "SQL
  syntax", "database error", etc). Documented tradeoff: substring
  matching means an innocuous message containing the phrase would also
  match — that's why it's evidence, never a verdict.
- `app/analyzer/analyzer.py` — `analyze()`: pure comparison, no I/O.
  Status analysis (category shifts, auth-status transitions in EITHER
  direction, redirects, network errors/timeouts as first-class
  observations rather than failures); timing analysis (anomaly requires
  BOTH the absolute-ms and ratio thresholds to clear — rejects "51ms vs
  48ms" and "1ms vs 5ms" alike, per the phase's own examples); body
  analysis (size/structure/generic-change, layered so the same
  underlying diff isn't reported three times); error-signature scan
  that only flags signatures NEW relative to the baseline (an endpoint
  that legitimately echoes "error" in its own normal output isn't
  evidence of anything). Explicit design note in the module docstring:
  a status-category shift is recorded as an observation regardless of
  whether it was actually the *correct* response for that mutation
  (e.g. a required field removed SHOULD 422) — deciding "expected vs
  suspicious" is later phases' job, which have the mutation type
  available to make that call.
- `app/analyzer/pipeline.py` — `analyze_fuzzing_results()`: wires
  `BaselineStore` + `run_fuzzing_pass()`'s output into
  `dict[str, list[AnalysisResult]]`. No new execution.
- `app/fuzzer/mutation_runner.py` — added `MutationResult.from_dict()`
  (symmetric with the existing `to_dict()`, matching `Baseline`'s own
  established pattern), needed for the demo's save-then-reload step.
- **Hit the exact same `/slow`-hang bug from Phase 4 again, in a new
  test file** — a useful confirmation that the fix belongs in "how you
  test," not something that could be patched once and forgotten:
  `capture_baselines` via `asgi_client` lets `/slow`'s baseline succeed
  (ASGITransport still executes the real 2s `asyncio.sleep`, it just
  doesn't enforce httpx's timeout around it), so a later mutation still
  generates `delay=999999999` and hangs. Fixed the same way — real
  live-server fixture with a short timeout for any full-spec test, so
  `/slow`'s baseline times out and is excluded before mutation.
- **Also caught a flawed test premise before it became a false "bug":**
  an early version of the determinism test ran the *entire* pipeline
  twice against the same live (stateful) server and expected identical
  results — but Phase 4's mutations genuinely change server-side state
  (PUT/PATCH modify real user records), so two full runs against one
  stateful target are NOT expected to match; that's the already-
  documented state-isolation limitation, not a determinism bug.
  Rewrote the test to state the real claim precisely: given the SAME
  already-captured data, `analyze_fuzzing_results` is deterministic —
  which is what the phase actually requires and is true.
- 56 new tests (7 signatures + 19 status/category/auth/redirect + 8
  timing + 12 body/structure/size + 7 integration-level `analyze()`
  tests including the phase doc's three worked examples verified
  exactly + 3 end-to-end pipeline tests), full suite now **169 passing**.
- `examples/demo_analysis.py` — captures baselines + runs a fuzzing
  pass live, saves both to JSON, **reloads them from disk**, then
  analyzes the reloaded data (proving the analyzer works from persisted
  data, not just same-process objects). Live run: 123 mutations across
  8 endpoints, 105 produced at least one observation — e.g.
  `GET /users/{user_id}` with `user_id=0` shows `status_changed` +
  `unexpected_client_error` (200→404) + `response_size_changed` +
  `response_structure_changed` (`{email,id,is_admin,username}` →
  `{detail}`), all evidence, zero severity anywhere in the output.

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
- **Array/object mutation is shallow, not recursive.** `FieldSchema` has
  no `items` sub-schema for arrays or `properties` for nested objects
  (a Phase 1 limitation, not new to Phase 4), so array mutations use
  generic placeholder elements rather than type-correct ones, and object
  mutations only operate at the whole-field level (null/empty/wrong
  type), never reaching into sub-properties. None of our own
  vulnerable-api's fields currently need more than this. Extending the
  parser to carry nested schemas is real, bounded future work if a
  target ever needs it.
- **Header mutation is out of scope for Phase 4** — the phase's own
  spec only calls out path/query/body mutation categories, not headers.
  Auth-header-specific fuzzing is a natural fit for a later
  authentication-testing phase rather than the generic mutation engine.
- **Timeout-dependent correctness requires a real socket, not
  ASGITransport.** This was already true from Phase 2 but Phase 4 hit it
  directly: a numeric mutation with no declared bounds can produce a
  large value, and if that value drives something like a sleep/delay
  parameter, only a real client's real timeout can cut it off gracefully.
  Tests that run mutations across the full spec now use the live-server
  fixture specifically because of this — see `tests/test_mutation_runner.py`
  for the full story. This is a general risk of fuzzing: an unbounded
  numeric mutation is safe for most fields but not guaranteed safe for
  all of them, since the fuzzer doesn't know what a given field
  controls. The runner's configurable timeout is the actual safety net
  in a real (non-test) run — always use a real client with a sane
  timeout when fuzzing a real target.
- **Single-baseline comparison only** — the analyzer compares against
  one captured baseline result, not multiple runs. An endpoint with a
  genuinely unstable baseline (flaky/non-deterministic target) could
  produce a `status_changed` observation that's really just baseline
  noise, not something the mutation caused. `BaselineStore` only stores
  one `Baseline` per endpoint (a Phase 3 design choice), so this
  analyzer works with what's available rather than requiring a redesign;
  representing multiple baseline runs (and analyzing against, say, their
  most common result) is real future work if a target turns out to need
  it, not attempted here per "extend only where necessary."
- **The `UNEXPECTED_CLIENT_ERROR` / `UNEXPECTED_SERVER_ERROR` labels are
  purely categorical, not judgments.** A status-category shift into 4xx
  or 5xx is labeled that way even when it's exactly the CORRECT response
  (e.g. a required field removed should 422) — deliberately, since
  distinguishing "expected" from "suspicious" requires knowing the
  mutation type's intent, which belongs to the security-rules phase, not
  this one. Documented explicitly in `app/analyzer/analyzer.py`'s module
  docstring so it isn't mistaken for an oversight later.
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
### Phase 6 — Deterministic Security Rules (most likely next)
Per the architecture diagram in the Phase 5 doc itself (Response Analysis
→ Deterministic Rules → Security Findings), the next logical step is a
rules engine that interprets `AnalysisResult`/`Anomaly` evidence into
actual findings with severity — the first point anywhere in this project
where a severity label is assigned. Deterministic rules only (e.g. "a
mutation-caused 5xx with a matched error signature is at least Medium");
LLM-assisted test generation (proposing adversarial cases the
deterministic mutation engine wouldn't think of, still gated by the same
validation layer, still no role in judging results) remains a separate,
not-yet-scheduled branch per the diagram. Actual next-phase scope is
whatever the next phase doc specifies.
