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

### Phase 6 — LLM-Assisted Intelligent Test Generation ✅
**Numbering note:** the phase doc for this one called itself "Phase 5"
and assumed Response Analysis hadn't been built yet (it listed that as
a future "Phase 6" in its own architecture diagram) — it was evidently
drafted independently of the actual Phase 5 that shipped. Content-wise
it only depends on Phases 1–4, so nothing was blocked; this is filed
as Phase 6 here to match what's actually in the repo.

- **Two small, backward-compatible extensions to Phase 4's own types**
  (verified: all 169 prior tests still passed unchanged after these) —
  this is the concrete meaning of "converge into one representation":
  `MutationType.LLM_SUGGESTED` added to the enum, and `source`
  (default `"deterministic"`), `reason`, `confidence` added to both
  `MutatedTestCase` and `MutationResult`. An LLM-origin mutation is the
  *same type* flowing through the *same* execution path
  (`app/fuzzer/mutation_runner.py`'s new shared
  `execute_mutated_test_cases()` helper, extracted from the previously
  inline loop in `run_mutations_for_endpoint`) — never a parallel
  architecture.
- `app/generator/models.py` — raw, untrusted LLM response shape
  (`LLMGenerationResponse`, `LLMTestCandidateRaw`, `LLMEndpointEcho`),
  `GeneratorConfig`, and bookkeeping types for what a generation pass
  did (`CombinedGenerationResult`, `CombinedScanSummary`).
- `app/generator/provider.py` — `LLMProvider` ABC + `ProviderError`
  hierarchy (`ProviderTimeout`/`ProviderUnavailable`/`ProviderAuthError`);
  `FakeLLMProvider` and `FailingLLMProvider` (test doubles, no network);
  `OpenAICompatibleProvider` (real provider, built on `httpx` — already
  a dependency, so no new SDK — against the OpenAI-compatible
  chat-completions shape, which works unmodified against OpenAI itself,
  OpenRouter, and most local model gateways).
- `app/generator/prompt.py` — the prompt template, kept separate from
  logic. The security-boundary system prompt is injected by the
  provider as an actual system-role message, never concatenated into
  the same string as untrusted context — concrete prompt-injection
  resistance, not just a comment saying so. Also holds
  `heuristic_offline_response()`: a fully offline, deterministic
  "model" that reads back the same JSON context block the prompt
  embeds and proposes plausible, endpoint-aware candidates — this is
  what makes `LLM_PROVIDER=fake` genuinely useful for demos/CI rather
  than just returning nothing.
- `app/generator/context.py` — builds the per-endpoint LLM context.
  Deliberately excludes `.headers` entirely (so a real auth token value
  can never reach a prompt) and excludes every other endpoint (token
  cost control + keeps "only propose tests for the endpoint you were
  asked about" enforceable).
- `app/generator/candidates.py` — parsing (never raises; malformed
  JSON or schema mismatch becomes `(None, error_string)`) and
  validation (the actual security boundary). The model's *echoed*
  endpoint must match the endpoint actually queried, or the entire
  batch is rejected outright — the concrete defense against a
  prompt-injection attempt hidden in OpenAPI description text trying to
  redirect candidates elsewhere; the model's self-report is checked,
  never trusted. `target_location` must resolve to a real field on
  *this* endpoint (`unknown_field`); only `path`/`query`/`body` kinds
  are accepted, never `header` (`unsupported_location_kind`). Value
  TYPE mismatches are explicitly NOT rejected — a string proposed for
  an integer field is often exactly the interesting test.
- `app/generator/config.py` — `LLMSettings` (env-driven:
  `LLM_PROVIDER`/`LLM_MODEL`/`LLM_API_KEY`/`LLM_BASE_URL`/
  `LLM_TIMEOUT_SECONDS`), `build_provider()`. The core "LLM is
  optional" contract lives here concretely: a real provider requested
  without an API key returns `None`, never raises — verified by a test.
- `app/generator/pipeline.py` — `deduplicate_against()` (stable key:
  endpoint + location + JSON-normalized value; removes LLM duplicates
  of deterministic mutations AND duplicates among LLM candidates
  themselves, order-preserving); `generate_combined_mutations()` (one
  endpoint: deterministic + validated/deduped LLM, any LLM failure at
  any stage degrades to deterministic-only and records why, never
  raises); `run_combined_fuzzing_pass()` (whole-spec orchestration,
  adds `generator_config.max_total_llm_calls` as a budget on top of
  Phase 4's existing `max_total_mutations`/`skip_methods` — once the
  LLM budget is spent, remaining endpoints still get full deterministic
  treatment).
- 71 new tests: provider contract (12, including a real HTTP-mocked
  `OpenAICompatibleProvider` — no real network, no real key), prompt +
  heuristic offline response (9), context/secret-exclusion (7),
  candidate parsing + every validation/security-boundary path (19),
  dedup + combined generation (13), settings/optional-LLM contract (7),
  full live end-to-end (4, including "budget exhausted mid-run still
  fuzzes deterministically" and "failing provider never stops the
  overall scan"). Full suite now **240 passing**.
- `examples/demo_llm_fuzz.py` — offline by default
  (`LLM_PROVIDER=fake`), same env vars swap in a real provider. Live
  run: 128 deterministic + 14 LLM-accepted (0 rejected — the offline
  heuristic only proposes real field names) = 142 executed. Notably,
  one LLM candidate (`GET /slow`'s `query.delay -> 999`) came back as a
  clean `ERROR(timeout)` rather than hanging — the runner's timeout
  protection (established in Phase 4) working correctly for an
  LLM-suggested value it had never seen before, not just
  deterministic ones.
- `README.md` created (didn't exist before this phase, despite being
  asked for back in the very first phase doc) — project overview,
  architecture, how to run, current status.

### Phase 7 — Deterministic Security Rules & Finding Classification ✅
The first phase anywhere in this project that assigns an actual
severity. Project renamed "IntelliFuzz" in this phase's own doc — no
functional change, just adopted the name going forward.

- `app/rules/models.py` — `Severity` (INFO/LOW/MEDIUM/HIGH — no numeric
  score), `Confidence` (LOW/MEDIUM/HIGH, kept strictly separate from
  severity — a HIGH-severity/LOW-confidence finding is a normal, valid
  combination, not a contradiction), `FindingCategory`, `Evidence`
  (structural facts only — status codes, sizes, matched pattern names —
  never a raw response body or a secret's actual value), `Reproduction`
  (built directly from the runner's own already-masked `RequestEcho`,
  no re-masking logic duplicated), `Finding` (the full traceability
  chain: endpoint → baseline → mutation → mutated request → response →
  rule, exactly as required).
- `app/rules/rule.py` — `SecurityRule` ABC (`evaluate(context) ->
  Optional[Finding]`) and `RuleContext`, which deliberately carries
  BOTH the Phase 5 `AnalysisResult` and the raw `TestResult`s together
  (see `app/rules/pipeline.py`'s docstring for why: reproduction info
  lives on `TestResult.request`, which `AnalysisResult` doesn't carry).
- `app/rules/rules.py` — five rules, each keyed to evidence the project
  actually produces, not a hypothetical vulnerability taxonomy:
  - **INPUT-001** (baseline succeeds, mutation 5xx) — severity/confidence
    bumped from LOW to MEDIUM when an error signature is also matched.
  - **AUTH-001** (baseline 401/403, mutation succeeds) — reachable
    with the *current* mutation engine's scope (a body/query/path field
    that incorrectly influences server-side auth would trigger it) even
    though headers aren't mutated; keyed on the status PATTERN, so it
    would also catch a future header-mutated "token removed, still
    succeeds" case with no new rule needed. Documented as unlikely to
    fire against our own vulnerable-api specifically, since its auth
    check happens before any mutated field is read — exercised via
    hand-built contexts in tests instead.
  - **AUTHZ-001** (path-identifier mutated, both baseline and mutation
    succeed) — `Severity.HIGH` / `Confidence.LOW` by design: exactly
    the "high potential impact, can't independently verify" example
    from the phase's own spec. Demonstrated live against vulnerable-
    api's real VULN #1 IDOR in `tests/test_rules_pipeline.py`.
  - **DATA-001** (new, sensitive-named field appears in the response) —
    a small (11-entry), conservative, name-only marker list; explicitly
    never inspects or logs field *values*.
  - **BEHAVIOR-001** (null/missing-field/type-confused value accepted
    with success) — fired for real in the live demo: Pydantic's own
    lenient coercion accepts a stringified number (`"1"` → `1`) where
    stricter typing might be expected.
  Every title starts with "Potential"; tested explicitly that none of
  the banned confirmed-vulnerability phrasing ("confirmed", "bypass
  confirmed") ever appears.
- `app/rules/engine.py` — `RuleEngine` (plain list of rules, not a
  plugin framework), `deduplicate_findings()` (keyed on endpoint +
  rule_id + mutation location, deliberately NOT the specific mutated
  value — `quantity=-1`, `quantity=-999`, `quantity=999999999` all
  correctly collapse into one finding, exactly per the phase's own
  example).
- `app/rules/pipeline.py` — `evaluate_fuzzing_results()`. Calls Phase
  5's `analyze()` directly (not the pre-computed
  `analyze_fuzzing_results` output) so each `RuleContext` gets the
  `AnalysisResult` and the original `MutationResult` (source/reason/
  `TestResult.request`) together without an error-prone zip-by-position
  between two separately-produced lists — additive, `app/analyzer/`
  itself untouched.
- **Found two more instances of the same class of bug this project
  keeps surfacing — shared mutable state across what look like
  independent operations:**
  1. A live-demo/test assumption that `AUTHZ-001` would fire against a
     *full-spec* run on `GET /users/{user_id}` was wrong: baseline
     capture's own `DELETE /users/{user_id}` baseline call (which runs
     regardless of the *fuzzing* pass's `skip_methods`) really deletes
     user 1 before the fuzzing pass even starts, so every mutation
     against that endpoint 404s regardless of the mutated id. Not a
     rule bug — verified live, then fixed the test/demo's expectations
     rather than the (already-documented, deliberately unsolved since
     Phase 3) baseline-capture limitation.
  2. Building a *targeted* single-endpoint test to demonstrate AUTHZ-001
     properly hit a related, genuinely new issue: it used the shared
     session-scoped `live_vulnerable_api_url` fixture, and an *earlier*
     test in the same file had already run a full-spec capture against
     that same shared server — deleting user 1 before this test even
     started. Fixed by adding `isolated_live_vulnerable_api_url` (a
     dedicated, function-scoped live server) to `tests/conftest.py` for
     tests that need guaranteed-fresh seed data, alongside the existing
     shared session-scoped one for tests that don't care.
- 41 new tests (22 rules incl. false-positive-resistance for every
  rule + 10 engine/dedup + 5 finding-ID determinism/serialization + 4
  live end-to-end, including the concrete AUTHZ-001 IDOR demonstration).
  Full suite now **281 passing**.
- `examples/demo_findings.py` — runs the FULL pipeline (deterministic +
  LLM via Phase 6, matching the phase's own final-architecture diagram)
  through to findings. Live, uncurated result: 3 real `BEHAVIOR-001`
  findings (stringified-number coercion on `/slow`, `POST /users`,
  `POST /orders`); zero `INPUT-001`/`AUTH-001`/`DATA-001`/`AUTHZ-001`
  this run — each absence explained above, not silently glossed over.
- `README.md` updated: new "Anomaly vs. signal vs. finding" section
  making the Phase 5 → Phase 7 distinction explicit, per the phase's
  own requirement.

### Phase 8 — Reporting ✅
- `app/reports/models.py` — `Report` (metadata + sorted findings —
  ONE object every renderer reads from, per the phase's own "single
  source of truth" requirement), `ReportMetadata` (project name,
  report ID, generated-at timestamp, target/spec if known, severity +
  rule counts, a fixed `disclaimer` string embedded in every format
  including JSON, so a downstream consumer like n8n gets the same
  honesty guarantee a human reading the Markdown/HTML gets).
- `app/reports/formatting.py` — `sort_findings()` (severity → endpoint
  → rule_id → finding_id, returns a NEW list, never mutates the input)
  and `safe_excerpt()` (truncates large values rather than dumping them
  whole — shared by both Markdown and HTML so the truncation behavior
  can't drift between formats).
- `app/reports/build.py` — `build_report()`: the only place metadata
  gets computed. `generated_at` is injectable (defaults to now, UTC) —
  same "explicit config, never a hidden global" pattern as
  `RunnerSettings`/`MutationConfig` since Phase 2 — so tests can assert
  exact output. Documented precisely what "deterministic" means here:
  finding ORDERING and every other field are deterministic given the
  same inputs; `generated_at`/`report_id` are inherently point-in-time
  and not expected to match across separate runs.
- `app/reports/json_reporter.py` — deliberately thin:
  `Report.model_dump(mode="json")` + `json.dumps`. No separate
  JSON-specific data model to keep in sync with the other two formats.
- `app/reports/markdown_reporter.py` — summary table, per-rule counts
  table, one section per finding (severity/confidence/rule/endpoint/
  source, evidence, reproduction), the disclaimer always present
  (including on an empty report).
- `app/reports/html_reporter.py` — standalone single file, no JS
  framework, no build step, severity-color-coded finding cards.
  **Added HTML-escaping (`html.escape`) on every rendered value** —
  not explicitly asked for in the phase spec, but a real, obvious gap
  once you notice where finding data ultimately comes from: mutation
  values, matched field names, and reproduction bodies are all derived
  from the fuzzed target's own responses (or an LLM's proposed values)
  — untrusted input from this report generator's point of view.
  Rendering any of that unescaped would make the report itself an XSS
  vector when opened in a browser. Masking (Phase 2's `RequestEcho`)
  handles secrets; this handles the separate, previously-unaddressed
  concern of the report becoming an injection vector. Verified with
  explicit regression tests (`<script>` in a title/evidence-detail/
  reproduction-body/endpoint never survives unescaped).
- `app/reports/service.py` — `ReportService.generate()`: findings → one
  or more files on disk in one call, unknown format names rejected
  with a clear error, output directory created if missing.
- `app/cli.py` — **the project's first standalone CLI**
  (`python -m app.cli`). No prior CLI existed to extend (every earlier
  phase was demo-script-driven), so this consolidates the same
  building blocks each `examples/demo_*.py` already used
  (parse → baseline → deterministic+LLM mutations → execute → analyze
  → rules → report) into one configurable command: `--spec`, `--target`,
  `--auth-header`/`--auth-value`, `--timeout`, `--max-mutations`,
  `--skip-methods`, `--report-dir`, `--formats`, `--no-llm`.
- 59 new tests (10 build/sorting + 10 JSON + 12 Markdown + 13 HTML
  incl. 4 dedicated XSS-escaping regressions + 8 service + 6 CLI incl.
  one live end-to-end run). Full suite now **340 passing**.
- `examples/demo_reporting.py` — full pipeline through to all three
  report formats, offline by default. Live, uncurated result: same 3
  real `BEHAVIOR-001` findings as Phase 7's own demo, rendered
  correctly and consistently across JSON/Markdown/HTML (verified: same
  `finding_id`s appear in all three, masked header preserved in all
  three, large bodies truncated in Markdown/HTML but not JSON since
  JSON is the machine-readable format and truncating it would corrupt
  data a downstream consumer might need in full).
- `AI_NOTES.md` created — outstanding since the very first phase doc.
  Factual, cross-references real file paths and real tests, no
  marketing language.
- `README.md`: architecture diagram extended through Reporting, status
  table updated, "Anomaly vs. signal vs. finding" renamed to include
  "vs. report" with a new paragraph, dedicated "Reporting" section, CLI
  usage added to "Running it", repository layout updated (including an
  explicit note that `app/reports/` — the code — and top-level
  `reports/` — the generated output directory — are two different
  things sharing a name, since that could otherwise confuse a reader).

## Known gaps (not blocking, tracked for later phases)
- **AUTH-001 has never fired against vulnerable-api specifically**, and
  isn't expected to, since its auth check happens before any mutated
  field is read — the rule is correct and tested (hand-built contexts),
  just not exercised by this particular target's own bugs. A target
  whose authorization logic incorrectly depends on a body/query field
  would trigger it for real.
- **AUTHZ-001 doesn't fire on a full-spec run against
  `GET /users/{user_id}`** specifically, because baseline capture's own
  `DELETE /users/{user_id}` baseline call deletes user 1 before the
  fuzzing pass starts (documented since Phase 3, still unsolved) — every
  mutation against that endpoint then 404s regardless of the mutated id.
  Demonstrated working correctly via a targeted single-endpoint test
  instead (`tests/test_rules_pipeline.py`). A future fix to baseline-
  capture ordering (e.g. capturing read-only baselines before
  state-changing ones) would make this reachable on a full run too.
- **DATA-001 is name-only, not value- or type-aware** — a boolean field
  literally named `password_reset_available` would still match. A
  deliberate, documented tradeoff (conservative, explainable, no
  guessing at semantics) over a "smarter" rule that would need to.
- **No rule currently uses `RESPONSE_SIZE_CHANGED` or
  `TIMING_ANOMALY` anomalies** (both produced by Phase 5's analyzer,
  neither consumed by any Phase 7 rule yet) — e.g. a mutation that
  causes a dramatically slower response could be a resource-exhaustion
  signal worth its own rule. Left out to keep this phase's rule set
  small and defensible rather than exhaustive, per its own instruction.
- Deduplication is finding-level only (endpoint + rule + location) —
  it does not attempt cross-rule correlation (e.g. recognizing that an
  AUTH-001 and an AUTHZ-001 finding on the same endpoint might describe
  related underlying behavior). Each rule's findings stand alone.
- **No pagination or size cap on the HTML/Markdown report itself** — a
  scan with hundreds of findings would produce one large (if
  internally truncated per-field) file rather than being split or
  paginated. Individual large VALUES are truncated (`safe_excerpt`),
  but the overall finding COUNT isn't capped by the reporter — that's
  `MutationConfig.max_total_mutations` and dedup's job upstream, which
  already bound this in practice; a report genuinely produced from an
  enormous, unbounded scan is not separately guarded against here.
- **CLI has no dry-run/validate-only mode** — every invocation performs
  a real scan against the real target. Fine for this project's current
  scope (a local/authorized test target), worth revisiting before
  pointing this at anything more sensitive.
- Only one real LLM provider implemented (OpenAI-compatible, via raw
  `httpx`) — genuinely covers OpenAI/OpenRouter/most local gateways in
  practice, but a native Anthropic Messages-API provider (different
  request shape) isn't implemented. Adding one is a small, additive
  change against the same `LLMProvider` interface — not attempted here
  per "at least one real provider" being the phase's actual requirement.
- The LLM generator only targets path/query/body locations, same as
  Phase 4's deterministic engine — no header-value fuzzing (e.g.
  proposing a mutated auth token). Consistent, deliberate scope
  boundary across both generators, not an oversight specific to this
  phase.
- `generate_combined_mutations` makes exactly one LLM call per endpoint
  (matching "one call can generate several candidate tests rather than
  one call per field" from the phase spec) — there's no retry-with-
  feedback loop (e.g. re-prompting after a validation rejection to ask
  for a corrected candidate). Simple and predictable; revisit only if a
  real provider's rejection rate in practice turns out to be high
  enough to matter.
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
### Phase 9 — n8n Automation (most likely next)
Per every architecture diagram from Phase 5 onward (Findings → Reports
→ n8n → Slack/Discord), reporting was the last piece n8n needed to
exist before it had something concrete to trigger from and consume.
`app/cli.py` (Phase 8) is already the shape an n8n "Execute Command"
node would call, and `security-report.json`'s stable, documented shape
(Phase 8) is already what an n8n "Read JSON" node would parse — the
next phase is wiring an actual n8n workflow around them: trigger scan →
wait for completion → read the JSON report → branch on
`severity_counts`/`total_findings` → notify. Slack/Discord alerting
follows naturally once n8n exists to send them from. Actual next-phase
scope is whatever the next phase doc specifies.
