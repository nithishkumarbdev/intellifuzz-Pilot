# IntelliFuzz — AI-Powered API Security Fuzzer

An automation-heavy API security testing pipeline: an OpenAPI/Swagger
specification goes in, adversarial test cases are generated
(deterministically, and — optionally — with LLM assistance), executed
automatically against the target API, and the results are analyzed and
classified into structured security findings.

(Named IntelliFuzz starting with its Phase 7 spec doc — no functional
change, just the name the project goes by from here on.)

## Why this project exists

The easy version of "AI security fuzzer" is *send the API spec to an
LLM and ask if it's vulnerable*. That's mostly an LLM wrapper, and its
output is exactly as reliable as one model's guess.

This project is built the other way around: a real, deterministic
fuzzing and analysis engine comes first — parsing, execution, mutation,
response comparison, rule-based classification — and the LLM is added
*on top of* that foundation as an optional layer that **proposes**
additional test ideas. It never executes anything itself, and it has no
say in whether a result is suspicious or how severe it is. The core
architectural principle, unchanged since the first line of code:

> **AI proposes. Deterministic systems validate, execute, and decide.**

## Architecture

```text
OpenAPI / Swagger
        │
        ▼
  Spec Parser                              (app/parser)
        │
        ▼
  Baseline Builder                         (app/fuzzer/baseline.py)
        │
        ├────────────────┬─────────────────┐
        ▼                ▼                 │
  Deterministic     LLM Generator          │
  Mutations         (optional, provider-   │
  (app/fuzzer/       agnostic)             │
   mutations)        (app/generator)       │
        │                │                 │
        └───── validated, deduplicated ────┘
                    │
                    ▼
              Generic HTTP Runner           (app/runner)
                    │
                    ▼
              Response Analysis             (app/analyzer)
              (behavioral observations,
               no severity yet)
                    │
                    ▼
              Security Rule Engine          (app/rules)
              (deterministic findings,
               real severity — the first
               place severity appears)
                    │
                    ▼
          [ next: reporting, n8n, alerts ]
```

Every stage after the parser is independently testable and has run
against the project's own intentionally-vulnerable local test API
(`vulnerable-api/`) — nothing here has only been unit-tested in
isolation.

## Current status

| Phase | What it does | Status |
|---|---|---|
| 1 | OpenAPI/Swagger → normalized `APISpec` | done |
| 2 | Generic HTTP execution engine, provider-agnostic | done |
| 3 | Deterministic baseline capture | done |
| 4 | Deterministic mutation/fuzzing engine | done |
| 5 | Response analysis & anomaly detection (evidence, no severity) | done |
| 6 | LLM-assisted intelligent test generation (optional, provider-agnostic) | done |
| 7 | Deterministic security rules & finding classification (real severity) | done |
| 8+ | Reporting, n8n, Slack/Discord alerts | not yet |

See `PROJECT_STATE.md` for the detailed, per-phase build log — what was
built, why, what broke along the way and how it was fixed, and honestly
stated known limitations. That file is the real source of truth on
"where is this project, exactly" — this README is the tour.

## Anomaly vs. signal vs. finding

Three different, deliberately-separated concepts get easy to conflate
in a project like this, so here's the precise distinction:

- **Anomaly** (`app/analyzer`, Phase 5) — "this specific mutation's
  result differs from the baseline in some measurable way": a status
  code changed, a response got bigger, a new JSON key appeared. Pure
  observation. No judgment about whether the difference matters.
- **Signal / Finding** (`app/rules`, Phase 7) — "this specific pattern
  of evidence matches a rule that's worth a human looking at": a
  deterministic `SecurityRule` looked at the anomaly evidence (plus the
  mutation that caused it) and recognized a named, defensible pattern
  — e.g. *baseline succeeded, mutation caused a 5xx* (`INPUT-001`) or
  *a path identifier was swapped and both requests still succeeded*
  (`AUTHZ-001`). A `Finding` always carries a `Severity` (impact if the
  pattern is real) and a `Confidence` (how sure the rule can be, kept
  strictly separate — see below) — the first place in this project
  either of those exists.
- **Confirmed vulnerability** — does not exist anywhere in this
  project's output, on purpose. Every finding's title starts with
  "Potential"; the rules are tested explicitly to make sure phrasing
  like "confirmed" or "bypass confirmed" never appears. A `Finding` is
  where to start an investigation, not where one ends.

Concretely: Phase 5 says *"something changed."* Phase 7 says *"this
change matches a deterministic security-relevant pattern — here's how
bad it could be, and here's how sure we are."* Neither says *"this is a
vulnerability."*

`Severity` and `Confidence` are intentionally independent scales — a
`HIGH` severity / `LOW` confidence finding (e.g. `AUTHZ-001`: a
cross-resource access pattern the fuzzer cannot independently verify as
unauthorized) is a completely normal, valid combination, not a
contradiction.

## Technology stack

- **Python + FastAPI** — the fuzzer's own thin backend API, and the
  local vulnerable test target
- **httpx** — async HTTP execution (the runner, and the LLM provider's
  HTTP calls — no separate provider SDK)
- **Pydantic** — schema validation throughout, including LLM output
  validation
- **pytest** — the whole test suite (281 tests as of Phase 7)

No database (JSON files are sufficient at this project's current
scale), no Kubernetes, no message broker — deliberately. See
`PROJECT_STATE.md`'s "Known gaps" sections for what's genuinely
simplified vs. what's a real limitation.

## Running it

### 1. Start the local vulnerable test API

```bash
cd vulnerable-api
pip install -r requirements.txt
uvicorn app.main:app --port 8001
```

This is an intentionally vulnerable FastAPI app (IDOR, weak input
validation, missing auth on one endpoint, etc. — each documented inline
in `vulnerable-api/app/main.py`) used as the fuzzer's own development
and demo target. Only test APIs you own or are explicitly authorized to
test — see the Security scope section below.

### 2. Install the fuzzer's own dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the demos

Each demo is self-contained and runs against the vulnerable-api started
above:

```bash
python3 examples/demo_parse.py        # Phase 1: parse the spec, print endpoints
python3 examples/demo_run.py          # Phase 2: execute a few hand-built requests
python3 examples/demo_baseline.py     # Phase 3: capture a baseline for every endpoint
python3 examples/demo_fuzz.py         # Phase 4: deterministic mutation + execution
python3 examples/demo_analysis.py     # Phase 5: mutation + response analysis
python3 examples/demo_llm_fuzz.py     # Phase 6: deterministic + LLM-assisted, offline by default
python3 examples/demo_findings.py     # Phase 7: full pipeline through to security findings
```

`demo_llm_fuzz.py` and `demo_findings.py` run fully offline by default
(`LLM_PROVIDER=fake` — a deterministic, endpoint-aware heuristic
"model", no network, no API key). To use a real provider instead:

```bash
export LLM_PROVIDER=openai_compatible
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4o-mini                     # optional
export LLM_BASE_URL=https://api.openai.com/v1    # optional — or OpenRouter / a local gateway
python3 examples/demo_findings.py
```

`OpenAICompatibleProvider` works unmodified against OpenAI itself,
OpenRouter, and most local model gateways (Ollama's OpenAI-compat mode,
vLLM, etc.) — anything that speaks the standard `/chat/completions`
shape.

### 4. Run the test suite

```bash
pytest -q
```

281 tests, all passing, no real network access or API key required
anywhere (the LLM provider tests use `httpx.MockTransport`; the runner
tests use a mix of in-process ASGI transport and a real local socket
where timeout behavior genuinely requires one — see
`tests/conftest.py`).

## How the LLM is actually used

`app/generator/` is the whole LLM-assisted layer. In order:

1. **Context** (`context.py`) — builds a small, safe, per-endpoint
   context: method, path, parameter/field schemas, the baseline
   request. Deliberately excludes headers entirely (a real auth token
   value can never reach a prompt) and every other endpoint (keeps the
   prompt small and keeps "only propose tests for this endpoint"
   enforceable).
2. **Prompt** (`prompt.py`) — a template, not string-built logic. The
   security-boundary system prompt is injected by the provider as an
   actual system-role message, separate from the untrusted context —
   concrete resistance to a prompt-injection attempt hidden in an
   OpenAPI description, not just a comment saying so.
3. **Provider** (`provider.py`) — `LLMProvider` is a two-method
   abstraction (`generate(prompt) -> text`). A fake, fully offline
   implementation and a real OpenAI-compatible one both satisfy it.
4. **Validation** (`candidates.py`) — the actual enforcement point.
   The model's self-reported endpoint is checked against the endpoint
   actually queried (mismatch rejects the whole batch); every
   `target_location` must resolve to a real field on that endpoint;
   only `path`/`query`/`body` locations are accepted, never `header`.
   The model can never supply a host, scheme, or URL — nothing here
   reads anything but a location string and a value.
5. **Deduplication** (`pipeline.py`) — an LLM candidate that happens to
   match a deterministic mutation exactly (same endpoint, location,
   value) is dropped rather than executed twice.
6. **Convergence** — a validated, deduplicated LLM candidate becomes
   exactly the same `MutatedTestCase` type a deterministic mutation is.
   The HTTP runner that executes it has no idea, and doesn't need to,
   where a given test case came from. The rule engine (Phase 7) does
   still know — every `Finding` carries a `source` field
   (`"deterministic"` or `"llm"`) — but no rule currently treats the two
   differently.

If the LLM isn't configured, fails, times out, or returns malformed
output, the scan continues with deterministic mutations only — this is
tested explicitly, not just claimed.

## Security scope

This is a defensive security testing tool. Use it only against:

- local test APIs (like `vulnerable-api/`)
- APIs you own
- APIs you have explicit authorization to test

It is not designed or intended to evade detection, bypass rate limits,
or facilitate unauthorized access to systems you don't control.

## Repository layout

```text
app/
├── parser/       Phase 1 — OpenAPI/Swagger → normalized models
├── runner/       Phase 2 — generic HTTP execution engine
├── fuzzer/       Phase 3+4 — baseline capture, deterministic mutation engine
├── analyzer/     Phase 5 — response comparison, anomaly detection
├── generator/    Phase 6 — LLM-assisted test generation
├── rules/        Phase 7 — deterministic security rules, Finding model
├── core/         shared config (RunnerSettings)
└── api/          the fuzzer's own thin FastAPI backend

vulnerable-api/   intentionally vulnerable local test target
examples/         one runnable, self-contained demo per phase
tests/            pytest suite, one file per module + integration/e2e tests
reports/          generated output (gitignored)
```
