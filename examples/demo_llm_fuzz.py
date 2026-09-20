"""
Demo: OpenAPI -> baseline -> deterministic mutations -> LLM candidate
generation -> validation -> deduplication -> execution -> structured
report.

Runs fully offline by default (LLM_PROVIDER=fake, the built-in
heuristic offline "model" — no network, no API key, fully
deterministic). To use a real provider instead:

    export LLM_PROVIDER=openai_compatible
    export LLM_API_KEY=sk-...
    export LLM_MODEL=gpt-4o-mini          # optional, has a default
    export LLM_BASE_URL=https://api.openai.com/v1   # optional, or point at OpenRouter/a local gateway

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_llm_fuzz.py

No severity is assigned anywhere in this output — see PROJECT_STATE.md.
LLM "confidence" values, if present, are stored and printed but never
treated as a security signal.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import RunnerSettings  # noqa: E402
from app.fuzzer.baseline import capture_baselines  # noqa: E402
from app.fuzzer.mutations.models import MutationConfig  # noqa: E402
from app.generator.config import build_provider, load_llm_settings  # noqa: E402
from app.generator.models import GeneratorConfig  # noqa: E402
from app.generator.pipeline import run_combined_fuzzing_pass  # noqa: E402
from app.parser.openapi_parser import parse_openapi_spec  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
REPORT_PATH = Path(__file__).parent.parent / "reports" / "llm-fuzz-demo.json"

SETTINGS = RunnerSettings(
    base_url="http://localhost:8001",
    auth_header_name="x-api-token",
    auth_header_value="alice-token",
    request_timeout_seconds=5.0,
)
FUZZ_CONFIG = MutationConfig(max_total_mutations=200, skip_methods={"DELETE"})
GENERATOR_CONFIG = GeneratorConfig(max_candidates_per_endpoint=5, max_total_llm_calls=20)


async def main():
    llm_settings = load_llm_settings()
    provider = build_provider(llm_settings)

    print("API Security Fuzzing — Deterministic + LLM-Assisted\n")
    print(f"Target:       {SETTINGS.base_url}")
    print(
        f"LLM provider: {llm_settings.provider}"
        + (" (offline heuristic — no network)" if llm_settings.provider == "fake" else "")
    )
    if provider is None:
        print("  -> LLM not usably configured (e.g. openai_compatible with no LLM_API_KEY) — running deterministic-only.")
    print()

    spec = parse_openapi_spec(SPEC_PATH)
    print(f"Endpoints: {spec.endpoint_count()}")

    baseline_store = await capture_baselines(spec, SETTINGS)
    baseline_ok = sum(1 for b in baseline_store.all() if b.result.executed)
    print(f"Baselines: {baseline_ok}/{len(baseline_store)} executed successfully\n")

    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, SETTINGS, provider=provider, fuzz_config=FUZZ_CONFIG, generator_config=GENERATOR_CONFIG
    )

    print("--- Scan summary ---")
    print(f"Deterministic mutations generated: {summary.deterministic_count}")
    print(f"LLM candidates proposed:           {summary.llm_candidate_count}")
    print(f"LLM candidates accepted:           {summary.llm_accepted_count}")
    print(f"LLM candidates rejected:           {summary.llm_rejected_count}")
    print(f"Duplicates removed:                {summary.duplicates_removed}")
    print(f"Total executed:                    {summary.total_executed}")
    if summary.llm_errors:
        print(f"LLM errors ({len(summary.llm_errors)}), deterministic fuzzing continued regardless:")
        for err in summary.llm_errors[:5]:
            print(f"  - {err}")
    print()

    # Show a few LLM-sourced results specifically — the part that's new
    # in this phase.
    llm_results = [
        (key, r) for key, results in summary.results_by_endpoint.items() for r in results if r.source == "llm"
    ]
    print(f"--- Sample LLM-sourced test results ({len(llm_results)} total) ---\n")
    for key, r in llm_results[:6]:
        print(f"{key}  |  {r.mutation.location} -> {r.mutation.mutated_value!r}")
        print(f"  reason: {r.reason}")
        status = r.result.status_code if r.result.error is None else f"ERROR({r.result.error.type})"
        print(f"  status: {status}")
        print()

    REPORT_PATH.parent.mkdir(exist_ok=True)
    report = {
        "target": SETTINGS.base_url,
        "llm_provider": llm_settings.provider,
        "summary": {
            "deterministic_count": summary.deterministic_count,
            "llm_candidate_count": summary.llm_candidate_count,
            "llm_accepted_count": summary.llm_accepted_count,
            "llm_rejected_count": summary.llm_rejected_count,
            "duplicates_removed": summary.duplicates_removed,
            "total_executed": summary.total_executed,
            "llm_errors": summary.llm_errors,
        },
        "endpoints": [
            {"endpoint": key, "mutations": [r.to_dict() for r in results]}
            for key, results in summary.results_by_endpoint.items()
        ],
    }
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"No severity assigned — evidence only. Saved full report to {REPORT_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
