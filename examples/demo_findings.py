"""
Demo: OpenAPI -> baseline -> deterministic + LLM-assisted mutations ->
execution -> response analysis -> security rules -> findings.

Runs fully offline by default (same LLM_PROVIDER=fake heuristic as
Phase 6's demo - no network, no API key). Results are genuine, not
curated: whatever the rules actually find against vulnerable-api's
current state is what gets printed, including runs where a given rule
category doesn't happen to fire (see PROJECT_STATE.md's Known gaps for
why AUTH-001 in particular is unlikely to fire against THIS specific
target, and how to see it fire - the isolated single-endpoint pattern
in tests/test_rules_pipeline.py demonstrates AUTHZ-001 concretely).

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_findings.py

Every finding below is a signal, never a verdict - see the title
prefix ("Potential ...") and PROJECT_STATE.md for what this phase does
and does not prove.
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
from app.rules.pipeline import evaluate_fuzzing_results  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
REPORT_PATH = Path(__file__).parent.parent / "reports" / "findings-demo.json"

SETTINGS = RunnerSettings(
    base_url="http://localhost:8001",
    auth_header_name="x-api-token",
    auth_header_value="alice-token",
    request_timeout_seconds=5.0,
)
FUZZ_CONFIG = MutationConfig(max_total_mutations=200, skip_methods={"DELETE"})
GENERATOR_CONFIG = GeneratorConfig(max_candidates_per_endpoint=5, max_total_llm_calls=20)

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


async def main():
    llm_settings = load_llm_settings()
    provider = build_provider(llm_settings)

    spec = parse_openapi_spec(SPEC_PATH)
    baseline_store = await capture_baselines(spec, SETTINGS)
    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, SETTINGS, provider=provider, fuzz_config=FUZZ_CONFIG, generator_config=GENERATOR_CONFIG
    )

    findings = evaluate_fuzzing_results(baseline_store, summary.results_by_endpoint)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.value, 9))

    print("IntelliFuzz Security Findings")
    print("-" * 60)
    print()
    print(f"Endpoints scanned:       {spec.endpoint_count()}")
    print(
        f"Mutations executed:     {summary.total_executed} "
        f"(deterministic: {summary.deterministic_count}, LLM-accepted: {summary.llm_accepted_count})"
    )
    print(f"Findings (deduplicated): {len(findings)}")
    print()

    if not findings:
        print("No findings this run - see PROJECT_STATE.md for what conditions each rule needs.")
    for f in findings:
        print(f"[{f.severity.value.upper()}] {f.title}")
        print(f"Endpoint:   {f.method} {f.endpoint}")
        print(f"Rule:       {f.rule_id}  (confidence: {f.confidence.value})")
        print(f"Mutation:   {f.mutation_location} -> {f.reproduction.mutation_value!r}  (source: {f.source})")
        details_suffix = f"  {f.evidence.details}" if f.evidence.details else ""
        print(f"Evidence:   baseline={f.evidence.baseline_status} mutation={f.evidence.mutation_status}{details_suffix}")
        print()

    print("No confirmed vulnerabilities - every finding above is a signal for human review, not a verdict.")

    REPORT_PATH.parent.mkdir(exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump([finding.model_dump(mode="json") for finding in findings], f, indent=2)
    print(f"\nSaved full findings to {REPORT_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
