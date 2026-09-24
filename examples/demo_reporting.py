"""
Demo: OpenAPI -> baseline -> deterministic + LLM-assisted mutations ->
execution -> response analysis -> security rules -> findings -> reports
(JSON, Markdown, HTML).

Runs fully offline by default (LLM_PROVIDER=fake, same as Phase 6/7's
demos). Uses the ACTUAL Phase 7 finding output - nothing here is
fabricated to make the report look more impressive than the real scan.

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_reporting.py

Equivalent to running:
    python -m app.cli --spec examples/vulnerable-api-openapi.json \\
        --target http://localhost:8001 --auth-header x-api-token \\
        --auth-value alice-token --report-dir reports
but spelled out step-by-step for readability, matching every other
phase's demo script in this project.
"""

import asyncio
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
from app.reports.service import ReportService  # noqa: E402
from app.rules.pipeline import evaluate_fuzzing_results  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
REPORT_DIR = Path(__file__).parent.parent / "reports"

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

    spec = parse_openapi_spec(SPEC_PATH)
    baseline_store = await capture_baselines(spec, SETTINGS)
    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, SETTINGS, provider=provider, fuzz_config=FUZZ_CONFIG, generator_config=GENERATOR_CONFIG
    )
    findings = evaluate_fuzzing_results(baseline_store, summary.results_by_endpoint)

    print("IntelliFuzz Reporting Demo")
    print("-" * 60)
    print()
    print(f"Findings: {len(findings)}")
    print()

    written = ReportService().generate(
        findings,
        output_dir=str(REPORT_DIR),
        formats=["json", "markdown", "html"],
        target_base_url=SETTINGS.base_url,
        spec_title=spec.title,
        base_filename="security-report",
    )

    print("Generated:")
    for fmt, path in written.items():
        print(f"  {path}")
    print()
    print("Open reports/security-report.html directly in a browser to view it.")


if __name__ == "__main__":
    asyncio.run(main())
