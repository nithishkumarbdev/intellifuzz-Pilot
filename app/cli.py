"""
CLI entry point for running a full IntelliFuzz scan end-to-end:
parse -> baseline -> deterministic (+ optional LLM) mutations -> execute
-> analyze -> rules -> report.

This is the project's first standalone CLI. Every earlier phase was
driven through examples/demo_*.py scripts instead — those still exist
and still work (useful for reading through one phase's pipeline in
isolation), but there was no single configurable command to actually
run a scan against an arbitrary target. This consolidates the same
building blocks those demos already used into one.

Usage:
    python -m app.cli --spec examples/vulnerable-api-openapi.json \\
        --target http://localhost:8001 \\
        --auth-header x-api-token --auth-value alice-token \\
        --report-dir reports --formats json,markdown,html

    python -m app.cli --spec my-api.json --target https://staging.example.com \\
        --no-llm --skip-methods DELETE
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.core.config import RunnerSettings
from app.fuzzer.baseline import capture_baselines
from app.fuzzer.mutations.models import MutationConfig
from app.generator.config import build_provider, load_llm_settings
from app.generator.models import GeneratorConfig
from app.generator.pipeline import run_combined_fuzzing_pass
from app.parser.openapi_parser import parse_openapi_spec
from app.reports.service import ReportService
from app.rules.pipeline import evaluate_fuzzing_results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a full IntelliFuzz scan and generate reports.")
    parser.add_argument("--spec", required=True, help="Path to the OpenAPI/Swagger spec file")
    parser.add_argument("--target", required=True, help="Base URL of the target API")
    parser.add_argument("--auth-header", default=None, help="Name of the auth header to send, if any")
    parser.add_argument("--auth-value", default=None, help="Value of the auth header, if any")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds (default: 5.0)")
    parser.add_argument("--max-mutations", type=int, default=200, help="Max total mutations for the whole scan (default: 200)")
    parser.add_argument(
        "--skip-methods", default="", help="Comma-separated HTTP methods to skip during fuzzing, e.g. DELETE"
    )
    parser.add_argument("--report-dir", default="reports", help="Directory to write report files into (default: reports)")
    parser.add_argument("--formats", default="json,markdown,html", help="Comma-separated report formats")
    parser.add_argument("--report-name", default="security-report", help="Base filename for report output, no extension")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM-assisted generation even if configured")
    return parser


async def run(args: argparse.Namespace) -> int:
    settings = RunnerSettings(
        base_url=args.target,
        auth_header_name=args.auth_header,
        auth_header_value=args.auth_value,
        request_timeout_seconds=args.timeout,
    )
    fuzz_config = MutationConfig(
        max_total_mutations=args.max_mutations,
        skip_methods={m.strip().upper() for m in args.skip_methods.split(",") if m.strip()},
    )

    spec = parse_openapi_spec(args.spec)
    print(f"Parsed {spec.title} ({spec.endpoint_count()} endpoints)")

    baseline_store = await capture_baselines(spec, settings)
    baseline_ok = sum(1 for b in baseline_store.all() if b.result.executed)
    print(f"Baselines: {baseline_ok}/{len(baseline_store)} executed")

    provider = None if args.no_llm else build_provider(load_llm_settings())
    summary = await run_combined_fuzzing_pass(
        spec, baseline_store, settings, provider=provider, fuzz_config=fuzz_config, generator_config=GeneratorConfig()
    )
    print(
        f"Executed {summary.total_executed} mutations "
        f"({summary.deterministic_count} deterministic, {summary.llm_accepted_count} LLM)"
    )

    findings = evaluate_fuzzing_results(baseline_store, summary.results_by_endpoint)
    print(f"Findings: {len(findings)}")

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    written = ReportService().generate(
        findings,
        output_dir=args.report_dir,
        formats=formats,
        target_base_url=args.target,
        spec_title=spec.title,
        base_filename=args.report_name,
    )
    for fmt, path in written.items():
        print(f"  {fmt}: {path}")

    return 0


def main() -> int:
    args = build_arg_parser().parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
