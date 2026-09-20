"""
Demo: parse the vulnerable-api spec, capture baselines, generate
deterministic mutations, execute them all, and print a summary.

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_fuzz.py

Uses a real running server (not an in-process mock) deliberately: the
spec includes /slow, and a numeric mutation with no declared bounds can
produce a very large value (e.g. delay=999999999). Against a real
client with a real timeout, that resolves itself gracefully — /slow's
own baseline (default delay=2.0) executes fine within a 5s timeout, but
if you lower FUZZER_REQUEST_TIMEOUT_SECONDS below 2, its baseline will
legitimately time out and it'll be skipped from mutation, exactly like
any other endpoint whose baseline didn't execute. See
tests/test_mutation_runner.py for the full explanation.

This does NOT classify anything as a vulnerability. It generates and
executes security-oriented test cases and records what happened —
interpretation is Phase 7+ (anomaly detection) and Phase 8 (security
rules), both still ahead.
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import RunnerSettings  # noqa: E402
from app.fuzzer.baseline import capture_baselines  # noqa: E402
from app.fuzzer.mutation_runner import run_fuzzing_pass  # noqa: E402
from app.fuzzer.mutations.models import MutationConfig  # noqa: E402
from app.parser.openapi_parser import parse_openapi_spec  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
OUTPUT_PATH = Path(__file__).parent.parent / "reports" / "fuzz-demo.json"

SETTINGS = RunnerSettings(
    base_url="http://localhost:8001",
    auth_header_name="x-api-token",
    auth_header_value="alice-token",
    request_timeout_seconds=5.0,
)

# DELETE skipped by default in this demo — repeatedly mutating and
# executing DELETE would just repeatedly delete the same seeded users,
# which makes the rest of the run's results harder to interpret. This
# is exactly the kind of safety toggle Phase 4 asked for.
CONFIG = MutationConfig(max_total_mutations=200, skip_methods={"DELETE"})


async def main():
    spec = parse_openapi_spec(SPEC_PATH)
    print("API Security Fuzzing Demo (deterministic, no LLM)\n")
    print(f"Target:    {SETTINGS.base_url}")
    print(f"Endpoints: {spec.endpoint_count()}\n")

    print("Capturing baselines...")
    baseline_store = await capture_baselines(spec, SETTINGS)
    baseline_ok = sum(1 for b in baseline_store.all() if b.result.executed)
    print(f"  {baseline_ok}/{len(baseline_store)} baselines executed successfully\n")

    print("Generating and executing mutations...")
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, SETTINGS, config=CONFIG)
    total_mutations = sum(len(v) for v in results_by_endpoint.values())
    print(f"  {total_mutations} mutations executed across {len(results_by_endpoint)} endpoints\n")

    print(f"{'Endpoint':<28} {'Mutations':>10} {'2xx':>5} {'4xx':>5} {'5xx':>5} {'errors':>7}")
    for key, results in results_by_endpoint.items():
        status_buckets = {"2xx": 0, "4xx": 0, "5xx": 0, "errors": 0}
        for r in results:
            if r.result.error is not None:
                status_buckets["errors"] += 1
            elif r.result.status_code is not None:
                bucket = f"{r.result.status_code // 100}xx"
                if bucket in ("2xx", "4xx", "5xx"):
                    status_buckets[bucket] += 1
        print(
            f"{key:<28} {len(results):>10} {status_buckets['2xx']:>5} "
            f"{status_buckets['4xx']:>5} {status_buckets['5xx']:>5} {status_buckets['errors']:>7}"
        )

    # Structured JSON report: scan info + baseline + mutations + results,
    # per the phase's report-format requirement. No severity — evidence
    # only.
    report = {
        "target": SETTINGS.base_url,
        "endpoint_count": spec.endpoint_count(),
        "total_mutations_executed": total_mutations,
        "endpoints": [],
    }
    for key, results in results_by_endpoint.items():
        method, path = key.split(" ", 1)
        baseline = baseline_store.get(method, path)
        report["endpoints"].append(
            {
                "endpoint": key,
                "baseline": {"status_code": baseline.result.status_code if baseline else None},
                "mutations": [r.to_dict() for r in results],
            }
        )

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved full results to {OUTPUT_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
