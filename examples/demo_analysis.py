"""
Demo: capture baselines and run a fuzzing pass live, persist both to
JSON, RELOAD them from disk, then run the Phase 5 analyzer against the
reloaded data and print observations.

The reload step matters: it proves the analyzer works from the same
structured JSON a later reporting phase will consume — not just from
in-memory objects freshly produced in the same process.

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_analysis.py

No severity or confidence is assigned anywhere in this output — see
PROJECT_STATE.md for why that's a deliberate phase boundary, not an
oversight. GET /slow is naturally excluded: with the request timeout
below its default 2s delay, its own baseline capture times out, so
run_fuzzing_pass skips it before any mutation of it is ever attempted
(see tests/test_analyzer_pipeline.py for the full explanation of why
that matters).
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.analyzer.analyzer import analyze  # noqa: E402
from app.analyzer.models import AnalysisConfig  # noqa: E402
from app.core.config import RunnerSettings  # noqa: E402
from app.fuzzer.baseline import BaselineStore, capture_baselines  # noqa: E402
from app.fuzzer.mutation_runner import MutationResult, run_fuzzing_pass  # noqa: E402
from app.fuzzer.mutations.models import MutationConfig  # noqa: E402
from app.parser.openapi_parser import parse_openapi_spec  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
REPORTS_DIR = Path(__file__).parent.parent / "reports"
BASELINES_PATH = REPORTS_DIR / "analysis-demo-baselines.json"
MUTATIONS_PATH = REPORTS_DIR / "analysis-demo-mutations.json"
ANALYSIS_PATH = REPORTS_DIR / "analysis-demo-results.json"

SETTINGS = RunnerSettings(
    base_url="http://localhost:8001",
    auth_header_name="x-api-token",
    auth_header_value="alice-token",
    request_timeout_seconds=1.0,
)
FUZZ_CONFIG = MutationConfig(max_total_mutations=150, skip_methods={"DELETE"})


async def main():
    spec = parse_openapi_spec(SPEC_PATH)

    print("Capturing baselines and running a fuzzing pass...")
    baseline_store = await capture_baselines(spec, SETTINGS)
    results_by_endpoint = await run_fuzzing_pass(spec, baseline_store, SETTINGS, config=FUZZ_CONFIG)
    total_mutations = sum(len(v) for v in results_by_endpoint.values())
    print(f"  {total_mutations} mutations executed across {len(results_by_endpoint)} endpoints\n")

    # Persist both to disk...
    REPORTS_DIR.mkdir(exist_ok=True)
    baseline_store.save_to_file(str(BASELINES_PATH))
    flat_results = [mr.to_dict() for results in results_by_endpoint.values() for mr in results]
    with open(MUTATIONS_PATH, "w") as f:
        json.dump(flat_results, f, indent=2)

    # ...then reload from disk before analyzing, proving the analyzer
    # works from persisted data, not just in-memory objects still warm
    # from the same process.
    reloaded_baselines = BaselineStore.load_from_file(str(BASELINES_PATH))
    with open(MUTATIONS_PATH) as f:
        reloaded_mutation_results = [MutationResult.from_dict(d) for d in json.load(f)]
    print(
        f"Reloaded {len(reloaded_baselines)} baselines and "
        f"{len(reloaded_mutation_results)} mutation results from disk.\n"
    )

    config = AnalysisConfig()
    all_analyses = []
    for mr in reloaded_mutation_results:
        method, path = mr.baseline_key.split(" ", 1)
        baseline = reloaded_baselines.get(method, path)
        if baseline is None:
            continue
        all_analyses.append(analyze(baseline.result, mr.mutation, mr.result, mr.baseline_key, config))

    anomalous = [a for a in all_analyses if a.anomalies]
    print(f"Analyzed {len(all_analyses)} mutation results — {len(anomalous)} produced at least one observation.\n")

    print("--- Sample observations (no severity assigned) ---\n")
    for analysis in anomalous[:8]:
        print(f"{analysis.baseline_key}  |  {analysis.mutation.location} -> {analysis.mutation.mutated_value!r}")
        print(
            f"  baseline={analysis.baseline_status} ({analysis.baseline_status_category.value})  "
            f"mutation={analysis.mutation_status} ({analysis.mutation_status_category.value})"
        )
        for a in analysis.anomalies:
            print(f"  - {a.type.value}: {a.evidence}")
        print()

    with open(ANALYSIS_PATH, "w") as f:
        json.dump([a.model_dump(mode="json") for a in all_analyses], f, indent=2)
    print(f"No severity assigned — evidence only. Saved full analysis to {ANALYSIS_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
