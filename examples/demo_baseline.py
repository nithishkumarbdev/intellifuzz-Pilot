"""
Demo: parse the vulnerable-api spec, capture a baseline for every
endpoint against a real running instance, and print a summary.

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_baseline.py

This also writes reports/baselines-demo.json — a persisted snapshot
that later phases (Phase 4's mutation engine, Phase 7's anomaly
detection) will load and diff mutated results against.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import RunnerSettings  # noqa: E402
from app.fuzzer.baseline import capture_baselines  # noqa: E402
from app.parser.openapi_parser import parse_openapi_spec  # noqa: E402

SPEC_PATH = Path(__file__).parent / "vulnerable-api-openapi.json"
OUTPUT_PATH = Path(__file__).parent.parent / "reports" / "baselines-demo.json"

SETTINGS = RunnerSettings(
    base_url="http://localhost:8001",
    auth_header_name="x-api-token",
    auth_header_value="alice-token",
)


async def main():
    spec = parse_openapi_spec(SPEC_PATH)
    print(f"Capturing baselines for {spec.endpoint_count()} endpoints...\n")

    store = await capture_baselines(spec, SETTINGS)

    for baseline in store.all():
        outcome = (
            f"error({baseline.result.error.type})"
            if baseline.result.error
            else f"status={baseline.result.status_code}"
        )
        print(f"{baseline.endpoint_method:6} {baseline.endpoint_path:24} -> {outcome}")

    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    store.save_to_file(str(OUTPUT_PATH))
    print(f"\nSaved {len(store)} baselines to {OUTPUT_PATH}")


if __name__ == "__main__":
    asyncio.run(main())
