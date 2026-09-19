"""
Demo: execute a handful of TestCases against a real running vulnerable-api
and print the normalized results.

Run:
    # terminal 1
    cd vulnerable-api && uvicorn app.main:app --port 8001

    # terminal 2
    python3 examples/demo_run.py

This is plain runner usage — no LLM, no mutation engine, no rules engine
yet. But notice the last example: just by executing two ordinary,
correctly-authenticated requests and looking at the results side by
side, VULN #1 (the IDOR on GET /users/{user_id}) is already visible in
the raw evidence. That's the point of getting the runner right first —
everything later (baseline comparison, rules) builds on results shaped
exactly like this.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import RunnerSettings  # noqa: E402
from app.runner.http_runner import execute_test_case  # noqa: E402
from app.runner.models import TestCase  # noqa: E402

SETTINGS = RunnerSettings(base_url="http://localhost:8001")


async def run(label: str, test_case: TestCase) -> None:
    result = await execute_test_case(test_case, SETTINGS)
    print(f"--- {label} ---")
    print(f"  {result.request.method} {result.request.url}")
    if result.error:
        print(f"  ERROR ({result.error.type}): {result.error.message}")
    else:
        print(f"  status={result.status_code}  time={result.response_time_ms}ms  size={result.body_size}B")
        print(f"  body={result.body}")
    print()


async def main():
    await run("health check", TestCase(method="GET", path="/health"))

    await run(
        "alice fetches her own profile (expected)",
        TestCase(
            method="GET",
            path="/users/{user_id}",
            path_params={"user_id": 1},
            headers={"x-api-token": "alice-token"},
        ),
    )

    await run(
        "alice fetches bob's profile — should be blocked, isn't (VULN #1)",
        TestCase(
            method="GET",
            path="/users/{user_id}",
            path_params={"user_id": 2},
            headers={"x-api-token": "alice-token"},
        ),
    )

    await run(
        "unauthenticated request to /admin/stats — should be blocked, isn't (VULN #4)",
        TestCase(method="GET", path="/admin/stats"),
    )


if __name__ == "__main__":
    asyncio.run(main())
