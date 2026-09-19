"""
Captures a baseline (valid request + its result) for every endpoint in
a parsed APISpec, and holds them in a BaselineStore — the reference
point every future mutation's result gets compared against (Phase 7).

No database: a scan's baselines are a handful of JSON-serializable
objects, held in memory during a scan and optionally written to a
single JSON file. That's simple, inspectable, and sufficient — a
database would be solving a problem we don't have yet.

IMPORTANT CAVEAT, documented rather than hidden: baseline capture runs
sequentially, one endpoint at a time, in whatever order the spec
listed them. For a state-changing API (this includes our own
vulnerable-api — e.g. its DELETE /users/{user_id}), an earlier
baseline call can change or remove data that a later baseline call
implicitly depends on (both happen to default to the same generated
path param value, e.g. user_id=1). Phase 3 does not attempt to solve
safe test ordering or state isolation — that's a real problem for a
production fuzzer, tracked in PROJECT_STATE.md as a known gap.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import httpx

from app.core.config import RunnerSettings
from app.fuzzer.test_case_builder import build_baseline_test_case
from app.parser.models import APISpec, Endpoint
from app.runner.http_runner import execute_test_case
from app.runner.models import ErrorInfo, TestCase, TestResult
from app.runner.validation import ValidationError


@dataclass
class Baseline:
    endpoint_path: str
    endpoint_method: str
    test_case: TestCase
    result: TestResult

    def to_dict(self) -> dict:
        return {
            "endpoint_path": self.endpoint_path,
            "endpoint_method": self.endpoint_method,
            "test_case": self.test_case.model_dump(),
            "result": self.result.model_dump(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls(
            endpoint_path=data["endpoint_path"],
            endpoint_method=data["endpoint_method"],
            test_case=TestCase.model_validate(data["test_case"]),
            result=TestResult.model_validate(data["result"]),
        )


class BaselineStore:
    """Keyed by (method, path) — one baseline per endpoint."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], Baseline] = {}

    def add(self, baseline: Baseline) -> None:
        key = (baseline.endpoint_method.upper(), baseline.endpoint_path)
        self._data[key] = baseline

    def get(self, method: str, path: str) -> Optional[Baseline]:
        return self._data.get((method.upper(), path))

    def all(self) -> list[Baseline]:
        return list(self._data.values())

    def __len__(self) -> int:
        return len(self._data)

    def to_json(self) -> str:
        return json.dumps([b.to_dict() for b in self._data.values()], indent=2)

    @classmethod
    def from_json(cls, text: str) -> "BaselineStore":
        store = cls()
        for raw in json.loads(text):
            store.add(Baseline.from_dict(raw))
        return store

    def save_to_file(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(self.to_json())

    @classmethod
    def load_from_file(cls, path: str) -> "BaselineStore":
        with open(path) as f:
            return cls.from_json(f.read())


async def capture_baseline_for_endpoint(
    endpoint: Endpoint,
    settings: RunnerSettings,
    client: Optional[httpx.AsyncClient] = None,
) -> Baseline:
    test_case = build_baseline_test_case(endpoint, settings)
    try:
        result = await execute_test_case(test_case, settings, client=client)
    except ValidationError as exc:
        # Shouldn't normally happen — we build the test case ourselves —
        # but if the generator ever produces something invalid (e.g. an
        # endpoint the parser couldn't fully resolve), record that as
        # the baseline's outcome rather than crashing the whole capture.
        result = TestResult(error=ErrorInfo(type="validation_error", message=str(exc)))

    return Baseline(
        endpoint_path=endpoint.path,
        endpoint_method=endpoint.method,
        test_case=test_case,
        result=result,
    )


async def capture_baselines(
    spec: APISpec,
    settings: RunnerSettings,
    client: Optional[httpx.AsyncClient] = None,
) -> BaselineStore:
    store = BaselineStore()
    for endpoint in spec.endpoints:
        baseline = await capture_baseline_for_endpoint(endpoint, settings, client=client)
        store.add(baseline)
    return store
