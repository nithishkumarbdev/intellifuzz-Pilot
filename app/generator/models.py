"""
Data models for LLM-assisted test generation.

Two distinct model "levels" live here, deliberately kept separate:

1. The RAW shape we ask the LLM to return (LLMGenerationResponse and
   friends) — untrusted, parsed defensively, never executed directly.
2. Bookkeeping types (GeneratorConfig, RejectedCandidate,
   CombinedGenerationResult, CombinedScanSummary) that describe what
   the generation pipeline did, for logging/summaries/tests.

Once a raw candidate passes validation, it becomes a
MutatedTestCase (app.fuzzer.mutations.models) — the SAME type
deterministic mutations use. That convergence point is the whole
architectural point of this module; nothing downstream of validation
should need to know a mutation came from an LLM at all, except via the
`source`/`reason`/`confidence` fields already added to that type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import BaseModel, Field

from app.fuzzer.mutation_runner import MutationResult


class LLMEndpointEcho(BaseModel):
    """The LLM must echo back which endpoint it believes it's proposing
    tests for. We independently verify this matches the endpoint we
    actually asked about — the LLM's own claim is never trusted as the
    routing decision (see candidates.py)."""

    method: str
    path: str


class LLMTestCandidateRaw(BaseModel):
    """One untrusted candidate, exactly as parsed from the model's JSON
    output. Every field is deliberately permissive at this stage —
    strict checking against the real endpoint happens in
    candidates.py, not here. Pydantic only enforces "is this even the
    right shape", not "is this a valid test for this API"."""

    name: Optional[str] = None
    target_location: str
    mutation_type: Optional[str] = None
    proposed_value: Any = None
    reason: Optional[str] = None
    confidence: Optional[float] = None


class LLMGenerationResponse(BaseModel):
    endpoint: LLMEndpointEcho
    tests: list[LLMTestCandidateRaw] = Field(default_factory=list)


@dataclass
class RejectedCandidate:
    """A candidate that failed validation — kept for logging/summary,
    never converted into anything executable."""

    raw: LLMTestCandidateRaw
    reason: str  # short machine-readable code, e.g. "unknown_field"
    detail: str


class GeneratorConfig(BaseModel):
    """Bounds on LLM-assisted generation. Mirrors MutationConfig's own
    "conservative defaults, explicit limits" philosophy — the model is
    never trusted to self-limit its own output."""

    max_candidates_per_endpoint: int = 10
    max_total_llm_calls: int = 50
    max_output_tokens: int = 1024


@dataclass
class CombinedGenerationResult:
    """Summary of one endpoint's combined (deterministic + LLM)
    generation pass, plus the final deduplicated mutation list ready
    for execution."""

    deterministic_count: int
    llm_candidate_count: int  # accepted + rejected, i.e. everything the model proposed
    llm_accepted_count: int
    llm_rejected: list[RejectedCandidate]
    duplicates_removed: int
    llm_error: Optional[str]
    mutations: list  # list[MutatedTestCase] — typed loosely here to avoid a circular import; see pipeline.py


@dataclass
class CombinedScanSummary:
    """Aggregated across an entire run_combined_fuzzing_pass call —
    exactly the numbers the phase's own demo/summary format asks for."""

    deterministic_count: int = 0
    llm_candidate_count: int = 0
    llm_accepted_count: int = 0
    llm_rejected_count: int = 0
    duplicates_removed: int = 0
    llm_errors: list[str] = field(default_factory=list)
    results_by_endpoint: dict[str, list[MutationResult]] = field(default_factory=dict)

    def record(self, endpoint_key: str, generation: CombinedGenerationResult) -> None:
        self.deterministic_count += generation.deterministic_count
        self.llm_candidate_count += generation.llm_candidate_count
        self.llm_accepted_count += generation.llm_accepted_count
        self.llm_rejected_count += len(generation.llm_rejected)
        self.duplicates_removed += generation.duplicates_removed
        if generation.llm_error:
            self.llm_errors.append(f"{endpoint_key}: {generation.llm_error}")

    @property
    def total_executed(self) -> int:
        return sum(len(v) for v in self.results_by_endpoint.values())
