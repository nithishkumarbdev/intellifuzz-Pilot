"""
The response analyzer: compares a baseline TestResult against a
mutation's TestResult and produces a normalized AnalysisResult.

Pure comparison only — no HTTP requests, no result storage, no
vulnerability judgment. Given the same baseline result, mutation
metadata, mutation result, and config, `analyze()` always returns the
same output (verified by an explicit determinism test).

False-positive awareness (per the project's own guidance): a status
category shift into 4xx or 5xx is recorded as an observation
(UNEXPECTED_CLIENT_ERROR / UNEXPECTED_SERVER_ERROR) regardless of
whether that shift was actually the *correct* behavior for that
mutation — e.g. removing a required field SHOULD produce a 422, and
this analyzer will still label it "unexpected" relative to the
baseline. That's intentional: this layer only describes what changed,
never whether the change was right or wrong. Deciding that is later
phases' job (deterministic security rules), which have the mutation
type available precisely to make that distinction.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from app.analyzer.models import Anomaly, AnalysisConfig, AnalysisResult, AnomalyType, StatusCategory
from app.analyzer.signatures import find_error_signatures
from app.fuzzer.mutations.models import Mutation
from app.runner.models import TestResult

AUTH_STATUS_CODES = {401, 403}


def categorize_status(result: TestResult) -> StatusCategory:
    if result.error is not None:
        return StatusCategory.TIMEOUT if result.error.type == "timeout" else StatusCategory.NETWORK_ERROR
    if result.status_code is None:
        return StatusCategory.UNKNOWN
    code = result.status_code
    if 100 <= code < 200:
        return StatusCategory.INFORMATIONAL
    if 200 <= code < 300:
        return StatusCategory.SUCCESS
    if 300 <= code < 400:
        return StatusCategory.REDIRECT
    if 400 <= code < 500:
        return StatusCategory.CLIENT_ERROR
    if 500 <= code < 600:
        return StatusCategory.SERVER_ERROR
    return StatusCategory.UNKNOWN


def _response_text(result: TestResult) -> Optional[str]:
    if result.body is None:
        return None
    if isinstance(result.body, str):
        return result.body
    try:
        return json.dumps(result.body)
    except (TypeError, ValueError):
        return str(result.body)


def _extract_json_keys(body: Any) -> Optional[list[str]]:
    if isinstance(body, dict):
        return sorted(body.keys())
    return None


def _status_analysis(baseline: TestResult, mutation: TestResult) -> tuple[bool, list[Anomaly]]:
    anomalies: list[Anomaly] = []

    error_presence_changed = (baseline.error is not None) != (mutation.error is not None)
    status_changed = error_presence_changed or (baseline.status_code != mutation.status_code)

    if mutation.error is not None:
        # A network-level failure — no status code to compare against.
        anomaly_type = AnomalyType.REQUEST_TIMEOUT if mutation.error.type == "timeout" else AnomalyType.NETWORK_ERROR
        anomalies.append(
            Anomaly(type=anomaly_type, evidence={"error_type": mutation.error.type, "message": mutation.error.message})
        )
        return status_changed, anomalies

    b_code, m_code = baseline.status_code, mutation.status_code
    b_cat, m_cat = categorize_status(baseline), categorize_status(mutation)

    if status_changed:
        anomalies.append(Anomaly(type=AnomalyType.STATUS_CHANGED, evidence={"baseline_status": b_code, "mutation_status": m_code}))

    if m_cat == StatusCategory.SERVER_ERROR and b_cat != StatusCategory.SERVER_ERROR:
        anomalies.append(
            Anomaly(type=AnomalyType.UNEXPECTED_SERVER_ERROR, evidence={"baseline_status": b_code, "mutation_status": m_code})
        )
    elif m_cat == StatusCategory.CLIENT_ERROR and b_cat != StatusCategory.CLIENT_ERROR:
        anomalies.append(
            Anomaly(type=AnomalyType.UNEXPECTED_CLIENT_ERROR, evidence={"baseline_status": b_code, "mutation_status": m_code})
        )

    baseline_is_auth_status = b_code in AUTH_STATUS_CODES
    mutation_is_auth_status = m_code in AUTH_STATUS_CODES
    if baseline_is_auth_status != mutation_is_auth_status:
        anomalies.append(
            Anomaly(
                type=AnomalyType.AUTHENTICATION_BEHAVIOR_CHANGED,
                evidence={"baseline_status": b_code, "mutation_status": m_code},
            )
        )

    if m_cat == StatusCategory.REDIRECT and b_cat != StatusCategory.REDIRECT:
        location = mutation.headers.get("location") or mutation.headers.get("Location")
        anomalies.append(
            Anomaly(
                type=AnomalyType.REDIRECT_CHANGED,
                evidence={"baseline_status": b_code, "mutation_status": m_code, "location": location},
            )
        )

    return status_changed, anomalies


def _timing_analysis(
    baseline: TestResult, mutation: TestResult, config: AnalysisConfig
) -> tuple[bool, Optional[float], Optional[float], list[Anomaly]]:
    b_time, m_time = baseline.response_time_ms, mutation.response_time_ms
    if b_time is None or m_time is None:
        return False, None, None, []

    difference = m_time - b_time
    if b_time > 0:
        ratio = m_time / b_time
    else:
        ratio = float("inf") if m_time > 0 else 1.0

    is_anomaly = abs(difference) >= config.min_time_difference_ms and ratio >= config.min_time_multiplier
    anomalies: list[Anomaly] = []
    if is_anomaly:
        anomalies.append(
            Anomaly(
                type=AnomalyType.TIMING_ANOMALY,
                evidence={
                    "baseline_response_time_ms": b_time,
                    "mutation_response_time_ms": m_time,
                    "difference_ms": round(difference, 2),
                    "ratio": None if ratio == float("inf") else round(ratio, 2),
                },
            )
        )
    return is_anomaly, round(difference, 2), (None if ratio == float("inf") else round(ratio, 2)), anomalies


def _body_analysis(
    baseline: TestResult, mutation: TestResult, config: AnalysisConfig
) -> tuple[dict[str, bool], list[Anomaly]]:
    anomalies: list[Anomaly] = []
    body_changed = baseline.body != mutation.body
    size_changed = False
    structure_changed = False

    b_size, m_size = baseline.body_size, mutation.body_size
    if b_size is not None and m_size is not None:
        size_difference = m_size - b_size
        if abs(size_difference) >= config.min_body_size_difference_bytes:
            size_changed = True
            anomalies.append(
                Anomaly(
                    type=AnomalyType.RESPONSE_SIZE_CHANGED,
                    evidence={"baseline_body_size": b_size, "mutation_body_size": m_size, "difference_bytes": size_difference},
                )
            )

    if baseline.body_is_json != mutation.body_is_json:
        structure_changed = True
        anomalies.append(
            Anomaly(
                type=AnomalyType.RESPONSE_STRUCTURE_CHANGED,
                evidence={"baseline_is_json": baseline.body_is_json, "mutation_is_json": mutation.body_is_json},
            )
        )
    else:
        b_keys, m_keys = _extract_json_keys(baseline.body), _extract_json_keys(mutation.body)
        if b_keys is not None and m_keys is not None and b_keys != m_keys:
            structure_changed = True
            anomalies.append(
                Anomaly(
                    type=AnomalyType.RESPONSE_STRUCTURE_CHANGED,
                    evidence={"baseline_keys": b_keys, "mutation_keys": m_keys},
                )
            )

    # Only add the generic "body changed" observation when neither more
    # specific signal (size, structure) already captured it — avoids
    # reporting the same underlying difference three times.
    if body_changed and not size_changed and not structure_changed:
        anomalies.append(Anomaly(type=AnomalyType.RESPONSE_BODY_CHANGED, evidence={}))

    return {"body_changed": body_changed, "body_size_changed": size_changed, "body_structure_changed": structure_changed}, anomalies


def analyze(
    baseline_result: TestResult,
    mutation: Mutation,
    mutation_result: TestResult,
    baseline_key: str,
    config: Optional[AnalysisConfig] = None,
) -> AnalysisResult:
    config = config or AnalysisConfig()

    status_changed, status_anomalies = _status_analysis(baseline_result, mutation_result)
    time_changed, time_diff, time_ratio, timing_anomalies = _timing_analysis(baseline_result, mutation_result, config)
    body_flags, body_anomalies = _body_analysis(baseline_result, mutation_result, config)

    anomalies = [*status_anomalies, *timing_anomalies, *body_anomalies]

    # Error-signature scan: only flag signatures that are NEW in the
    # mutation's response — a signature already present in the baseline
    # (e.g. an endpoint that legitimately echoes the word "error") isn't
    # a signal that this specific mutation caused anything.
    mutation_signatures = find_error_signatures(_response_text(mutation_result))
    baseline_signatures = set(find_error_signatures(_response_text(baseline_result)))
    new_signatures = [s for s in mutation_signatures if s not in baseline_signatures]
    if new_signatures:
        anomalies.append(Anomaly(type=AnomalyType.ERROR_SIGNATURE_DETECTED, evidence={"matched_patterns": new_signatures}))

    return AnalysisResult(
        baseline_key=baseline_key,
        mutation=mutation,
        baseline_status=baseline_result.status_code,
        mutation_status=mutation_result.status_code,
        baseline_status_category=categorize_status(baseline_result),
        mutation_status_category=categorize_status(mutation_result),
        status_changed=status_changed,
        baseline_response_time_ms=baseline_result.response_time_ms,
        mutation_response_time_ms=mutation_result.response_time_ms,
        response_time_changed=time_changed,
        response_time_difference_ms=time_diff,
        response_time_ratio=time_ratio,
        baseline_body_size=baseline_result.body_size,
        mutation_body_size=mutation_result.body_size,
        body_size_changed=body_flags["body_size_changed"],
        body_changed=body_flags["body_changed"],
        body_structure_changed=body_flags["body_structure_changed"],
        anomalies=anomalies,
    )
