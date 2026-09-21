"""
The concrete rule set. Deliberately small — five rules, each built on
evidence this project's own analyzer (Phase 5) and mutation engine
(Phase 4/6) actually produce, not a giant vulnerability taxonomy.

Every finding's title starts with "Potential" and every rule's
docstring states plainly what it does and doesn't prove. This is not
boilerplate caution — it's the load-bearing distinction the whole
phase rests on: these are investigation signals, not verdicts. A rule
that can't honestly earn HIGH confidence doesn't claim it.

Two rules are worth flagging honestly up front, in the same spirit as
this project's other "here's a real limitation" notes:

- AuthEnforcementRegressionRule's pattern (baseline was 401/403,
  mutation succeeds instead) is reachable with the CURRENT mutation
  engine's scope — a body/query/path field that incorrectly influences
  server-side authorization would trigger it — but it will not fire
  against our own vulnerable-api specifically, because vulnerable-api's
  auth check happens before any mutated field is even read. That's a
  property of this particular test target, not a gap in the rule; it's
  exercised with hand-built RuleContexts in tests instead.
- The same rule is also exactly what would catch a header-mutated
  "token removed, still succeeds" case once header mutation exists
  (currently out of scope for both generators) — no new rule would be
  needed, since it's keyed on the STATUS PATTERN, not on what changed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from app.analyzer.models import AnomalyType, StatusCategory
from app.fuzzer.mutations.models import MutationType
from app.rules.models import Confidence, Evidence, Finding, FindingCategory, Reproduction, Severity
from app.rules.rule import RuleContext, SecurityRule

# Conservative, deliberately small — per the phase's own explicit
# instruction not to build a payload/keyword database. Matched as a
# whole-word-ish substring against a NEW field NAME only, never against
# field values, and never against fields already present in the
# baseline (see SensitiveDataExposureRule).
SENSITIVE_FIELD_NAME_MARKERS = [
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "private_key",
    "ssn",
    "credit_card",
]

# Mutation types that represent a structurally-invalid value a
# well-behaved API should reject — used by BehaviorInconsistencyRule.
STRUCTURALLY_INVALID_MUTATION_TYPES = {
    MutationType.NULL,
    MutationType.MISSING_FIELD,
    MutationType.TYPE_CONFUSION,
}


def _stable_finding_id(rule_id: str, baseline_key: str, location: str, value: Any) -> str:
    """Deterministic — the same underlying finding gets the same ID
    across separate runs, matching this project's own "same input ->
    same output" standard everywhere else. Not a random UUID, not an
    incrementing counter."""
    try:
        normalized_value = json.dumps(value, sort_keys=True)
    except (TypeError, ValueError):
        normalized_value = repr(value)
    digest = hashlib.sha256(f"{rule_id}|{baseline_key}|{location}|{normalized_value}".encode()).hexdigest()[:8]
    return f"{rule_id}-{digest}"


def _reproduction(context: RuleContext) -> Reproduction:
    request = context.mutation_result.request
    return Reproduction(
        method=request.method if request else context.method,
        url=request.url if request else context.endpoint,
        headers=request.headers if request else {},
        body=request.body if request else None,
        mutation_location=context.mutation.location,
        mutation_value=context.mutation.mutated_value,
    )


def _build_finding(
    context: RuleContext,
    rule_id: str,
    title: str,
    description: str,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence,
    details: Optional[dict[str, Any]] = None,
) -> Finding:
    analysis = context.analysis
    return Finding(
        finding_id=_stable_finding_id(rule_id, context.baseline_key, context.mutation.location, context.mutation.mutated_value),
        rule_id=rule_id,
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        endpoint=context.endpoint,
        method=context.method,
        baseline_key=context.baseline_key,
        mutation_type=context.mutation.mutation_type,
        mutation_location=context.mutation.location,
        source=context.source,
        evidence=Evidence(
            baseline_status=analysis.baseline_status,
            mutation_status=analysis.mutation_status,
            baseline_body_size=analysis.baseline_body_size,
            mutation_body_size=analysis.mutation_body_size,
            details=details or {},
        ),
        reproduction=_reproduction(context),
    )


# ---------------------------------------------------------------------------
# Rule A — INPUT-001
# ---------------------------------------------------------------------------


class UnexpectedServerErrorRule(SecurityRule):
    """Baseline succeeded; this mutation's malformed/unusual input
    caused a server-side 5xx instead of a clean rejection. This proves
    only that the input triggered unexpected server-side behavior — NOT
    that the behavior is exploitable, and not what kind of bug it is."""

    rule_id = "INPUT-001"
    title = "Potential input-handling weakness"

    def evaluate(self, context: RuleContext) -> Optional[Finding]:
        analysis = context.analysis
        if analysis.baseline_status_category != StatusCategory.SUCCESS:
            return None
        if analysis.mutation_status_category != StatusCategory.SERVER_ERROR:
            return None

        has_signature = any(a.type == AnomalyType.ERROR_SIGNATURE_DETECTED for a in analysis.anomalies)
        # A matched error signature (a traceback-like string, a SQL
        # error, etc.) is stronger, more specific evidence than "just a
        # 500" — bumps both severity and confidence one step.
        severity = Severity.MEDIUM if has_signature else Severity.LOW
        confidence = Confidence.MEDIUM if has_signature else Confidence.LOW

        details: dict[str, Any] = {"mutation_type": context.mutation.mutation_type.value}
        if has_signature:
            signature_anomaly = next(a for a in analysis.anomalies if a.type == AnomalyType.ERROR_SIGNATURE_DETECTED)
            details["matched_patterns"] = signature_anomaly.evidence.get("matched_patterns")

        return _build_finding(
            context,
            self.rule_id,
            self.title,
            f"A request that normally succeeds ({analysis.baseline_status}) returned a server error "
            f"({analysis.mutation_status}) after mutating {context.mutation.location}. This means the "
            f"input triggered unexpected server-side behavior — it does not by itself prove an "
            f"exploitable vulnerability or identify its type.",
            FindingCategory.INPUT_HANDLING,
            severity,
            confidence,
            details,
        )


# ---------------------------------------------------------------------------
# Rule B — AUTH-001
# ---------------------------------------------------------------------------


class AuthEnforcementRegressionRule(SecurityRule):
    """Baseline was auth-gated (401/403); this mutation's result
    succeeded instead. See this module's docstring for why this is
    reachable without header mutation, and why it won't fire against
    our own vulnerable-api's specific implementation."""

    rule_id = "AUTH-001"
    title = "Potential authentication enforcement weakness"

    def evaluate(self, context: RuleContext) -> Optional[Finding]:
        analysis = context.analysis
        if analysis.baseline_status not in (401, 403):
            return None
        if analysis.mutation_status_category != StatusCategory.SUCCESS:
            return None

        return _build_finding(
            context,
            self.rule_id,
            self.title,
            f"The baseline request was rejected with {analysis.baseline_status} (an authentication/"
            f"authorization-gated status), but mutating {context.mutation.location} produced a "
            f"successful response ({analysis.mutation_status}) instead. This does not prove an "
            f"authentication bypass — only that this specific mutation changed the outcome of a "
            f"request that was previously blocked.",
            FindingCategory.AUTHENTICATION,
            Severity.HIGH,
            Confidence.MEDIUM,
            {"baseline_status": analysis.baseline_status, "mutation_status": analysis.mutation_status},
        )


# ---------------------------------------------------------------------------
# Rule C — AUTHZ-001
# ---------------------------------------------------------------------------


class AuthorizationBoundaryRule(SecurityRule):
    """A path-parameter identifier was mutated (e.g. a resource ID) and
    the mutated request ALSO succeeded, just like the baseline. This is
    the classic shape of a cross-resource access pattern (IDOR/BOLA-
    style) — but the fuzzer has no way to independently verify whether
    the caller was actually authorized to access the mutated resource,
    so this is explicitly labeled a signal, never a confirmed finding."""

    rule_id = "AUTHZ-001"
    title = "Potential authorization boundary weakness"

    def evaluate(self, context: RuleContext) -> Optional[Finding]:
        analysis = context.analysis
        if not context.mutation.location.startswith("path."):
            return None
        if analysis.baseline_status_category != StatusCategory.SUCCESS:
            return None
        if analysis.mutation_status_category != StatusCategory.SUCCESS:
            return None
        if context.mutation.mutated_value == context.mutation.original_value:
            return None  # not actually a different identifier

        return _build_finding(
            context,
            self.rule_id,
            self.title,
            f"Changing the identifier at {context.mutation.location} from "
            f"{context.mutation.original_value!r} to {context.mutation.mutated_value!r} still returned "
            f"a successful response ({analysis.mutation_status}), the same as the baseline. This is "
            f"consistent with (but does not prove) missing per-resource authorization — the fuzzer "
            f"cannot determine whether the caller was legitimately permitted to access this identifier.",
            FindingCategory.AUTHORIZATION,
            Severity.HIGH,
            Confidence.LOW,
            {
                "original_identifier": context.mutation.original_value,
                "mutated_identifier": context.mutation.mutated_value,
            },
        )


# ---------------------------------------------------------------------------
# Rule D — DATA-001
# ---------------------------------------------------------------------------


class SensitiveDataExposureRule(SecurityRule):
    """A mutation caused NEW, sensitive-looking field names to appear
    in the response that weren't in the baseline. Name-based only — it
    cannot inspect actual field values (and never logs them), so a
    field like "password_reset_enabled" (a boolean flag, not a secret)
    will also match. That's a deliberate, documented false-positive
    tradeoff for a conservative, explainable rule over a "smarter" one
    that would need to guess at semantics."""

    rule_id = "DATA-001"
    title = "Potential sensitive-data exposure"

    def evaluate(self, context: RuleContext) -> Optional[Finding]:
        analysis = context.analysis
        structure_anomaly = next(
            (a for a in analysis.anomalies if a.type == AnomalyType.RESPONSE_STRUCTURE_CHANGED and "mutation_keys" in a.evidence),
            None,
        )
        if structure_anomaly is None:
            return None

        baseline_keys = set(structure_anomaly.evidence.get("baseline_keys") or [])
        mutation_keys = set(structure_anomaly.evidence.get("mutation_keys") or [])
        new_keys = mutation_keys - baseline_keys

        flagged = sorted(
            key for key in new_keys if any(marker in key.lower() for marker in SENSITIVE_FIELD_NAME_MARKERS)
        )
        if not flagged:
            return None

        return _build_finding(
            context,
            self.rule_id,
            self.title,
            f"Mutating {context.mutation.location} caused new field(s) with sensitive-looking names "
            f"to appear in the response that were not present in the baseline: {', '.join(flagged)}. "
            f"Field VALUES are never inspected or logged by this rule — only names.",
            FindingCategory.DATA_EXPOSURE,
            Severity.HIGH,
            Confidence.LOW,
            {"new_sensitive_field_names": flagged},
        )


# ---------------------------------------------------------------------------
# Rule E — BEHAVIOR-001
# ---------------------------------------------------------------------------


class BehaviorInconsistencyRule(SecurityRule):
    """A structurally-invalid value (null where a value was expected, a
    required field removed entirely, or a type-confused value) was
    silently accepted with a success response, where a validation
    rejection would normally be expected. This is a data-integrity /
    input-validation signal, not necessarily a security vulnerability
    on its own — but it's exactly the kind of gap that often sits
    upstream of a real one."""

    rule_id = "BEHAVIOR-001"
    title = "Potential input-validation inconsistency"

    def evaluate(self, context: RuleContext) -> Optional[Finding]:
        analysis = context.analysis
        if context.mutation.mutation_type not in STRUCTURALLY_INVALID_MUTATION_TYPES:
            return None
        if analysis.baseline_status_category != StatusCategory.SUCCESS:
            return None
        if analysis.mutation_status_category != StatusCategory.SUCCESS:
            return None

        return _build_finding(
            context,
            self.rule_id,
            self.title,
            f"A structurally invalid value ({context.mutation.mutation_type.value}) at "
            f"{context.mutation.location} was accepted with a successful response "
            f"({analysis.mutation_status}) rather than being rejected.",
            FindingCategory.BEHAVIOR_INCONSISTENCY,
            Severity.LOW,
            Confidence.MEDIUM,
            {"mutation_type": context.mutation.mutation_type.value},
        )
