"""Runs detectors in layers, cheapest first, and merges their findings into a Verdict."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import groupby

from breakwater.core.context import CallContext, ScanContext
from breakwater.core.normalize import build_views
from breakwater.core.policy import (
    DETECTOR_ERROR_RULE_ID,
    SCAN_LIMIT_RULE_ID,
    Policy,
    Redaction,
    most_severe,
)
from breakwater.core.verdict import Action, AttackClass, Finding, Role, Severity, Verdict
from breakwater.detectors.base import Detector
from breakwater.detectors.judge import JUDGE_LAYER, Judge

log = logging.getLogger("gateway.pipeline")

# A finding at or above this score is certain enough to skip the costlier later layers.
SKIP_LATER_LAYERS_AT = 0.9
# Layers: 1 rules, 2 classifier, 3 judge (layer 0, normalization, always runs).
MAX_LAYER = 3

# Attack class used for gateway-generated findings (errors, limits), by role inspected.
_CLASS_FOR_ROLE = {
    Role.USER: AttackClass.A1,
    Role.SYSTEM: AttackClass.A1,
    Role.RETRIEVED: AttackClass.A2,
    Role.TOOL_RESULT: AttackClass.A2,
    Role.ASSISTANT: AttackClass.A3,
}


@dataclass(frozen=True)
class Inspection:
    """A verdict plus the spans the policy wants redacted (internal, never sent to clients)."""

    verdict: Verdict
    redactions: tuple[Redaction, ...]


def _gateway_finding(detector: str, role: Role, rule_id: str, reason: str) -> Finding:
    return Finding(
        detector=detector,
        attack_class=_CLASS_FOR_ROLE[role],
        severity=Severity.HIGH,
        score=1.0,
        reason=reason,
        rule_id=rule_id,
        layer=0,
    )


class Pipeline:
    def __init__(
        self, detectors: Sequence[Detector], policy: Policy, judge: Judge | None = None
    ) -> None:
        ordered = sorted(detectors, key=lambda d: d.layer)
        self._layers = [
            (layer, list(group)) for layer, group in groupby(ordered, key=lambda d: d.layer)
        ]
        self.policy = policy
        self.judge = judge

    @property
    def detectors(self) -> list[Detector]:
        return [d for _, layer in self._layers for d in layer]

    @property
    def layers(self) -> tuple[int, ...]:
        """The detection layers this pipeline runs (layer 0, normalization, always runs)."""
        layers = tuple(layer for layer, _ in self._layers)
        return (*layers, JUDGE_LAYER) if self._judge_on() else layers

    def _judge_on(self) -> bool:
        settings = self.policy.config.judge
        return self.judge is not None and settings.enabled and settings.max_calls_per_minute > 0

    async def inspect(
        self,
        text: str,
        role: Role,
        call: CallContext,
        request_id: str,
        message_index: int | None = None,
        only: frozenset[str] | None = None,
    ) -> Inspection:
        """``only`` restricts the scan to the named detectors (and skips the judge)."""
        started = time.perf_counter()
        findings, judge_used = await self._findings(text, role, call, only)
        if message_index is not None:
            findings = [f.model_copy(update={"message_index": message_index}) for f in findings]
        decision = self.policy.decide(findings, role)
        verdict = Verdict(
            request_id=request_id,
            action=decision.action,
            risk_score=decision.risk_score,
            findings=findings,
            latency_ms=(time.perf_counter() - started) * 1000,
            judge_used=judge_used,
        )
        return Inspection(verdict, decision.redactions)

    async def _findings(
        self, text: str, role: Role, call: CallContext, only: frozenset[str] | None = None
    ) -> tuple[list[Finding], bool]:
        """Findings from every layer that ran, and whether the judge was asked."""
        limits = self.policy.config.limits
        if len(text) > limits.max_scan_chars:
            if limits.over_limit == "block":
                finding = _gateway_finding(
                    "pipeline",
                    role,
                    SCAN_LIMIT_RULE_ID,
                    f"Text exceeds the {limits.max_scan_chars}-character scan limit",
                )
                return [finding], False
            text = text[: limits.max_scan_chars]

        context = ScanContext(views=build_views(text), call=call)
        findings: list[Finding] = []
        for number, layer in self._layers:
            if call.max_layer is not None and number > call.max_layer:
                break
            active = [d for d in layer if d.applies_to(role) and (only is None or d.name in only)]
            results = await asyncio.gather(
                *(d.scan(text, role, context) for d in active), return_exceptions=True
            )
            for detector, result in zip(active, results, strict=True):
                if isinstance(result, BaseException):
                    findings.extend(self._on_error(detector, role, result))
                else:
                    findings.extend(result)
            if any(self.policy.weighted_score(f) >= SKIP_LATER_LAYERS_AT for f in findings):
                return findings, False
        if only is not None or not self._should_judge(role, call, findings) or self.judge is None:
            return findings, False
        config = self.policy.config
        findings += await self.judge.review(
            text,
            role,
            findings,
            self.policy.risk_score(findings),
            config.judge,
            config.failure_mode,
        )
        return findings, True

    def _should_judge(self, role: Role, call: CallContext, findings: list[Finding]) -> bool:
        """Borderline text only: its score from layers 1-2 is in the judge band."""
        if self.judge is None or not self._judge_on() or not self.judge.applies_to(role):
            return False
        if call.max_layer is not None and call.max_layer < JUDGE_LAYER:
            return False
        low, high = self.policy.config.thresholds.judge_band
        return low <= self.policy.risk_score(findings) < high

    def _on_error(self, detector: Detector, role: Role, error: BaseException) -> list[Finding]:
        log.error(
            "detector failed",
            exc_info=error,
            extra={"detector": detector.name, "role": role.value},
        )
        modes = self.policy.config.failure_mode
        if detector.failure_mode is not None:
            mode = getattr(modes, detector.failure_mode)
        elif role is Role.ASSISTANT:
            mode = modes.response_inspection_error
        else:
            mode = modes.request_inspection_error
        if mode == "allow_and_log":
            return []
        return [
            _gateway_finding(
                detector.name, role, DETECTOR_ERROR_RULE_ID, "Detector failed; failing closed"
            )
        ]


def merge(request_id: str, inspections: Sequence[Inspection]) -> Inspection:
    """Combine inspections of several messages into one verdict for the call."""
    findings = [f for i in inspections for f in i.verdict.findings]
    return Inspection(
        Verdict(
            request_id=request_id,
            action=most_severe([i.verdict.action for i in inspections]),
            risk_score=max((i.verdict.risk_score for i in inspections), default=0.0),
            findings=findings,
            latency_ms=max((i.verdict.latency_ms for i in inspections), default=0.0),
            judge_used=any(i.verdict.judge_used for i in inspections),
        ),
        tuple(r for i in inspections for r in i.redactions),
    )


def allowed(request_id: str) -> Inspection:
    return Inspection(
        Verdict(request_id=request_id, action=Action.ALLOW, risk_score=0.0, latency_ms=0.0), ()
    )
