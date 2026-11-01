"""Runs detectors in layers, cheapest first, and merges their findings into a Verdict."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from itertools import groupby

from gateway.core.policy import Policy
from gateway.core.verdict import Finding, Role, ScanContext, Verdict
from gateway.detectors.base import Detector

# A finding at or above this score is certain enough to skip the costlier later layers.
SKIP_LATER_LAYERS_AT = 0.9


class Pipeline:
    def __init__(self, detectors: Sequence[Detector], policy: Policy) -> None:
        ordered = sorted(detectors, key=lambda d: d.layer)
        self._layers = [list(group) for _, group in groupby(ordered, key=lambda d: d.layer)]
        self.policy = policy

    async def inspect(
        self, text: str, role: Role, context: ScanContext, request_id: str
    ) -> Verdict:
        started = time.perf_counter()
        findings: list[Finding] = []
        for layer in self._layers:
            active = [d for d in layer if d.applies_to(role)]
            results = await asyncio.gather(*(d.scan(text, role, context) for d in active))
            for result in results:
                findings.extend(result)
            if any(f.score >= SKIP_LATER_LAYERS_AT for f in findings):
                break
        action, risk = self.policy.decide(findings, role)
        return Verdict(
            request_id=request_id,
            action=action,
            risk_score=risk,
            findings=findings,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
