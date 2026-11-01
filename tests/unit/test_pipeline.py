from __future__ import annotations

import asyncio
import time

from gateway.config import DEFAULT_POLICIES_PATH
from gateway.core.pipeline import Pipeline
from gateway.core.policy import load_policy
from gateway.core.verdict import Action, AttackClass, Finding, Role, ScanContext, Severity
from gateway.detectors.base import Detector


def make_detector(
    name: str, layer: int, score: float | None, delay: float = 0.0, roles: set[Role] | None = None
) -> Detector:
    class Stub(Detector):
        calls = 0

        async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
            type(self).calls += 1
            await asyncio.sleep(delay)
            if score is None:
                return []
            return [
                Finding(
                    detector=name,
                    attack_class=AttackClass.A1,
                    severity=Severity.HIGH,
                    score=score,
                    reason="stub",
                    layer=layer,
                )
            ]

    Stub.name = name
    Stub.layer = layer
    Stub.roles = frozenset(roles or {Role.USER})
    return Stub()


def pipeline(*detectors: Detector) -> Pipeline:
    return Pipeline(detectors, load_policy(DEFAULT_POLICIES_PATH))


async def test_no_detectors_allows() -> None:
    verdict = await pipeline().inspect("hello", Role.USER, {}, "r1")
    assert verdict.action is Action.ALLOW
    assert verdict.risk_score == 0.0
    assert verdict.findings == []
    assert verdict.request_id == "r1"
    assert verdict.latency_ms >= 0


async def test_findings_merge_and_block() -> None:
    verdict = await pipeline(make_detector("a", 1, 0.4), make_detector("b", 2, 0.75)).inspect(
        "x", Role.USER, {}, "r1"
    )
    assert verdict.action is Action.BLOCK
    assert verdict.risk_score == 0.75
    assert [f.detector for f in verdict.findings] == ["a", "b"]


async def test_certain_finding_skips_later_layers() -> None:
    layer2 = make_detector("later", 2, 0.1)
    verdict = await pipeline(make_detector("rules", 1, 0.95), layer2).inspect(
        "x", Role.USER, {}, "r1"
    )
    assert type(layer2).calls == 0  # type: ignore[attr-defined]
    assert [f.detector for f in verdict.findings] == ["rules"]


async def test_role_filter() -> None:
    assistant_only = make_detector("leak", 1, 0.99, roles={Role.ASSISTANT})
    verdict = await pipeline(assistant_only).inspect("x", Role.USER, {}, "r1")
    assert verdict.action is Action.ALLOW
    assert type(assistant_only).calls == 0  # type: ignore[attr-defined]


async def test_same_layer_runs_concurrently() -> None:
    p = pipeline(*(make_detector(f"d{i}", 1, None, delay=0.2) for i in range(3)))
    started = time.perf_counter()
    await p.inspect("x", Role.USER, {}, "r1")
    assert time.perf_counter() - started < 0.45
