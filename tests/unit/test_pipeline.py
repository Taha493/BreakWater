from __future__ import annotations

import asyncio
import time
from typing import ClassVar

import yaml

from breakwater.config import DEFAULT_POLICIES_PATH
from breakwater.core.context import CallContext, ScanContext
from breakwater.core.pipeline import Pipeline, allowed, merge
from breakwater.core.policy import DETECTOR_ERROR_RULE_ID, SCAN_LIMIT_RULE_ID, parse_policy
from breakwater.core.verdict import Action, AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector

CALL = CallContext()


def make_detector(
    name: str,
    layer: int,
    score: float | None,
    delay: float = 0.0,
    roles: set[Role] | None = None,
    fail: bool = False,
) -> Detector:
    class Stub(Detector):
        calls = 0
        seen_views: ClassVar[list[str]] = []

        async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
            type(self).calls += 1
            type(self).seen_views = [v.kind for v in context.views.all]
            await asyncio.sleep(delay)
            if fail:
                raise RuntimeError("boom")
            if score is None:
                return []
            return [
                Finding(
                    detector=name,
                    attack_class=AttackClass.A1,
                    severity=Severity.HIGH,
                    score=score,
                    reason="stub",
                    span=(0, 1),
                    layer=layer,
                )
            ]

    Stub.name = name
    Stub.layer = layer
    Stub.roles = frozenset(roles or {Role.USER, Role.ASSISTANT})
    return Stub()


def pipeline(*detectors: Detector, **policy_changes: object) -> Pipeline:
    data = yaml.safe_load(DEFAULT_POLICIES_PATH.read_bytes())
    data.update(policy_changes)
    return Pipeline(detectors, parse_policy(yaml.safe_dump(data).encode()))


async def test_no_findings_allows() -> None:
    inspection = await pipeline(make_detector("a", 1, None)).inspect("hello", Role.USER, CALL, "r1")
    verdict = inspection.verdict
    assert (verdict.action, verdict.risk_score, verdict.findings) == (Action.ALLOW, 0.0, [])
    assert verdict.request_id == "r1"
    assert inspection.redactions == ()


async def test_findings_merge_and_block() -> None:
    p = pipeline(make_detector("a", 1, 0.4), make_detector("b", 2, 0.75))
    verdict = (await p.inspect("x", Role.USER, CALL, "r1")).verdict
    assert verdict.action is Action.BLOCK
    assert verdict.risk_score == 0.75
    assert [f.detector for f in verdict.findings] == ["a", "b"]


async def test_certain_finding_skips_later_layers() -> None:
    layer2 = make_detector("later", 2, 0.1)
    verdict = (
        await pipeline(make_detector("rules", 1, 0.95), layer2).inspect("x", Role.USER, CALL, "r")
    ).verdict
    assert type(layer2).calls == 0  # type: ignore[attr-defined]
    assert [f.detector for f in verdict.findings] == ["rules"]


async def test_role_filter() -> None:
    assistant_only = make_detector("leak", 1, 0.99, roles={Role.ASSISTANT})
    verdict = (await pipeline(assistant_only).inspect("x", Role.USER, CALL, "r1")).verdict
    assert verdict.action is Action.ALLOW
    assert type(assistant_only).calls == 0  # type: ignore[attr-defined]


async def test_same_layer_runs_concurrently() -> None:
    p = pipeline(*(make_detector(f"d{i}", 1, None, delay=0.2) for i in range(3)))
    started = time.perf_counter()
    await p.inspect("x", Role.USER, CALL, "r1")
    assert time.perf_counter() - started < 0.45


async def test_detectors_receive_layer0_views() -> None:
    d = make_detector("a", 1, None)
    await pipeline(d).inspect("ig​nore", Role.USER, CALL, "r1")
    assert type(d).seen_views == ["original", "normalized"]  # type: ignore[attr-defined]


async def test_message_index_is_attached() -> None:
    inspection = await pipeline(make_detector("a", 1, 0.9)).inspect(
        "x", Role.USER, CALL, "r1", message_index=3
    )
    assert inspection.verdict.findings[0].message_index == 3


async def test_detector_error_fails_closed_on_both_sides() -> None:
    p = pipeline(make_detector("broken", 1, None, fail=True))
    for role in (Role.USER, Role.ASSISTANT):
        verdict = (await p.inspect("x", role, CALL, "r1")).verdict
        assert verdict.action is Action.BLOCK
        assert verdict.findings[0].rule_id == DETECTOR_ERROR_RULE_ID
        assert verdict.findings[0].detector == "broken"


async def test_detector_error_can_allow_and_log() -> None:
    p = pipeline(
        make_detector("broken", 1, None, fail=True),
        failure_mode={
            "request_inspection_error": "allow_and_log",
            "response_inspection_error": "allow_and_log",
        },
    )
    assert (await p.inspect("x", Role.USER, CALL, "r1")).verdict.action is Action.ALLOW


async def test_scan_limit_blocks_or_truncates() -> None:
    d = make_detector("a", 1, None)
    blocked = await pipeline(d, limits={"max_scan_chars": 10}).inspect(
        "x" * 11, Role.USER, CALL, "r"
    )
    assert blocked.verdict.action is Action.BLOCK
    assert blocked.verdict.findings[0].rule_id == SCAN_LIMIT_RULE_ID

    truncated = await pipeline(d, limits={"max_scan_chars": 10, "over_limit": "truncate"}).inspect(
        "x" * 11, Role.USER, CALL, "r"
    )
    assert truncated.verdict.action is Action.ALLOW


async def test_merge() -> None:
    p = pipeline(make_detector("a", 1, 0.9))
    one = await p.inspect("x", Role.USER, CALL, "r", message_index=0)
    merged = merge("r", [allowed("r"), one])
    assert merged.verdict.action is Action.BLOCK
    assert merged.verdict.risk_score == 0.9
    assert len(merged.verdict.findings) == 1


async def test_max_layer_skips_higher_layers() -> None:
    rules, classifier = make_detector("rules", 1, 0.2), make_detector("classifier", 2, 0.8)
    p = pipeline(rules, classifier)
    assert p.layers == (1, 2)
    capped = (await p.inspect("x", Role.USER, CallContext(max_layer=1), "r")).verdict
    assert [f.detector for f in capped.findings] == ["rules"] and capped.action is Action.ALLOW
    assert type(classifier).calls == 0  # type: ignore[attr-defined]
    full = (await p.inspect("x", Role.USER, CALL, "r")).verdict
    assert [f.detector for f in full.findings] == ["rules", "classifier"]
    assert full.action is Action.BLOCK
