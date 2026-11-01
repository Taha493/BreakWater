from __future__ import annotations

import pytest
from pydantic import ValidationError

from gateway.core.verdict import Action, AttackClass, Finding, Severity, Verdict


def _finding(**overrides: object) -> Finding:
    values: dict[str, object] = {
        "detector": "injection_rules",
        "attack_class": AttackClass.A1,
        "severity": Severity.HIGH,
        "score": 0.8,
        "reason": "Matched instruction-override pattern",
        "rule_id": "inj-001",
        "span": (12, 48),
        "layer": 1,
    }
    values.update(overrides)
    return Finding.model_validate(values)


def test_verdict_json_matches_spec_shape() -> None:
    verdict = Verdict(
        request_id="r1", action=Action.BLOCK, risk_score=0.8, findings=[_finding()], latency_ms=1.5
    )
    data = verdict.model_dump(mode="json")
    assert set(data) == {
        "request_id",
        "action",
        "risk_score",
        "findings",
        "latency_ms",
        "judge_used",
    }
    assert data["action"] == "block"
    assert data["judge_used"] is False
    finding = data["findings"][0]
    assert set(finding) == {
        "detector",
        "attack_class",
        "severity",
        "score",
        "reason",
        "rule_id",
        "span",
        "layer",
    }
    assert finding["span"] == [12, 48]
    assert finding["attack_class"] == "A1"
    assert finding["severity"] == "high"


@pytest.mark.parametrize("score", [-0.1, 1.1])
def test_finding_score_bounded(score: float) -> None:
    with pytest.raises(ValidationError):
        _finding(score=score)


def test_unknown_enum_rejected() -> None:
    with pytest.raises(ValidationError):
        _finding(attack_class="A9")


def test_finding_is_immutable() -> None:
    with pytest.raises(ValidationError):
        _finding().score = 0.1  # type: ignore[misc]
