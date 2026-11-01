from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from breakwater.config import DEFAULT_POLICIES_PATH
from breakwater.core.policy import CANARY_RULE_ID, Policy, Redaction, parse_policy
from breakwater.core.verdict import Action, AttackClass, Finding, Role, Severity

DEFAULT = DEFAULT_POLICIES_PATH.read_bytes()


def policy(**changes: object) -> Policy:
    data = yaml.safe_load(DEFAULT)
    data.update(changes)
    return parse_policy(yaml.safe_dump(data).encode())


def finding(
    score: float,
    attack_class: AttackClass = AttackClass.A1,
    detector: str = "injection_rules",
    rule_id: str = "r1",
    span: tuple[int, int] | None = (0, 4),
    message_index: int | None = None,
) -> Finding:
    return Finding(
        detector=detector,
        attack_class=attack_class,
        severity=Severity.HIGH,
        score=score,
        reason="test",
        rule_id=rule_id,
        span=span,
        layer=1,
        message_index=message_index,
    )


def test_default_policy_matches_spec() -> None:
    config = parse_policy(DEFAULT).config
    t = config.thresholds
    assert (t.allow_below, t.judge_band, t.block_at) == (0.30, (0.30, 0.70), 0.70)
    assert config.actions[AttackClass.A1] == {"user": "block"}
    assert config.actions[AttackClass.A3] == {"assistant": "redact", "secrets": "block"}
    assert config.failure_mode.response_inspection_error == "block"
    assert config.canary.enabled is False


@pytest.mark.parametrize(
    ("findings", "role", "expected"),
    [
        ([], Role.USER, Action.ALLOW),
        ([finding(0.2)], Role.USER, Action.ALLOW),
        ([finding(0.5)], Role.USER, Action.ALLOW),  # judge band, no judge yet: allow and log
        ([finding(0.7)], Role.USER, Action.BLOCK),
        ([finding(0.9, AttackClass.A2)], Role.RETRIEVED, Action.QUARANTINE),
        ([finding(0.9, AttackClass.A2)], Role.TOOL_RESULT, Action.REDACT),  # strip_and_log
        ([finding(0.9, AttackClass.A3, "leak_pii")], Role.ASSISTANT, Action.REDACT),
        ([finding(0.9, AttackClass.A3, "leak_secrets")], Role.ASSISTANT, Action.REDACT),
        ([finding(0.9, AttackClass.A3, "leak_secrets")], Role.USER, Action.BLOCK),
        ([finding(0.9, AttackClass.A3, "leak_secrets")], Role.TOOL_RESULT, Action.BLOCK),
        ([finding(0.9, AttackClass.A1)], Role.ASSISTANT, Action.BLOCK),  # unconfigured: fail safe
    ],
)
def test_decide(findings: list[Finding], role: Role, expected: Action) -> None:
    assert parse_policy(DEFAULT).decide(findings, role).action is expected


def test_most_severe_action_wins() -> None:
    p = parse_policy(DEFAULT)
    findings = [finding(0.9, AttackClass.A3, "leak_pii"), finding(0.9, AttackClass.A1)]
    assert p.decide(findings, Role.ASSISTANT).action is Action.BLOCK


def test_canary_always_blocks() -> None:
    p = policy(weights={"leak_system_prompt": 0.0})
    canary = finding(1.0, AttackClass.A3, "leak_system_prompt", rule_id=CANARY_RULE_ID)
    assert p.decide([canary], Role.ASSISTANT).action is Action.BLOCK


def test_weights_scale_scores() -> None:
    p = policy(weights={"injection_rules": 0.5})
    decision = p.decide([finding(0.9)], Role.USER)
    assert decision.action is Action.ALLOW
    assert decision.risk_score == pytest.approx(0.45)
    assert policy(weights={"injection_rules": 2.0}).risk_score([finding(0.9)]) == 1.0


def test_redactions_carry_spans_and_message_index() -> None:
    p = parse_policy(DEFAULT)
    pii = finding(
        0.9, AttackClass.A3, "leak_pii", rule_id="pii-email", span=(5, 9), message_index=2
    )
    decision = p.decide([pii, finding(0.5, AttackClass.A3, "leak_pii")], Role.ASSISTANT)
    assert decision.redactions == (Redaction((5, 9), "pii-email", 2),)


def test_strip_and_log_redacts_whole_message() -> None:
    p = parse_policy(DEFAULT)
    decision = p.decide([finding(0.9, AttackClass.A2, span=(3, 8))], Role.TOOL_RESULT)
    assert decision.redactions == (Redaction(None, "r1", None),)


def test_action_can_be_set_to_allow() -> None:
    p = policy(actions={"A1": {"user": "allow"}})
    assert p.decide([finding(0.95)], Role.USER).action is Action.ALLOW


@pytest.mark.parametrize(
    "changes",
    [
        {"thresholds": {"allow_below": 0.8, "judge_band": [0.3, 0.7], "block_at": 0.7}},
        {"actions": {"A1": {"user": "explode"}}},
        {"actions": {"A9": {"user": "block"}}},
        {"weights": {"injection_rules": -1}},
        {"limits": {"max_scan_chars": 0}},
        {"failure_mode": {"response_inspection_error": "maybe"}},
        {"typo": 1},
    ],
)
def test_invalid_policy_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        policy(**changes)


def test_non_mapping_rejected() -> None:
    with pytest.raises(ValueError, match="mapping"):
        parse_policy(b"- a\n- b\n")
