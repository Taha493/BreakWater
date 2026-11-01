from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from gateway.config import DEFAULT_POLICIES_PATH
from gateway.core.policy import load_policy
from gateway.core.verdict import Action, AttackClass, Finding, Role, Severity


def _finding(score: float) -> Finding:
    return Finding(
        detector="stub",
        attack_class=AttackClass.A1,
        severity=Severity.HIGH,
        score=score,
        reason="test",
        layer=1,
    )


def test_default_policy_loads_with_spec_thresholds() -> None:
    policy = load_policy(DEFAULT_POLICIES_PATH)
    t = policy.config.thresholds
    assert (t.allow_below, t.judge_band, t.block_at) == (0.30, (0.30, 0.70), 0.70)
    assert policy.config.actions["A1"] == {"user": "block"}
    assert len(policy.version) == 12


def test_version_tracks_file_content(tmp_path: Path) -> None:
    copy = tmp_path / "p.yaml"
    copy.write_bytes(DEFAULT_POLICIES_PATH.read_bytes())
    assert load_policy(copy).version == load_policy(DEFAULT_POLICIES_PATH).version
    copy.write_text(DEFAULT_POLICIES_PATH.read_text().replace("block_at: 0.70", "block_at: 0.80"))
    assert load_policy(copy).version != load_policy(DEFAULT_POLICIES_PATH).version


def test_thresholds_must_be_ordered(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("thresholds: {allow_below: 0.8, judge_band: [0.3, 0.7], block_at: 0.7}\n")
    with pytest.raises(ValidationError, match="allow_below"):
        load_policy(bad)


def test_unknown_keys_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text(
        "thresholds: {allow_below: 0.3, judge_band: [0.3, 0.7], block_at: 0.7}\ntypo: 1\n"
    )
    with pytest.raises(ValidationError):
        load_policy(bad)


def test_non_mapping_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("- a\n- b\n")
    with pytest.raises(ValueError, match="mapping"):
        load_policy(bad)


@pytest.mark.parametrize(
    ("scores", "role", "expected"),
    [
        ([], Role.USER, Action.ALLOW),
        ([0.2, 0.5], Role.USER, Action.ALLOW),
        ([0.2, 0.7], Role.USER, Action.BLOCK),
        ([0.95], Role.ASSISTANT, Action.BLOCK),
        ([0.9], Role.RETRIEVED, Action.QUARANTINE),
    ],
)
def test_decide(scores: list[float], role: Role, expected: Action) -> None:
    policy = load_policy(DEFAULT_POLICIES_PATH)
    action, risk = policy.decide([_finding(s) for s in scores], role)
    assert action is expected
    assert risk == max(scores, default=0.0)
