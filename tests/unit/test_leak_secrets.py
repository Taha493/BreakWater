"""leak_secrets beyond the per-rule cases: entropy heuristic, overlap, roles, hidden secrets."""

from __future__ import annotations

import base64
import hashlib
import secrets

from gateway.config import DEFAULT_RULES_DIR
from gateway.core.context import ScanContext
from gateway.core.policy import SecretsSettings
from gateway.core.rules import load_rules
from gateway.core.verdict import AttackClass, Role
from gateway.detectors.leak_secrets import ENTROPY_RULE_ID, LeakSecrets, shannon_entropy

DETECTOR = LeakSecrets(load_rules(DEFAULT_RULES_DIR / "secrets.yaml"), SecretsSettings())


def rule_ids(text: str) -> list[str]:
    return [f.rule_id or "" for f in DETECTOR.hits(ScanContext.for_text(text).views)]


def test_roles_include_prompts_and_tool_results() -> None:
    assert DETECTOR.roles == {Role.ASSISTANT, Role.TOOL_RESULT, Role.USER}


async def test_finding_shape() -> None:
    text = "key: sk-" + "p" * 40
    (finding,) = await DETECTOR.scan(text, Role.ASSISTANT, ScanContext.for_text(text))
    assert finding.attack_class is AttackClass.A3
    assert finding.span == (5, len(text))
    assert finding.score >= 0.9


def test_random_token_flagged_by_entropy_at_low_score() -> None:
    token = secrets.token_urlsafe(32) + "9a"
    findings = DETECTOR.hits(ScanContext.for_text(f"value {token}").views)
    assert [f.rule_id for f in findings] == [ENTROPY_RULE_ID]
    assert findings[0].score < 0.7  # logged, not acted on


def test_hashes_and_words_not_flagged_by_entropy() -> None:
    sha = hashlib.sha256(b"x").hexdigest()  # hex tops out at 4 bits/char
    assert rule_ids(f"commit {sha}") == []
    assert rule_ids("internationalization_and_localization_guidelines") == []
    assert rule_ids("12345678901234567890123456789012345") == []


def test_specific_rule_wins_over_entropy() -> None:
    assert rule_ids("token ghp_" + secrets.token_hex(20)) == ["secret-github-token"]


def test_secret_hidden_in_base64_is_found() -> None:
    hidden = base64.b64encode(("the key is sk-" + "p" * 40).encode()).decode()
    assert "secret-api-key" in rule_ids(f"blob {hidden}")


def test_entropy_function() -> None:
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
