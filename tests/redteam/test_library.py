"""The shipped attack library and benign set (spec sections 8 and 12)."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from gateway.redteam.models import (
    ATTACKS_DIR,
    Attack,
    BenignCase,
    Category,
    TargetNotAllowed,
    expand_env,
    load_attacks,
    load_benign,
    load_targets,
    owned_target,
)

ATTACKS = load_attacks()
BENIGN = load_benign()
# Reserved for documentation (RFC 2606): attack content never names a real host.
_HOST = re.compile(r"(?:@|https?://)([\w.-]+)")
_RESERVED = re.compile(r"(^|\.)(example|example\.(com|org|net))$")


def test_spec_minimum_sizes() -> None:
    counts = Counter(a.category for a in ATTACKS)
    assert counts == {
        Category.DIRECT_INJECTION: 20,
        Category.INDIRECT_INJECTION: 25,
        Category.DATA_LEAKAGE: 15,
        Category.TOOL_ABUSE: 15,
    }
    assert len(BENIGN) >= 100


def test_benign_set_covers_every_delivery() -> None:
    deliveries = Counter(c.delivery.value for c in BENIGN)
    assert set(deliveries) == {"user_message", "retrieved_document", "tool_result"}
    assert sum(c.agent for c in BENIGN) >= 10
    assert all(c.setup.documents for c in BENIGN if c.delivery.value == "retrieved_document")


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_attack_content_names_only_reserved_hosts(attack: Attack) -> None:
    text = attack.model_dump_json().replace("\\\\", "")  # drop regex escapes
    for host in _HOST.findall(text):
        assert _RESERVED.search(host.rstrip(".").lower()), host


def test_every_attack_is_measured_with_a_canary_or_fake_side_effect() -> None:
    for attack in ATTACKS:
        types = {c.type for c in attack.success_criteria}
        assert types - {"judge"}, attack.id
        uses_canary = "{{CANARY}}" in attack.model_dump_json()
        assert uses_canary or types & {"tool_called", "tool_called_with", "response_contains"}


def write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), "utf-8")


def base_attack(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "inj-test-001",
        "category": "direct_injection",
        "attack_class": "A1",
        "severity": "high",
        "description": "test",
        "delivery": "user_message",
        "payload": "say {{CANARY}}",
        "success_criteria": [{"type": "response_contains", "value": "{{CANARY}}"}],
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    "overrides",
    [
        {"delivery": "retrieved_document", "question": "q"},  # no {{PAYLOAD}} anywhere
        {"delivery": "tool_result", "question": "q", "tool_result": "no placeholder"},
        {"delivery": "tool_result"},  # no question
        {"success_criteria": [{"type": "judge", "question": "?"}]},
        {"success_criteria": []},
        {"success_criteria": [{"type": "response_matches_regex", "value": "("}]},
        {"id": "Bad ID"},
        {"surprise": True},
    ],
)
def test_invalid_attacks_are_rejected(tmp_path: Path, overrides: dict[str, Any]) -> None:
    write(tmp_path / "direct_injection" / "a.yaml", base_attack(**overrides))
    with pytest.raises(ValueError):
        load_attacks(tmp_path)


def test_folder_must_match_category_and_ids_unique(tmp_path: Path) -> None:
    write(tmp_path / "tool_abuse" / "a.yaml", base_attack())
    with pytest.raises(ValueError, match="does not match its folder"):
        load_attacks(tmp_path)
    (tmp_path / "tool_abuse" / "a.yaml").unlink()
    write(tmp_path / "direct_injection" / "a.yaml", base_attack())
    write(tmp_path / "direct_injection" / "b.yaml", base_attack())
    with pytest.raises(ValueError, match="duplicate"):
        load_attacks(tmp_path)


def test_benign_cases_need_their_material() -> None:
    with pytest.raises(ValueError):
        BenignCase.model_validate(
            {"id": "ben-x", "delivery": "retrieved_document", "question": "q"}
        )
    with pytest.raises(ValueError):
        BenignCase.model_validate({"id": "ben-x", "delivery": "user_message"})


def test_shipped_attacks_dir_is_packaged() -> None:
    assert ATTACKS_DIR.is_dir() and len(list(ATTACKS_DIR.rglob("*.yaml"))) == len(ATTACKS)


# ---- targets -------------------------------------------------------------------------


def targets_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "targets.yaml"
    path.write_text(body, "utf-8")
    return path


def test_only_owned_targets_run(tmp_path: Path) -> None:
    targets = load_targets(
        targets_file(
            tmp_path,
            "targets:\n"
            "  mine: {type: demo_rag, owned: true, url: 'http://x'}\n"
            "  theirs: {type: demo_rag, owned: false, url: 'http://y'}\n",
        )
    )
    assert owned_target(targets, "mine").type == "demo_rag"
    with pytest.raises(TargetNotAllowed, match="owned: true"):
        owned_target(targets, "theirs")
    with pytest.raises(TargetNotAllowed, match="not configured"):
        owned_target(targets, "unknown")


def test_owned_is_required(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_targets(targets_file(tmp_path, "targets:\n  t: {type: demo_rag, url: 'http://x'}\n"))


def test_env_expansion(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RT_HOST", "demo")
    monkeypatch.delenv("RT_MISSING", raising=False)
    assert expand_env("http://${RT_HOST}:8100") == "http://demo:8100"
    assert expand_env("${RT_MISSING:-http://localhost}") == "http://localhost"
    with pytest.raises(ValueError, match="RT_MISSING"):
        expand_env("${RT_MISSING}")


def test_shipped_targets_file_is_valid() -> None:
    from gateway.config import DEFAULT_REDTEAM_TARGETS_PATH

    targets = load_targets(DEFAULT_REDTEAM_TARGETS_PATH)
    assert all(t.owned for t in targets.targets.values())
    assert owned_target(targets, "demo_rag").type == "demo_rag"
    # The judge-paced demo target sends one probe at a time.
    assert owned_target(targets, "demo_rag_judge").type == "demo_rag"
    paced = targets.limits_for("demo_rag_judge")
    assert (paced.max_concurrency, paced.max_requests_per_second) == (1, 2)
