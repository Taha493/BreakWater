"""Rule loading, RE2 safety, and the per-rule positive/negative examples (spec section 6)."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from breakwater.config import DEFAULT_RULES_DIR
from breakwater.core.context import ScanContext
from breakwater.core.policy import SecretsSettings
from breakwater.core.rules import RuleError, load_rules, parse_rules
from breakwater.core.verdict import Role
from breakwater.detectors.injection_rules import InjectionRules
from breakwater.detectors.leak_secrets import LeakSecrets

CASES: dict[str, dict[str, dict[str, list[str]]]] = yaml.safe_load(
    (Path(__file__).parent / "rule_cases.yaml").read_text()
)
INJECTION = load_rules(DEFAULT_RULES_DIR / "injection.yaml")
SECRETS = load_rules(DEFAULT_RULES_DIR / "secrets.yaml")
_REPEAT = re.compile(r"\{repeat:(.):(\d+)\}")


def expand(text: str) -> str:
    return _REPEAT.sub(lambda m: m.group(1) * int(m.group(2)), text)


def _cases(group: str) -> list[tuple[str, str, bool]]:
    return [
        (rule_id, expand(text), expected)
        for rule_id, examples in CASES[group].items()
        for expected, key in ((True, "positive"), (False, "negative"))
        for text in examples[key]
    ]


async def _injection_rule_ids(text: str) -> set[str]:
    findings = await InjectionRules(INJECTION).scan(text, Role.USER, ScanContext.for_text(text))
    return {f.rule_id for f in findings if f.rule_id}


def _secret_rule_ids(text: str) -> set[str]:
    findings = LeakSecrets(SECRETS, SecretsSettings()).hits(ScanContext.for_text(text).views)
    return {f.rule_id for f in findings if f.rule_id}


@pytest.mark.parametrize(("group", "rules"), [("injection", INJECTION), ("secrets", SECRETS)])
def test_every_rule_has_examples(group: str, rules: Any) -> None:
    ids = {r.id for r in rules}
    assert ids == set(CASES[group]), "rule_cases.yaml must list exactly the rules in the file"
    for rule_id, examples in CASES[group].items():
        assert len(examples["positive"]) >= 2, rule_id
        assert len(examples["negative"]) >= 2, rule_id


@pytest.mark.parametrize(("rule_id", "text", "expected"), _cases("injection"))
async def test_injection_rule_cases(rule_id: str, text: str, expected: bool) -> None:
    assert (rule_id in await _injection_rule_ids(text)) is expected


@pytest.mark.parametrize(("rule_id", "text", "expected"), _cases("secrets"))
def test_secret_rule_cases(rule_id: str, text: str, expected: bool) -> None:
    assert (rule_id in _secret_rule_ids(text)) is expected


def test_every_rule_has_required_fields() -> None:
    for rule in (*INJECTION, *SECRETS):
        assert rule.spec.description
        assert 0 < rule.spec.score <= 1


def _rule(**overrides: object) -> bytes:
    rule = {
        "id": "test-rule",
        "description": "test",
        "attack_class": "A1",
        "severity": "high",
        "score": 0.9,
        "pattern": "hello",
    }
    rule.update(overrides)
    return yaml.safe_dump({"rules": [rule]}).encode()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"pattern": "(?<!x)hello"}, "RE2"),
        ({"pattern": r"(a)\1"}, "RE2"),
        ({"pattern": "x*"}, "empty"),
        ({"pattern": r"\s*"}, "empty"),
    ],
)
def test_unsafe_or_empty_patterns_rejected(overrides: dict[str, object], message: str) -> None:
    with pytest.raises(RuleError, match=message):
        parse_rules(_rule(**overrides), "test.yaml")


@pytest.mark.parametrize(
    "overrides",
    [{"id": "Bad Id"}, {"score": 1.5}, {"attack_class": "A9"}, {"extra": True}, {"pattern": ""}],
)
def test_invalid_rule_fields_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        parse_rules(_rule(**overrides), "test.yaml")


def test_duplicate_ids_rejected() -> None:
    raw = yaml.safe_load(_rule())
    raw["rules"].append(raw["rules"][0])
    with pytest.raises(RuleError, match="duplicate"):
        parse_rules(yaml.safe_dump(raw).encode(), "test.yaml")


def test_case_sensitivity() -> None:
    (insensitive,) = parse_rules(_rule(), "t")
    (sensitive,) = parse_rules(_rule(case_sensitive=True), "t")
    assert list(insensitive.regex.spans("HELLO")) == [(0, 5)]
    assert list(sensitive.regex.spans("HELLO")) == []


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200_000,
        "ignore " * 30_000,
        "ignore previous " * 20_000,
        "<|" * 100_000,
        "-" * 200_000,
        "password = " * 20_000,
        "-----BEGIN PRIVATE KEY-----" * 7_000,
        "eyJ" * 60_000,
    ],
)
def test_rules_are_fast_on_pathological_input(text: str) -> None:
    started = time.perf_counter()
    for rule in (*INJECTION, *SECRETS):
        list(rule.regex.spans(text))
    assert time.perf_counter() - started < 2.0
