"""YAML rule files compiled with RE2 (spec section 6, rules for rule authors).

RE2 matches in time linear in the input and has no backtracking, so a crafted prompt cannot
make a rule hang. The price is no lookarounds and no backreferences; such rules fail to load.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import re2
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from breakwater.core.verdict import AttackClass, Severity

MAX_PATTERN_CHARS = 2000


class RuleError(ValueError):
    pass


class RuleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    description: str = Field(min_length=1, max_length=200)
    attack_class: AttackClass
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_CHARS)
    case_sensitive: bool = False
    # Label used in redaction placeholders, e.g. ``[REDACTED:api_key]``.
    kind: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,32}$")

    @field_validator("description")
    @classmethod
    def _single_line(cls, value: str) -> str:
        return " ".join(value.split())


class _RuleFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleSpec] = Field(min_length=1)


class Pattern:
    """A typed wrapper around a compiled RE2 pattern."""

    def __init__(self, pattern: str, case_sensitive: bool) -> None:
        options = re2.Options()
        options.log_errors = False
        options.case_sensitive = case_sensitive
        try:
            self._compiled: Any = re2.compile(pattern, options)
        except re2.error as exc:
            raise RuleError(str(exc)) from exc

    def matches(self, text: str) -> bool:
        return self._compiled.search(text) is not None

    def spans(self, text: str) -> Iterator[tuple[int, int]]:
        for match in self._compiled.finditer(text):
            start, end = match.span()
            if end > start:
                yield int(start), int(end)


@dataclass(frozen=True)
class Rule:
    spec: RuleSpec
    regex: Pattern

    @property
    def id(self) -> str:
        return self.spec.id


def compile_rules(specs: list[RuleSpec], source: str) -> tuple[Rule, ...]:
    seen: set[str] = set()
    rules: list[Rule] = []
    for spec in specs:
        if spec.id in seen:
            raise RuleError(f"{source}: duplicate rule id {spec.id!r}")
        seen.add(spec.id)
        try:
            regex = Pattern(spec.pattern, spec.case_sensitive)
        except RuleError as exc:
            raise RuleError(
                f"{source}: rule {spec.id!r} does not compile under RE2: {exc}"
            ) from exc
        if regex.matches("") or regex.matches(" "):
            raise RuleError(f"{source}: rule {spec.id!r} matches empty or blank text")
        rules.append(Rule(spec, regex))
    return tuple(rules)


def parse_rules(raw: bytes, source: str) -> tuple[Rule, ...]:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise RuleError(f"{source}: must be a YAML mapping with a 'rules' list")
    return compile_rules(_RuleFile.model_validate(data).rules, source)


def load_rules(path: Path) -> tuple[Rule, ...]:
    return parse_rules(path.read_bytes(), path.name)
