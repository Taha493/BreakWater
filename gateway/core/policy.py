"""Policy: maps findings to an action (spec section 6).

A finding's score is multiplied by its detector's weight. Findings below ``block_at`` never
trigger an action (scores in the judge band are allowed and logged until the M5 judge exists).
Findings at or above it take the action configured for their attack class and role. The most
severe action across findings wins: block > quarantine > redact > allow.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from gateway.core.verdict import Action, AttackClass, Finding, Role

CANARY_RULE_ID = "canary-echo"
DETECTOR_ERROR_RULE_ID = "detector-error"
SCAN_LIMIT_RULE_ID = "scan-limit-exceeded"
SECRETS_DETECTOR = "leak_secrets"
_GATEWAY_BLOCK_RULES = frozenset({DETECTOR_ERROR_RULE_ID, SCAN_LIMIT_RULE_ID})

ACTION_RANK = {Action.ALLOW: 0, Action.REDACT: 1, Action.QUARANTINE: 2, Action.BLOCK: 3}


class PolicyAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    QUARANTINE = "quarantine"
    STRIP_AND_LOG = "strip_and_log"
    DENY = "deny"


_TO_ACTION = {
    PolicyAction.ALLOW: Action.ALLOW,
    PolicyAction.BLOCK: Action.BLOCK,
    PolicyAction.DENY: Action.BLOCK,
    PolicyAction.REDACT: Action.REDACT,
    PolicyAction.STRIP_AND_LOG: Action.REDACT,
    PolicyAction.QUARANTINE: Action.QUARANTINE,
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Thresholds(_Strict):
    allow_below: float = Field(ge=0.0, le=1.0)
    judge_band: tuple[float, float]
    block_at: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_order(self) -> Thresholds:
        low, high = self.judge_band
        if not (self.allow_below <= low <= high <= self.block_at):
            raise ValueError("thresholds must satisfy allow_below <= judge_band <= block_at")
        return self


class JudgeSettings(_Strict):
    enabled: bool = False
    timeout_ms: int = Field(default=4000, gt=0)
    max_calls_per_minute: int = Field(default=30, ge=0)


FailAction = Literal["block", "allow_and_log"]


class FailureModes(_Strict):
    classifier_error: str = "allow_and_log"  # used from M5
    judge_error: str = "block_if_score_at_least_0.5"  # used from M5
    response_inspection_error: FailAction = "block"
    request_inspection_error: FailAction = "block"


class Limits(_Strict):
    max_scan_chars: int = Field(default=200_000, gt=0)
    over_limit: Literal["block", "truncate"] = "block"


class CanarySettings(_Strict):
    enabled: bool = False


class SystemPromptLeakSettings(_Strict):
    min_overlap_words: int = Field(default=12, ge=6, le=200)


class ExfilSettings(_Strict):
    allowed_domains: list[str] = Field(default_factory=list)


class PiiSettings(_Strict):
    allowed_email_domains: list[str] = Field(default_factory=list)


class SecretsSettings(_Strict):
    entropy_threshold: float = Field(default=4.3, gt=0)
    min_entropy_length: int = Field(default=32, ge=16)


class DetectorSettings(_Strict):
    leak_system_prompt: SystemPromptLeakSettings = Field(default_factory=SystemPromptLeakSettings)
    exfil_channel: ExfilSettings = Field(default_factory=ExfilSettings)
    leak_pii: PiiSettings = Field(default_factory=PiiSettings)
    leak_secrets: SecretsSettings = Field(default_factory=SecretsSettings)


class PolicyConfig(_Strict):
    thresholds: Thresholds
    actions: dict[AttackClass, dict[str, PolicyAction]] = Field(default_factory=dict)
    weights: dict[str, float] = Field(default_factory=dict)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    failure_mode: FailureModes = Field(default_factory=FailureModes)
    limits: Limits = Field(default_factory=Limits)
    canary: CanarySettings = Field(default_factory=CanarySettings)
    detectors: DetectorSettings = Field(default_factory=DetectorSettings)

    @model_validator(mode="after")
    def _check_weights(self) -> PolicyConfig:
        if any(w < 0 for w in self.weights.values()):
            raise ValueError("detector weights must be >= 0")
        return self


@dataclass(frozen=True)
class Redaction:
    """Part of the inspected text to replace. ``span`` None means the whole text."""

    span: tuple[int, int] | None
    label: str
    message_index: int | None = None


@dataclass(frozen=True)
class Decision:
    action: Action
    risk_score: float
    redactions: tuple[Redaction, ...]


def most_severe(actions: Sequence[Action]) -> Action:
    return max(actions, key=lambda a: ACTION_RANK[a], default=Action.ALLOW)


class Policy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def weighted_score(self, finding: Finding) -> float:
        return min(1.0, finding.score * self.config.weights.get(finding.detector, 1.0))

    def risk_score(self, findings: Sequence[Finding]) -> float:
        return max((self.weighted_score(f) for f in findings), default=0.0)

    def finding_action(self, finding: Finding, role: Role) -> Action:
        if finding.rule_id == CANARY_RULE_ID:
            return Action.BLOCK  # a canary echo is a confirmed leak (spec section 6)
        if finding.rule_id in _GATEWAY_BLOCK_RULES:
            return Action.BLOCK  # fail closed: the text could not be fully inspected
        if self.weighted_score(finding) < self.config.thresholds.block_at:
            return Action.ALLOW
        row = self.config.actions.get(finding.attack_class, {})
        key = role.value
        if finding.detector == SECRETS_DETECTOR and role is not Role.ASSISTANT and "secrets" in row:
            key = "secrets"
        configured = row.get(key)
        # A class/role pair with no configured action fails safe.
        return Action.BLOCK if configured is None else _TO_ACTION[configured]

    def decide(self, findings: Sequence[Finding], role: Role) -> Decision:
        actions: list[Action] = []
        redactions: list[Redaction] = []
        for finding in findings:
            action = self.finding_action(finding, role)
            actions.append(action)
            if action is Action.REDACT:
                strip = self._configured(finding, role) is PolicyAction.STRIP_AND_LOG
                redactions.append(
                    Redaction(
                        span=None if strip else finding.span,
                        label=finding.rule_id or finding.detector,
                        message_index=finding.message_index,
                    )
                )
        return Decision(most_severe(actions), self.risk_score(findings), tuple(redactions))

    def _configured(self, finding: Finding, role: Role) -> PolicyAction | None:
        return self.config.actions.get(finding.attack_class, {}).get(role.value)


def parse_policy(raw: bytes, source: str = "policies.yaml") -> Policy:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{source} must contain a YAML mapping")
    return Policy(PolicyConfig.model_validate(data))
