"""Policy loading and the mapping from findings to an action (spec section 6).

M1 implements thresholds only: the risk score is the maximum finding score, and a score at or
above ``block_at`` blocks (or quarantines retrieved content). Per-class actions and per-detector
weights arrive with the detectors in M2.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from gateway.core.verdict import Action, Finding, Role


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow_below: float = Field(ge=0.0, le=1.0)
    judge_band: tuple[float, float]
    block_at: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_order(self) -> Thresholds:
        low, high = self.judge_band
        if not (self.allow_below <= low <= high <= self.block_at):
            raise ValueError("thresholds must satisfy allow_below <= judge_band <= block_at")
        return self


class JudgeSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    timeout_ms: int = Field(default=4000, gt=0)
    max_calls_per_minute: int = Field(default=30, ge=0)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    thresholds: Thresholds
    actions: dict[str, dict[str, str]] = Field(default_factory=dict)
    judge: JudgeSettings = Field(default_factory=JudgeSettings)
    failure_mode: dict[str, str] = Field(default_factory=dict)


class Policy:
    def __init__(self, config: PolicyConfig, version: str) -> None:
        self.config = config
        self.version = version

    def risk_score(self, findings: Sequence[Finding]) -> float:
        return max((f.score for f in findings), default=0.0)

    def decide(self, findings: Sequence[Finding], role: Role) -> tuple[Action, float]:
        score = self.risk_score(findings)
        if score >= self.config.thresholds.block_at:
            return (Action.QUARANTINE if role is Role.RETRIEVED else Action.BLOCK), score
        return Action.ALLOW, score


def load_policy(path: Path) -> Policy:
    raw = path.read_bytes()
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    config = PolicyConfig.model_validate(data)
    return Policy(config, version=hashlib.sha256(raw).hexdigest()[:12])
