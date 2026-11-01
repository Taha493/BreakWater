"""Verdict, Finding, and the enums shared by detectors, policy, and storage (spec section 5)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackClass(StrEnum):
    A1 = "A1"  # direct prompt injection
    A2 = "A2"  # indirect prompt injection
    A3 = "A3"  # data leakage
    A4 = "A4"  # tool abuse


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    QUARANTINE = "quarantine"


class Role(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    RETRIEVED = "retrieved"
    TOOL_RESULT = "tool_result"


class Finding(BaseModel):
    """One detector hit. Never carries the matched text, only its span in the original input."""

    model_config = ConfigDict(frozen=True)

    detector: str
    attack_class: AttackClass
    severity: Severity
    score: float = Field(ge=0.0, le=1.0)
    reason: str
    rule_id: str | None = None
    span: tuple[int, int] | None = None
    layer: int = Field(ge=0)


class Verdict(BaseModel):
    request_id: str
    action: Action
    risk_score: float = Field(ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    latency_ms: float = Field(ge=0.0)
    judge_used: bool = False


ScanContext = dict[str, Any]
