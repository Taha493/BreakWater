"""Tool-call guard (A4, spec section 7).

Checks a proposed agent tool call, in order:
1. the tool is on the agent's allowlist (unknown agents and tools are denied);
2. arguments validate against the tool's JSON Schema and constraints;
3. taint: a high-impact tool's arguments must not repeat untrusted text seen in the session;
4. ``triggering_text``, if given, must pass the injection detectors;
5. per-agent and per-session rate limits.
An allowed call to a tool marked ``requires_confirmation`` returns ``require_confirmation``.

Not a text detector: it judges a structured call, so it does not implement ``Detector``.
State (taint marks, recent call counts) comes from a ``GuardState`` the caller provides.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol
from urllib.parse import unquote

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, model_validator

from gateway.core.context import CallContext
from gateway.core.pipeline import Pipeline
from gateway.core.redact import Hasher
from gateway.core.taint import argument_strings, fingerprints
from gateway.core.verdict import Action, AttackClass, Finding, Role, Severity

DETECTOR = "tool_guard"
# Which argument names each constraint applies to.
EMAIL_ARGS = frozenset({"to", "cc", "bcc", "recipient", "recipients"})
BODY_ARGS = frozenset({"body"})
PATH_ARGS = frozenset({"path", "file", "file_path", "filename"})
_EMAIL = re.compile(r"[^\s<>@,;]+@([^\s<>@,;]+)")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class ToolConstraints(_Strict):
    to_domain_allowlist: list[str] | None = None
    max_body_chars: int | None = Field(default=None, gt=0)
    path_prefix: str | None = Field(default=None, pattern=r"^/")


class ToolSpec(_Strict):
    allow: bool
    impact: Literal["low", "high"] = "low"
    requires_confirmation: bool = False
    json_schema: dict[str, Any] | None = Field(default=None, alias="schema")
    constraints: ToolConstraints = Field(default_factory=ToolConstraints)
    on_taint: Literal["deny", "require_confirmation"] | None = None

    @model_validator(mode="after")
    def _check_schema(self) -> ToolSpec:
        if self.json_schema is not None:
            try:
                Draft202012Validator.check_schema(self.json_schema)
            except SchemaError as exc:
                raise ValueError(f"invalid JSON Schema: {exc.message}") from exc
        return self


class AgentSpec(_Strict):
    tools: dict[str, ToolSpec] = Field(default_factory=dict)
    rate_limit_per_minute: int | None = Field(default=None, gt=0)
    session_rate_limit_per_minute: int | None = Field(default=None, gt=0)


class ToolDefaults(_Strict):
    on_taint: Literal["deny", "require_confirmation"] = "deny"
    taint_ttl_seconds: int = Field(default=3600, gt=0)
    max_argument_chars: int = Field(default=20_000, gt=0)


class ToolPolicy(_Strict):
    defaults: ToolDefaults = Field(default_factory=ToolDefaults)
    agents: dict[str, AgentSpec] = Field(default_factory=dict)


def parse_tool_policy(raw: bytes, source: str = "tools.yaml") -> ToolPolicy:
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{source} must contain a YAML mapping")
    return ToolPolicy.model_validate(data)


class ToolDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"


@dataclass(frozen=True)
class ToolCall:
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    session: str | None = None
    triggering_text: str | None = None
    max_layer: int | None = None  # caps the triggering-text scan, as for any other scan


@dataclass
class ToolCheck:
    decision: ToolDecision
    rule_id: str
    reason: str
    findings: list[Finding] = field(default_factory=list)


class GuardState(Protocol):
    async def tainted(self, session: str, fingerprints: set[str]) -> set[str]: ...

    async def recent_calls(self, agent_id: str, session: str | None) -> tuple[int, int]: ...


def _finding(rule_id: str, reason: str, score: float = 1.0) -> Finding:
    return Finding(
        detector=DETECTOR,
        attack_class=AttackClass.A4,
        severity=Severity.HIGH if score >= 0.7 else Severity.MEDIUM,
        score=score,
        reason=reason,
        rule_id=rule_id,
        layer=1,
    )


def _deny(rule_id: str, reason: str, extra: list[Finding] | None = None) -> ToolCheck:
    return ToolCheck(
        ToolDecision.DENY, rule_id, reason, [_finding(rule_id, reason), *(extra or [])]
    )


def _domain_allowed(domain: str, allowed: list[str]) -> bool:
    domain = domain.lower().rstrip(".")
    return any(domain == d.lower() or domain.endswith("." + d.lower()) for d in allowed)


def normalize_path(value: str) -> str:
    """Resolve encodings, backslashes, and ``..`` the way a naive tool might."""
    for _ in range(2):
        if "%" in value:
            value = unquote(value)
    return posixpath.normpath(value.replace("\\", "/"))


def _constraint_violation(spec: ToolSpec, arguments: dict[str, Any]) -> ToolCheck | None:
    c = spec.constraints
    if c.to_domain_allowlist is not None:
        for name in EMAIL_ARGS & arguments.keys():
            values = arguments[name] if isinstance(arguments[name], list) else [arguments[name]]
            for value in values:
                domains = _EMAIL.findall(str(value))
                if not domains or not all(
                    _domain_allowed(d, c.to_domain_allowlist) for d in domains
                ):
                    return _deny(
                        "tool-constraint-domain",
                        f"Argument '{name}' has an address outside the allowed domains",
                    )
    if c.max_body_chars is not None:
        for name in BODY_ARGS & arguments.keys():
            if len(str(arguments[name])) > c.max_body_chars:
                return _deny(
                    "tool-constraint-body-size",
                    f"Argument '{name}' exceeds {c.max_body_chars} characters",
                )
    if c.path_prefix is not None:
        prefix = c.path_prefix.rstrip("/") + "/"
        for name in PATH_ARGS & arguments.keys():
            value = arguments[name]
            if not isinstance(value, str) or "\x00" in value:
                return _deny("tool-constraint-path", f"Argument '{name}' is not a valid path")
            path = normalize_path(value)
            if not (path + "/").startswith(prefix):
                return _deny(
                    "tool-constraint-path",
                    f"Argument '{name}' is outside the allowed path {c.path_prefix}",
                )
    return None


class ToolGuard:
    def __init__(self, policy: ToolPolicy) -> None:
        self.policy = policy
        self._validators = {
            (agent, tool): Draft202012Validator(spec.json_schema)
            for agent, agent_spec in policy.agents.items()
            for tool, spec in agent_spec.tools.items()
            if spec.json_schema is not None
        }

    async def check(
        self,
        call: ToolCall,
        state: GuardState,
        hasher: Hasher,
        pipeline: Pipeline,
        request_id: str,
    ) -> ToolCheck:
        # 1. Allowlist
        agent = self.policy.agents.get(call.agent_id)
        if agent is None:
            return _deny("tool-unknown-agent", "Agent has no tool policy")
        spec = agent.tools.get(call.tool_name)
        if spec is None:
            return _deny("tool-not-allowlisted", "Tool is not on the agent's allowlist")
        if not spec.allow:
            return _deny("tool-disallowed", "Tool is disallowed for this agent")

        # 2. Arguments
        for path, value in argument_strings(call.arguments):
            if len(value) > self.policy.defaults.max_argument_chars:
                return _deny("tool-argument-too-long", f"Argument '{path}' is too long")
        validator = self._validators.get((call.agent_id, call.tool_name))
        if validator is not None:
            error = next(iter(sorted(validator.iter_errors(call.arguments), key=str)), None)
            if error is not None:
                where = "/".join(str(p) for p in error.absolute_path) or "(root)"
                # Name the location and failed keyword only: messages can echo values.
                return _deny(
                    "tool-args-schema", f"Arguments fail the schema at {where} ({error.validator})"
                )
        if (violation := _constraint_violation(spec, call.arguments)) is not None:
            return violation

        # 3. Taint
        if spec.impact == "high" and call.session:
            session_hash = hasher.session(call.session)
            for path, value in argument_strings(call.arguments):
                prints = fingerprints(value, hasher)
                if prints and await state.tainted(session_hash, prints):
                    reason = f"Argument '{path}' repeats untrusted content from this session"
                    on_taint = spec.on_taint or self.policy.defaults.on_taint
                    if on_taint == "deny":
                        return _deny("tool-tainted-args", reason)
                    return ToolCheck(
                        ToolDecision.REQUIRE_CONFIRMATION,
                        "tool-tainted-args",
                        reason,
                        [_finding("tool-tainted-args", reason, 0.6)],
                    )

        # 4. Triggering text
        if call.triggering_text:
            inspection = await pipeline.inspect(
                call.triggering_text,
                Role.TOOL_RESULT,
                CallContext(session=call.session, max_layer=call.max_layer),
                request_id,
            )
            if inspection.verdict.action is not Action.ALLOW:
                return _deny(
                    "tool-injected-trigger",
                    "The text that triggered this call contains an injection",
                    inspection.verdict.findings,
                )

        # 5. Rate limits
        agent_count, session_count = await state.recent_calls(call.agent_id, call.session)
        if agent.rate_limit_per_minute and agent_count >= agent.rate_limit_per_minute:
            return _deny("tool-rate-limit-agent", "Agent exceeded its tool calls per minute")
        if (
            agent.session_rate_limit_per_minute
            and call.session
            and session_count >= agent.session_rate_limit_per_minute
        ):
            return _deny("tool-rate-limit-session", "Session exceeded its tool calls per minute")

        if spec.requires_confirmation:
            reason = "Tool requires human confirmation"
            return ToolCheck(
                ToolDecision.REQUIRE_CONFIRMATION,
                "tool-requires-confirmation",
                reason,
                [_finding("tool-requires-confirmation", reason, 0.3)],
            )
        return ToolCheck(ToolDecision.ALLOW, "tool-allowed", "Tool call is within policy")
