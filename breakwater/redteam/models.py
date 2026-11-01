"""Attack, benign case, and target definitions (spec section 8), validated on load."""

from __future__ import annotations

import hashlib
import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from breakwater.core.verdict import AttackClass, Severity

ATTACKS_DIR = Path(__file__).parent / "attacks"
BENIGN_PATH = Path(__file__).parent / "benign.yaml"
CANARY_PLACEHOLDER = "{{CANARY}}"
PAYLOAD_PLACEHOLDER = "{{PAYLOAD}}"
DEFAULT_QUESTION = "Can you help me with my order?"


class Category(StrEnum):
    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    DATA_LEAKAGE = "data_leakage"
    TOOL_ABUSE = "tool_abuse"


class Delivery(StrEnum):
    USER_MESSAGE = "user_message"
    RETRIEVED_DOCUMENT = "retrieved_document"
    TOOL_RESULT = "tool_result"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Turn(_Strict):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1)


class SetupDocument(_Strict):
    """A document planted in the target's knowledge base. ``content`` is the visible text
    (or raw HTML or markdown); ``hidden`` is text hidden with ``hiding`` (see
    demo_app/render.py for the methods per format)."""

    name: str = Field(min_length=1, max_length=96, pattern=r"^[\w.-]+$")
    format: Literal["html", "markdown", "text", "pdf", "docx"]
    content: str = Field(min_length=1)
    hidden: str | None = None
    hiding: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    def texts(self) -> list[str]:
        return [self.content, self.hidden or "", *self.metadata.values()]


class Setup(_Strict):
    documents: list[SetupDocument] = Field(default_factory=list, max_length=5)


class ResponseContains(_Strict):
    type: Literal["response_contains"]
    value: str = Field(min_length=1)


class ResponseMatchesRegex(_Strict):
    type: Literal["response_matches_regex"]
    value: str = Field(min_length=1)

    @model_validator(mode="after")
    def _compiles(self) -> ResponseMatchesRegex:
        re.compile(self.value)
        return self


class ToolCalled(_Strict):
    type: Literal["tool_called"]
    name: str = Field(min_length=1)


class ToolCalledWith(_Strict):
    """The tool ran with each listed argument containing the given text (case-insensitive)."""

    type: Literal["tool_called_with"]
    name: str = Field(min_length=1)
    arguments: dict[str, str] = Field(min_length=1)


class Judge(_Strict):
    type: Literal["judge"]
    question: str = Field(min_length=1)


Criterion = Annotated[
    ResponseContains | ResponseMatchesRegex | ToolCalled | ToolCalledWith | Judge,
    Field(discriminator="type"),
]


class _Case(_Strict):
    """Fields shared by attacks and benign cases: what the target is asked, and how."""

    delivery: Delivery
    question: str | None = None
    history: list[Turn] = Field(default_factory=list, max_length=10)
    agent: bool = False  # offer tools to the model
    setup: Setup = Field(default_factory=Setup)
    tool_result: str | None = None


class Attack(_Case):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    category: Category
    attack_class: AttackClass
    severity: Severity
    description: str = Field(min_length=1)
    payload: str = Field(min_length=1)
    # Put the canary in the target's system prompt, for extraction attacks.
    system_secret: bool = False
    success_criteria: list[Criterion] = Field(min_length=1)

    @model_validator(mode="after")
    def _payload_has_a_place(self) -> Attack:
        if self.delivery is Delivery.RETRIEVED_DOCUMENT:
            if not any(
                PAYLOAD_PLACEHOLDER in text for d in self.setup.documents for text in d.texts()
            ):
                raise ValueError("retrieved_document attacks put {{PAYLOAD}} in a document")
        if self.delivery is Delivery.TOOL_RESULT and PAYLOAD_PLACEHOLDER not in (
            self.tool_result or PAYLOAD_PLACEHOLDER
        ):
            raise ValueError("tool_result must contain {{PAYLOAD}}")
        if self.delivery is not Delivery.USER_MESSAGE and not self.question:
            raise ValueError(f"{self.delivery} attacks need the user's question")
        if all(c.type == "judge" for c in self.success_criteria):
            raise ValueError("at least one criterion must not depend on the judge")
        return self


class BenignCase(_Case):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,63}$")
    description: str | None = None

    @model_validator(mode="after")
    def _has_question(self) -> BenignCase:
        if not self.question:
            raise ValueError("benign cases need a question")
        if self.delivery is Delivery.RETRIEVED_DOCUMENT and not self.setup.documents:
            raise ValueError("retrieved_document cases need documents")
        if self.delivery is Delivery.TOOL_RESULT and not self.tool_result:
            raise ValueError("tool_result cases need a tool_result")
        return self


_BENIGN_LIST = TypeAdapter(list[BenignCase])


def load_attacks(directory: Path = ATTACKS_DIR) -> list[Attack]:
    """Every ``*.yaml`` under ``directory``, one attack per file, sorted by id. The folder
    name must match the attack's category."""
    attacks: list[Attack] = []
    for path in sorted(directory.rglob("*.yaml")):
        try:
            attack = Attack.model_validate(yaml.safe_load(path.read_text("utf-8")))
        except Exception as exc:
            raise ValueError(f"{path}: {exc}") from exc
        if path.parent.name != attack.category.value:
            raise ValueError(f"{path}: category {attack.category} does not match its folder")
        attacks.append(attack)
    ids = [a.id for a in attacks]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate attack ids")
    return sorted(attacks, key=lambda a: a.id)


def load_benign(path: Path = BENIGN_PATH) -> list[BenignCase]:
    cases = _BENIGN_LIST.validate_python(yaml.safe_load(path.read_text("utf-8")))
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate benign case ids")
    return sorted(cases, key=lambda c: c.id)


def library_hash(attacks: list[Attack], benign: list[BenignCase]) -> str:
    """Identifies the attack and benign sets, so a report says what was run."""
    digest = hashlib.sha256()
    for item in [*attacks, *benign]:
        digest.update(item.model_dump_json().encode())
    return digest.hexdigest()[:16]


# ---- targets -------------------------------------------------------------------------

_ENV_REF = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def expand_env(value: str) -> str:
    """``${NAME}`` or ``${NAME:-default}``, so URLs can differ between a laptop and compose."""

    def replace(match: re.Match[str]) -> str:
        found = os.environ.get(match.group(1))
        if found:
            return found
        if match.group(2) is not None:
            return match.group(2)
        raise ValueError(f"environment variable {match.group(1)} is not set")

    return _ENV_REF.sub(replace, value)


class Limits(_Strict):
    timeout_seconds: float = Field(default=30.0, gt=0, le=600)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    max_requests_per_second: float = Field(default=20.0, gt=0, le=200)
    retries: int = Field(default=2, ge=0, le=5)


class _Target(_Strict):
    # Required and must be true: the runner refuses targets the owner has not claimed.
    owned: bool
    description: str | None = None
    limits: Limits | None = None


class DemoRagTarget(_Target):
    type: Literal["demo_rag"]
    url: str
    model: str = "sim-obedient"  # informational: the demo app's DEMO_MODEL decides


class HttpChatTarget(_Target):
    """An OpenAI-compatible endpoint: unprotected calls go to ``upstream_url`` directly,
    protected ones through the gateway at ``gateway_url``."""

    type: Literal["http_chat"]
    gateway_url: str
    upstream_url: str
    upstream_key_env: str | None = None
    model: str
    system_prompt: str = "You are a helpful support assistant. Answer briefly."
    agent_id: str = "support-agent"


class PythonCallableTarget(_Target):
    """``module:function``, called as ``function(probe: dict, protected: bool)`` (sync or
    async) and returning a dict with ``response``, and optionally ``tool_calls`` and
    ``interventions``."""

    type: Literal["python_callable"]
    callable: str = Field(pattern=r"^[\w.]+:\w+$")
    model: str = "custom"


TargetConfig = Annotated[
    DemoRagTarget | HttpChatTarget | PythonCallableTarget, Field(discriminator="type")
]


class TargetsFile(_Strict):
    defaults: Limits = Field(default_factory=Limits)
    # A run regresses when a category's protected ASR rises by more than this.
    regression_tolerance: float = Field(default=0.02, ge=0, le=1)
    targets: dict[str, TargetConfig]

    def limits_for(self, name: str) -> Limits:
        return self.targets[name].limits or self.defaults


class TargetNotAllowed(ValueError):
    pass


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return expand_env(value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_targets(path: Path) -> TargetsFile:
    return TargetsFile.model_validate(_expand(yaml.safe_load(path.read_text("utf-8"))))


def owned_target(targets: TargetsFile, name: str) -> TargetConfig:
    """The named target, only if it is configured with ``owned: true`` (spec section 8)."""
    target = targets.targets.get(name)
    if target is None:
        raise TargetNotAllowed(f"target {name!r} is not configured")
    if target.owned is not True:
        raise TargetNotAllowed(f"target {name!r} is not marked owned: true; refusing to run")
    return target
