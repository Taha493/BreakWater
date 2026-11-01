"""Turns attacks and benign cases into probes: the concrete requests sent to a target.

Each attack probe gets a fresh canary (spec section 8). The payload is filled in, then
mutated, then placed where the attack's delivery says: the user message, a planted document,
or a tool result.
"""

from __future__ import annotations

import html
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from breakwater.redteam.models import (
    CANARY_PLACEHOLDER,
    DEFAULT_QUESTION,
    PAYLOAD_PLACEHOLDER,
    Attack,
    BenignCase,
    Criterion,
    Delivery,
    SetupDocument,
)
from breakwater.redteam.mutators import Mutation, apply, choose

BASE_VARIANT = "base"
BENIGN_CATEGORY = "benign"


def new_canary() -> str:
    """A harmless marker that proves an attack worked when it shows up where it should not."""
    return "RTC-" + secrets.token_hex(6).upper()


@dataclass(frozen=True)
class Probe:
    kind: Literal["attack", "benign"]
    source_id: str
    variant: str
    category: str
    attack_class: str | None
    delivery: str
    question: str
    history: list[dict[str, str]] = field(default_factory=list)
    documents: list[dict[str, Any]] = field(default_factory=list)
    tool_result: str | None = None
    agent: bool = False
    secret: str | None = None
    canary: str | None = None
    criteria: list[Criterion] = field(default_factory=list)

    @property
    def case_id(self) -> str:
        return self.source_id if self.kind == "benign" else f"{self.source_id}:{self.variant}"

    def as_dict(self) -> dict[str, Any]:
        """What a python_callable target receives."""
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "category": self.category,
            "delivery": self.delivery,
            "question": self.question,
            "history": self.history,
            "documents": self.documents,
            "tool_result": self.tool_result,
            "agent": self.agent,
            "secret": self.secret,
        }


def _fill(text: str, canary: str) -> str:
    return text.replace(CANARY_PLACEHOLDER, canary)


def _document(doc: SetupDocument, payload: str, canary: str) -> dict[str, Any]:
    def place(text: str) -> str:
        # The payload lands inside HTML markup only through `content`; escape it there.
        value = html.escape(payload) if doc.format == "html" else payload
        return _fill(text, canary).replace(PAYLOAD_PLACEHOLDER, value)

    return {
        "name": doc.name,
        "format": doc.format,
        "content": place(doc.content),
        "hidden": _fill(doc.hidden, canary).replace(PAYLOAD_PLACEHOLDER, payload)
        if doc.hidden
        else None,
        "hiding": doc.hiding,
        "metadata": {k: _fill(v, canary).replace(PAYLOAD_PLACEHOLDER, payload)
                     for k, v in doc.metadata.items()},
    }  # fmt: skip


def _documents(
    docs: list[SetupDocument], mutation: Mutation | None, payload: str, canary: str
) -> list[dict[str, Any]]:
    if mutation is None or mutation.parts is None:
        return [_document(d, payload, canary) for d in docs]
    # Split: the documents that carry the payload get the first half; a copy of each, with
    # the second half, is planted next to it.
    first, second = mutation.parts
    out: list[dict[str, Any]] = []
    for doc in docs:
        out.append(_document(doc, first, canary))
        if any(PAYLOAD_PLACEHOLDER in t for t in doc.texts()):
            copy = _document(doc, second, canary)
            copy["name"] = f"part2-{doc.name}"
            out.append(copy)
    return out


def attack_probe(attack: Attack, seed: int, mutation_name: str | None = None) -> Probe:
    canary = new_canary()
    payload = _fill(attack.payload, canary)
    mutation = apply(mutation_name, payload, seed, attack.id) if mutation_name else None
    if mutation is not None:
        payload = mutation.payload
    question = _fill(attack.question or DEFAULT_QUESTION, canary)
    tool_result = None
    if attack.delivery is Delivery.USER_MESSAGE:
        question = payload
    elif attack.delivery is Delivery.TOOL_RESULT:
        tool_result = _fill(attack.tool_result or PAYLOAD_PLACEHOLDER, canary).replace(
            PAYLOAD_PLACEHOLDER, payload
        )
    return Probe(
        kind="attack",
        source_id=attack.id,
        variant=mutation.name if mutation else BASE_VARIANT,
        category=attack.category.value,
        attack_class=attack.attack_class.value,
        delivery=attack.delivery.value,
        question=question,
        history=[{"role": t.role, "content": _fill(t.content, canary)} for t in attack.history],
        documents=_documents(attack.setup.documents, mutation, payload, canary),
        tool_result=tool_result,
        agent=attack.agent,
        secret=canary if attack.system_secret else None,
        canary=canary,
        criteria=[_fill_criterion(c, canary) for c in attack.success_criteria],
    )


def _fill_criterion(criterion: Criterion, canary: str) -> Criterion:
    data = criterion.model_dump()
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = _fill(value, canary)
        elif isinstance(value, dict):
            data[key] = {k: _fill(v, canary) for k, v in value.items()}
    return type(criterion).model_validate(data)


def attack_probes(attack: Attack, seed: int, mutations: int) -> list[Probe]:
    """The base probe plus up to ``mutations`` mutated variants, each with its own canary.

    Mutators are chosen from the payload before the canary is filled in, so a seed always
    picks the same ones."""
    names = choose(
        attack.payload,
        seed,
        attack.id,
        mutations,
        splittable=attack.delivery is Delivery.RETRIEVED_DOCUMENT,
    )
    return [attack_probe(attack, seed), *(attack_probe(attack, seed, n) for n in names)]


def benign_probe(case: BenignCase) -> Probe:
    return Probe(
        kind="benign",
        source_id=case.id,
        variant=BASE_VARIANT,
        category=BENIGN_CATEGORY,
        attack_class=None,
        delivery=case.delivery.value,
        question=case.question or DEFAULT_QUESTION,
        history=[t.model_dump() for t in case.history],
        documents=[_document(d, "", "") for d in case.setup.documents],
        tool_result=case.tool_result,
        agent=case.agent,
    )
