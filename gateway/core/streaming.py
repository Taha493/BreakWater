"""Response inspection for streamed completions (spec section 5, streaming).

Assistant text is held back by ``holdback`` characters and the accumulated text is rescanned
every ``scan_every`` new characters, so a secret split across chunks is still caught before
it is released. Redacted spans are replaced in the released text; a blocking finding ends
the stream (the caller then sends a final error event).

Text released before a late detection cannot be recalled; the hold-back window bounds how
long a secret can be and still be caught entirely.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from gateway.core.pipeline import Inspection
from gateway.core.sse import SSEEvent, SSEParser
from gateway.core.verdict import Action

InspectFn = Callable[[str, int], Awaitable[Inspection]]
DEFAULT_SCAN_EVERY = 64


def release(
    text: str, released: int, target: int, spans: list[tuple[int, int, str]]
) -> tuple[str, int]:
    """Text to emit for ``text[released:target]`` with ``spans`` replaced by placeholders.

    Never emits part of a span: if a span crosses ``target``, release stops at its start.
    Returns the output and the new release position.
    """
    out: list[str] = []
    pos = released
    for start, end, label in sorted(spans):
        if end <= pos:
            continue
        if start >= target:
            break
        if end > target:
            target = max(pos, start)
            break
        start = max(start, pos)
        out.append(text[pos:start])
        out.append(f"[REDACTED:{label}]")
        pos = end
    if pos < target:
        out.append(text[pos:target])
        pos = target
    return "".join(out), pos


@dataclass
class _Choice:
    text: str = ""
    released: int = 0
    scanned: int = 0
    inspection: Inspection | None = None


@dataclass
class StreamGuard:
    inspect: InspectFn
    holdback: int
    scan_every: int = DEFAULT_SCAN_EVERY
    blocked: Inspection | None = None
    _parser: SSEParser = field(default_factory=SSEParser)
    _choices: dict[int, _Choice] = field(default_factory=dict)
    _queued: list[bytes] = field(default_factory=list)
    _template: dict[str, Any] | None = None

    @property
    def inspections(self) -> list[Inspection]:
        return [c.inspection for _, c in sorted(self._choices.items()) if c.inspection]

    @property
    def model(self) -> str | None:
        model = (self._template or {}).get("model")
        return model if isinstance(model, str) else None

    @property
    def texts(self) -> dict[int, str]:
        return {i: c.text for i, c in sorted(self._choices.items())}

    def _holding(self) -> bool:
        return any(c.released < len(c.text) for c in self._choices.values())

    async def feed(self, chunk: bytes) -> list[bytes]:
        out: list[bytes] = []
        for event in self._parser.feed(chunk):
            out.extend(await self._on_event(event))
            if self.blocked:
                return out
        return out

    async def finish(self) -> list[bytes]:
        out: list[bytes] = []
        for event in self._parser.flush():
            out.extend(await self._on_event(event))
            if self.blocked:
                return out
        for index in sorted(self._choices):
            out.extend(await self._scan_and_release(index, final=True))
            if self.blocked:
                return out
        out.extend(self._queued)
        self._queued.clear()
        return out

    async def _on_event(self, event: SSEEvent) -> list[bytes]:
        payload = _json(event.data)
        deltas = _content_deltas(payload) if payload is not None else {}
        if payload is None or not deltas:
            if self._holding() or event.data == "[DONE]":
                self._queued.append(event.raw)
                return []
            return [event.raw]

        self._template = {k: v for k, v in payload.items() if k not in ("choices", "usage")}
        out: list[bytes] = []
        rest = _without_content(payload)
        if rest is not None:
            # Keep role/finish/tool-call parts in order relative to the text already sent.
            (self._queued if self._holding() else out).append(_encode(rest))
        for index, content in deltas.items():
            choice = self._choices.setdefault(index, _Choice())
            choice.text += content
            if len(choice.text) - choice.scanned >= self.scan_every:
                out.extend(await self._scan_and_release(index, final=False))
                if self.blocked:
                    return out
        return out

    async def _scan_and_release(self, index: int, final: bool) -> list[bytes]:
        choice = self._choices[index]
        if choice.scanned < len(choice.text) or choice.inspection is None:
            choice.inspection = await self.inspect(choice.text, index)
            choice.scanned = len(choice.text)
        inspection = choice.inspection
        if inspection.verdict.action in (Action.BLOCK, Action.QUARANTINE):
            self.blocked = inspection
            return []
        spans = [
            (*(r.span or (0, len(choice.text))), r.label)
            for r in inspection.redactions
            if inspection.verdict.action is Action.REDACT
        ]
        target = len(choice.text) if final else max(0, len(choice.text) - self.holdback)
        text, choice.released = release(choice.text, choice.released, target, spans)
        return [self._content_event(index, text)] if text else []

    def _content_event(self, index: int, text: str) -> bytes:
        payload = dict(self._template or {"object": "chat.completion.chunk"})
        payload["choices"] = [{"index": index, "delta": {"content": text}, "finish_reason": None}]
        return _encode(payload)


def _json(data: str | None) -> dict[str, Any] | None:
    if not data or data == "[DONE]":
        return None
    try:
        value = json.loads(data)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _content_deltas(payload: dict[str, Any]) -> dict[int, str]:
    deltas: dict[int, str] = {}
    for position, choice in enumerate(payload.get("choices") or []):
        if not isinstance(choice, dict):
            continue
        delta = choice.get("delta")
        content = delta.get("content") if isinstance(delta, dict) else None
        if isinstance(content, str) and content:
            index = choice.get("index", position)
            deltas[index if isinstance(index, int) else position] = content
    return deltas


def _without_content(payload: dict[str, Any]) -> dict[str, Any] | None:
    """The event minus its content deltas, if anything else (role, finish_reason, usage,
    tool calls) remains worth sending."""
    choices = []
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        delta = {k: v for k, v in (choice.get("delta") or {}).items() if k != "content"}
        if delta or choice.get("finish_reason") is not None:
            choices.append({**choice, "delta": delta})
    if not choices and "usage" not in payload:
        return None
    return {**payload, "choices": choices}


def _encode(payload: dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(payload).encode() + b"\n\n"
