"""Reassembles assistant text from an OpenAI-style server-sent event stream."""

from __future__ import annotations

import json

# Upper bound on text kept from one streamed response, so a runaway upstream cannot
# exhaust memory (spec section 11, input limits).
MAX_COLLECTED_CHARS = 1_000_000


class SSETextCollector:
    """Feed raw stream bytes in any chunking; read the concatenated ``delta.content`` text."""

    def __init__(self, max_chars: int = MAX_COLLECTED_CHARS) -> None:
        self._buffer = b""
        self._parts: list[str] = []
        self._size = 0
        self._max_chars = max_chars
        self.truncated = False
        self.model: str | None = None

    @property
    def text(self) -> str:
        return "".join(self._parts)

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        *lines, self._buffer = self._buffer.split(b"\n")
        for line in lines:
            self._handle_line(line.rstrip(b"\r"))

    def _handle_line(self, line: bytes) -> None:
        if not line.startswith(b"data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == b"[DONE]":
            return
        try:
            event = json.loads(payload)
        except ValueError:
            return
        if not isinstance(event, dict):
            return
        if self.model is None and isinstance(event.get("model"), str):
            self.model = event["model"]
        for choice in event.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            content = delta.get("content") if isinstance(delta, dict) else None
            if isinstance(content, str):
                self._append(content)

    def _append(self, content: str) -> None:
        room = self._max_chars - self._size
        if room <= 0:
            self.truncated = True
            return
        if len(content) > room:
            content = content[:room]
            self.truncated = True
        self._parts.append(content)
        self._size += len(content)
