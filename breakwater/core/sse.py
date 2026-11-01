"""Splits a server-sent event byte stream into events, in any chunking."""

from __future__ import annotations

from dataclasses import dataclass

# Upper bound on one buffered event, so an upstream that never ends an event cannot exhaust
# memory (spec section 11, input limits).
MAX_EVENT_BYTES = 1_000_000


class SSEError(ValueError):
    pass


@dataclass(frozen=True)
class SSEEvent:
    raw: bytes  # the event as received, normalized to "\n" line endings, with its blank line
    data: str | None  # the joined ``data:`` lines, or None if the event has none


def _parse(block: bytes) -> SSEEvent:
    lines = block.split(b"\n")
    data = [
        line[5:].removeprefix(b" ").decode("utf-8", "replace")
        for line in lines
        if line.startswith(b"data:")
    ]
    return SSEEvent(raw=block + b"\n\n", data="\n".join(data) if data else None)


class SSEParser:
    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buffer += chunk.replace(b"\r\n", b"\n")
        *blocks, self._buffer = self._buffer.split(b"\n\n")
        if len(self._buffer) > MAX_EVENT_BYTES:
            raise SSEError("upstream event exceeds the size limit")
        return [_parse(b) for b in blocks if b.strip()]

    def flush(self) -> list[SSEEvent]:
        rest, self._buffer = self._buffer, b""
        return [_parse(rest.rstrip(b"\n"))] if rest.strip() else []
