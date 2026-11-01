from __future__ import annotations

import json

import pytest

from gateway.core.context import CallContext
from gateway.core.pipeline import Inspection
from gateway.core.sse import SSEParser
from gateway.core.streaming import StreamGuard, release
from gateway.core.verdict import Role
from tests.conftest import default_runtime

SECRET = "sk-" + "s" * 40
RUNTIME = default_runtime()


def sse(*words: str, finish: bool = True) -> bytes:
    first = {"id": "c1", "model": "m-1", "choices": [{"index": 0, "delta": {"role": "assistant"}}]}
    first["choices"][0]["delta"]["content"] = ""  # type: ignore[index]
    out = f"data: {json.dumps(first)}\n\n".encode()
    for word in words:
        chunk = {"id": "c1", "model": "m-1", "choices": [{"index": 0, "delta": {"content": word}}]}
        out += f"data: {json.dumps(chunk)}\n\n".encode()
    if finish:
        last = {"id": "c1", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        out += f"data: {json.dumps(last)}\n\n".encode()
    return out + b"data: [DONE]\n\n"


def guard(
    holdback: int = 200, scan_every: int = 16, call: CallContext | None = None
) -> StreamGuard:
    async def inspect(text: str, index: int) -> Inspection:
        return await RUNTIME.pipeline.inspect(
            text, Role.ASSISTANT, call or CallContext(), "r", index
        )

    return StreamGuard(inspect=inspect, holdback=holdback, scan_every=scan_every)


async def run(g: StreamGuard, raw: bytes, chunk_size: int) -> bytes:
    out = b""
    for i in range(0, len(raw), chunk_size):
        out += b"".join(await g.feed(raw[i : i + chunk_size]))
        if g.blocked:
            return out
    return out + b"".join(await g.finish())


def text_of(stream: bytes) -> str:
    parser = SSEParser()
    text = ""
    for event in parser.feed(stream) + parser.flush():
        if event.data and event.data != "[DONE]":
            for choice in json.loads(event.data).get("choices", []):
                text += (choice.get("delta") or {}).get("content") or ""
    return text


# ---- release() -----------------------------------------------------------------------


def test_release_plain() -> None:
    assert release("hello world", 0, 5, []) == ("hello", 5)


def test_release_replaces_span() -> None:
    assert release("ab SECRET cd", 0, 12, [(3, 9, "x")]) == ("ab [REDACTED:x] cd", 12)


def test_release_stops_before_span_crossing_target() -> None:
    assert release("ab SECRET cd", 0, 6, [(3, 9, "x")]) == ("ab ", 3)


def test_release_late_span_redacts_remainder_only() -> None:
    # The span started in text that was already released: send only the placeholder.
    assert release("ab SECRET cd", 5, 12, [(3, 9, "x")]) == ("[REDACTED:x] cd", 12)


# ---- StreamGuard ---------------------------------------------------------------------


@pytest.mark.parametrize("chunk_size", [1, 7, 64, 10_000])
async def test_benign_stream_text_is_unchanged(chunk_size: int) -> None:
    words = [f"word{i} " for i in range(80)]
    out = await run(guard(holdback=50), sse(*words), chunk_size)
    assert text_of(out) == "".join(words)
    events = [e.data for e in SSEParser().feed(out)]
    assert events[-1] == "[DONE]"
    assert '"role": "assistant"' in (events[0] or "")  # role first
    assert '"finish_reason": "stop"' in (events[-2] or "")  # finish after all text


@pytest.mark.parametrize("chunk_size", [1, 5, 33, 10_000])
async def test_secret_split_across_chunks_is_redacted(chunk_size: int) -> None:
    pieces = ["Your key: ", SECRET[:10], SECRET[10:25], SECRET[25:], " keep it safe."]
    g = guard(holdback=60)
    out = await run(g, sse(*pieces), chunk_size)
    text = text_of(out)
    assert SECRET[5:] not in text
    assert "[REDACTED:secret-api-key]" in text
    assert text.endswith(" keep it safe.")
    assert g.blocked is None


async def test_holdback_limits_what_is_released_before_scanning() -> None:
    g = guard(holdback=30, scan_every=1)
    out = b"".join(await g.feed(sse("a" * 100, finish=False)[:-14]))
    assert len(text_of(out)) == 70  # everything except the held-back tail


async def test_blocking_finding_stops_the_stream() -> None:
    canary = "cnry-0123456789abcdef0123"
    g = guard(call=CallContext(canary=canary))
    out = await run(g, sse("The code is ", canary, " ok"), 8)
    assert g.blocked is not None
    assert canary not in text_of(out)
    assert b"[DONE]" not in out


async def test_events_without_content_pass_through_when_nothing_is_held() -> None:
    g = guard()
    out = b"".join(await g.feed(b": keep-alive\n\n"))
    assert out == b": keep-alive\n\n"


async def test_inspections_and_texts_recorded() -> None:
    g = guard(holdback=10)
    await run(g, sse("hello ", "there"), 4)
    assert g.texts == {0: "hello there"}
    assert g.model == "m-1"
    assert [i.verdict.action.value for i in g.inspections] == ["allow"]


def test_parser_handles_crlf_and_partial_events() -> None:
    parser = SSEParser()
    events = parser.feed(b"data: a\r\n\r\ndata: b")
    assert [e.data for e in events] == ["a"]
    assert [e.data for e in parser.flush()] == ["b"]
