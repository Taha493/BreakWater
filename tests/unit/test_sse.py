from __future__ import annotations

import json

from gateway.core.sse import SSETextCollector


def _stream(*words: str) -> bytes:
    out = b""
    for word in words:
        chunk = {"model": "m1", "choices": [{"index": 0, "delta": {"content": word}}]}
        out += f"data: {json.dumps(chunk)}\n\n".encode()
    return out + b"data: [DONE]\n\n"


def test_collects_text() -> None:
    c = SSETextCollector()
    c.feed(_stream("Hello", ", ", "world"))
    assert c.text == "Hello, world"
    assert c.model == "m1"


def test_any_chunking_gives_same_text() -> None:
    raw = _stream("héllo ", "wörld ", "😀")
    c = SSETextCollector()
    for i in range(len(raw)):
        c.feed(raw[i : i + 1])
    assert c.text == "héllo wörld 😀"


def test_crlf_lines() -> None:
    c = SSETextCollector()
    c.feed(_stream("a", "b").replace(b"\n", b"\r\n"))
    assert c.text == "ab"


def test_ignores_malformed_and_non_data_lines() -> None:
    c = SSETextCollector()
    c.feed(b": keepalive\n\nevent: ping\ndata: {not json\n\ndata: [1, 2]\n\n")
    c.feed(b'data: {"choices": [{"delta": {"role": "assistant"}}, "bad"]}\n\n')
    c.feed(_stream("ok"))
    assert c.text == "ok"


def test_caps_collected_text() -> None:
    c = SSETextCollector(max_chars=5)
    c.feed(_stream("abc", "def", "ghi"))
    assert c.text == "abcde"
    assert c.truncated
