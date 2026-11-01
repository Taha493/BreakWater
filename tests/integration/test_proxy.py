from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator

import httpx
import respx
from fastapi import FastAPI

from breakwater.core.context import ScanContext
from breakwater.core.sse import SSEParser
from breakwater.core.verdict import AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector
from tests.conftest import UPSTREAM_KEY, chat_body, completion, pin_runtime, runtime_with


async def test_allowed_request_passes_through(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str], client_key: str
) -> None:
    route = upstream.post("/chat/completions").respond(200, json=completion("Paris."))
    body = chat_body("What is the capital of France?", temperature=0.2)

    response = await client.post("/v1/chat/completions", json=body, headers=auth)

    assert response.status_code == 200
    assert response.json() == completion("Paris.")
    assert response.headers["X-Gateway-Verdict"] == "allow"
    uuid.UUID(response.headers["X-Gateway-Request-Id"])
    sent = route.calls.last.request
    assert json.loads(sent.content) == body
    assert sent.url == "http://upstream.test/v1/chat/completions"
    # The upstream sees the server's provider key, never the client's gateway key.
    assert sent.headers["Authorization"] == f"Bearer {UPSTREAM_KEY}"
    assert client_key not in sent.headers.get("Authorization", "")


async def test_multimodal_content_parts_accepted(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("ok"))
    body = {
        "model": "m",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "describe"}]}],
    }
    response = await client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 200


def stream_text(raw: bytes) -> str:
    text = ""
    for event in SSEParser().feed(raw):
        if event.data and event.data != "[DONE]":
            for choice in json.loads(event.data).get("choices", []):
                text += (choice.get("delta") or {}).get("content") or ""
    return text


def _sse(*words: str) -> bytes:
    out = b""
    for word in words:
        chunk = {"model": "test-model", "choices": [{"index": 0, "delta": {"content": word}}]}
        out += f"data: {json.dumps(chunk)}\n\n".encode()
    return out + b"data: [DONE]\n\n"


async def test_streaming_passthrough(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    raw = _sse("Hel", "lo", "!")
    upstream.post("/chat/completions").respond(
        200, content=raw, headers={"Content-Type": "text/event-stream"}
    )
    response = await client.post(
        "/v1/chat/completions", json=chat_body("hi", stream=True), headers=auth
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["X-Gateway-Verdict"] == "allow"
    # The hold-back guard re-frames content events, so compare text, not bytes.
    assert stream_text(response.content) == "Hello!"
    assert response.content.endswith(b"data: [DONE]\n\n")


async def test_stream_upstream_failure_mid_stream_ends_with_error_event(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    async def broken() -> AsyncIterator[bytes]:
        yield _sse("partial")[:60]
        raise httpx.ReadTimeout("boom")

    upstream.post("/chat/completions").mock(
        return_value=httpx.Response(
            200, content=broken(), headers={"Content-Type": "text/event-stream"}
        )
    )
    response = await client.post(
        "/v1/chat/completions", json=chat_body("hi", stream=True), headers=auth
    )
    last = response.text.strip().split("\n\n")[-1]
    assert last.startswith("data: ")
    error = json.loads(last.removeprefix("data: "))["error"]
    assert error["type"] == "upstream_error"
    assert error["code"] == "upstream_timeout"
    assert error["request_id"] == response.headers["X-Gateway-Request-Id"]


async def test_stream_upstream_status_error_before_stream(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(503, json={"error": {"message": "overloaded"}})
    response = await client.post(
        "/v1/chat/completions", json=chat_body("hi", stream=True), headers=auth
    )
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_status_503"


async def test_upstream_error_status(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(500, json={"error": {"message": "internal"}})
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 502
    error = response.json()["error"]
    assert error["type"] == "upstream_error"
    assert error["code"] == "upstream_status_500"
    assert error["request_id"] == response.headers["X-Gateway-Request-Id"]
    assert error["findings"] == []


async def test_upstream_error_message_is_redacted(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    leaked = "sk-" + "q" * 40
    upstream.post("/chat/completions").respond(
        400, json={"error": {"message": f"Incorrect API key provided: {leaked}"}}
    )
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 502
    message = response.json()["error"]["message"]
    assert "HTTP 400" in message
    assert leaked not in message
    assert "[REDACTED:secret-api-key]" in message


async def test_upstream_timeout(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").mock(side_effect=httpx.ReadTimeout("slow"))
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "upstream_timeout"


async def test_upstream_unreachable(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").mock(side_effect=httpx.ConnectError("refused"))
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unreachable"


async def test_upstream_invalid_json(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(200, content=b"<html>oops</html>")
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_invalid_response"


async def test_invalid_json_body(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    route = upstream.post("/chat/completions")
    response = await client.post(
        "/v1/chat/completions",
        content=b"{not json",
        headers={**auth, "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"
    assert not route.called


async def test_missing_messages_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    route = upstream.post("/chat/completions")
    for body in ({"model": "m"}, {"model": "m", "messages": []}, [1, 2]):
        response = await client.post("/v1/chat/completions", json=body, headers=auth)
        assert response.status_code in (400, 422)
        assert response.json()["error"]["type"] == "invalid_request"
    assert not route.called


async def test_oversized_body_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    route = upstream.post("/chat/completions")
    body = chat_body("a" * 1_100_000)
    response = await client.post("/v1/chat/completions", json=body, headers=auth)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "body_too_large"
    assert response.headers["X-Gateway-Request-Id"]
    assert not route.called


async def test_oversized_chunked_body_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    route = upstream.post("/chat/completions")

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(20):
            yield b"x" * 100_000

    response = await client.post(
        "/v1/chat/completions",
        content=chunks(),
        headers={**auth, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert not route.called


async def test_header_too_long_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("ok"))
    response = await client.post(
        "/v1/chat/completions",
        json=chat_body("hi"),
        headers={**auth, "X-Gateway-App": "a" * 500},
    )
    assert response.status_code == 422
    assert response.json()["error"]["type"] == "invalid_request"


class _Trigger(Detector):
    """Flags any text containing TRIGGER, standing in for the M2 detectors."""

    name = "test_trigger"
    layer = 1
    roles = frozenset({Role.USER, Role.ASSISTANT})

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        index = text.find("TRIGGER")
        if index < 0:
            return []
        attack = AttackClass.A1 if role is Role.USER else AttackClass.A3
        return [
            Finding(
                detector=self.name,
                attack_class=attack,
                severity=Severity.CRITICAL,
                score=0.95,
                reason="test trigger",
                rule_id="test-001",
                span=(index, index + 7),
                layer=1,
            )
        ]


def install_trigger(app: FastAPI) -> None:
    pin_runtime(app, runtime_with(_Trigger()))


async def test_blocked_request_never_reaches_upstream(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    install_trigger(app)
    route = upstream.post("/chat/completions").respond(200, json=completion("ok"))
    response = await client.post(
        "/v1/chat/completions", json=chat_body("please TRIGGER now"), headers=auth
    )
    assert response.status_code == 403
    assert response.headers["X-Gateway-Verdict"] == "blocked"
    error = response.json()["error"]
    assert error["type"] == "gateway_blocked"
    assert error["code"] == "prompt_injection"
    assert error["findings"][0]["rule_id"] == "test-001"
    assert error["findings"][0]["span"] == [7, 14]
    assert "TRIGGER" not in json.dumps(error)
    assert not route.called


async def test_flagged_response_is_redacted(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    # An A3 finding on assistant text takes the A3.assistant action: redact.
    install_trigger(app)
    upstream.post("/chat/completions").respond(200, json=completion("here: TRIGGER ok"))
    response = await client.post("/v1/chat/completions", json=chat_body("hi"), headers=auth)
    assert response.status_code == 200
    assert response.headers["X-Gateway-Verdict"] == "redacted"
    content = response.json()["choices"][0]["message"]["content"]
    assert content == "here: [REDACTED:test-001] ok"


async def test_unknown_route_uses_error_format(client: httpx.AsyncClient) -> None:
    response = await client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"]["type"] == "invalid_request"
    assert response.json()["error"]["request_id"] == response.headers["X-Gateway-Request-Id"]
