"""A fake OpenAI-compatible upstream for local runs and the compose smoke test.

It echoes the last user message back, so a test can check that text flowing through the
gateway is redacted in the event log, and leaks a fake key when asked (``MOCK_LEAK``).
Requests for the model ``sim-obedient`` are answered by scripts/sim_model.py instead: a
simulated model that obeys injected instructions, used as the red-team target's model.
Never point it at real traffic.

Run: uv run uvicorn scripts.mock_upstream:app --port 9000
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from scripts import sim_model

app = FastAPI(title="mock upstream")

MODEL = "mock-model"


# Sending this phrase makes the mock leak a fake secret, so tests can check response
# redaction without putting a secret in the request (which the gateway blocks).
LEAK_TRIGGER = "MOCK_LEAK"
FAKE_LEAKED_KEY = "sk-" + "m" * 40


def _reply(body: dict[str, Any]) -> str:
    for message in reversed(body.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            content = str(message.get("content", ""))
            if LEAK_TRIGGER in content:
                return f"mock reply: the key is {FAKE_LEAKED_KEY} as requested"
            return f"mock reply to: {content}"
    return "mock reply"


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(request: Request) -> JSONResponse | StreamingResponse:
    body = await request.json()
    created = int(time.time())
    if body.get("model") == sim_model.MODEL:
        return _sim_completion(body, created)
    reply = _reply(body)
    if body.get("stream"):

        async def events() -> AsyncIterator[bytes]:
            for word in reply.split(" "):
                chunk = {
                    "id": "chatcmpl-mock",
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": MODEL,
                    "choices": [{"index": 0, "delta": {"content": word + " "}}],
                }
                yield f"data: {json.dumps(chunk)}\n\n".encode()
            yield b"data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    return JSONResponse(
        {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "created": created,
            "model": MODEL,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": reply},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    )


def _sim_completion(body: dict[str, Any], created: int) -> JSONResponse:
    if body.get("stream"):
        error = {"message": "sim-obedient does not stream", "code": "unsupported"}
        return JSONResponse({"error": error}, status_code=400)
    result = sim_model.respond(body)
    return JSONResponse(
        {
            "id": "chatcmpl-sim",
            "object": "chat.completion",
            "created": created,
            "model": sim_model.MODEL,
            "choices": [{"index": 0, **result}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    )
