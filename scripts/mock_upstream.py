"""A fake OpenAI-compatible upstream for local runs and the compose smoke test.

It echoes the last user message back, so a test can check that text flowing through the
gateway is redacted in the event log. Never point it at real traffic.

Run: uv run uvicorn scripts.mock_upstream:app --port 9000
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="mock upstream")

MODEL = "mock-model"


def _reply(body: dict[str, Any]) -> str:
    for message in reversed(body.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            return f"mock reply to: {message.get('content', '')}"
    return "mock reply"


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/chat/completions", response_model=None)
async def chat_completions(request: Request) -> JSONResponse | StreamingResponse:
    body = await request.json()
    reply = _reply(body)
    created = int(time.time())
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
