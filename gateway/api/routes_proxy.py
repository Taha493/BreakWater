"""OpenAI-compatible ``/v1/chat/completions`` passthrough with request and response inspection."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.background import BackgroundTask

from gateway.api.deps import ClientPrincipal, Services, ServicesDep
from gateway.api.errors import GatewayError, error_body, request_id_of
from gateway.core.providers import UpstreamError
from gateway.core.sse import SSETextCollector
from gateway.core.verdict import Action, AttackClass, Finding, Role, Verdict
from gateway.storage import repo
from gateway.storage.repo import EventInput

log = logging.getLogger("gateway.proxy")
router = APIRouter()

VERDICT_HEADER = "X-Gateway-Verdict"
_VERDICT_LABELS = {
    Action.ALLOW: "allow",
    Action.REDACT: "redacted",
    Action.BLOCK: "blocked",
    Action.QUARANTINE: "blocked",
}
_BLOCK_CODES = {
    AttackClass.A1: "prompt_injection",
    AttackClass.A2: "prompt_injection",
    AttackClass.A3: "data_leak",
    AttackClass.A4: "tool_denied",
}


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[Any] | None = None


class ChatCompletionRequest(BaseModel):
    """Only the fields the gateway reads. The original body is forwarded unchanged."""

    model_config = ConfigDict(extra="allow")

    model: str | None = None
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False


def message_text(content: str | list[Any] | None) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return ""


def last_user_text(messages: list[ChatMessage]) -> str:
    """The newest user input. Earlier turns were inspected and logged on their own calls.

    M2 extends request inspection to every message role the detectors cover.
    """
    for message in reversed(messages):
        if message.role == "user":
            return message_text(message.content)
    return ""


def completion_text(data: dict[str, Any]) -> str:
    parts: list[str] = []
    for choice in data.get("choices") or []:
        if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
            parts.append(message_text(choice["message"].get("content")))
    return "\n".join(parts)


@dataclass(frozen=True)
class _CallInfo:
    """Attribution shared by the request and response events of one proxied call."""

    ruleset_version: str
    app: str | None
    user: str | None
    session: str | None

    def event(
        self, direction: str, role: Role, text: str, verdict: Verdict, model: str | None
    ) -> EventInput:
        return EventInput(
            direction=direction,
            role=role,
            text=text,
            verdict=verdict,
            ruleset_version=self.ruleset_version,
            app=self.app,
            user=self.user,
            session=self.session,
            upstream_model=model,
        )


def _blocked(verdict: Verdict) -> GatewayError:
    top: Finding | None = max(verdict.findings, key=lambda f: f.score, default=None)
    code = _BLOCK_CODES[top.attack_class] if top else "policy_block"
    return GatewayError(
        403,
        "gateway_blocked",
        code,
        "Blocked by gateway policy",
        findings=verdict.findings,
        headers={VERDICT_HEADER: _VERDICT_LABELS[Action.BLOCK]},
    )


async def _record(services: Services, items: list[EventInput]) -> None:
    try:
        async with services.sessionmaker() as session:
            await repo.record_events(
                session, items, services.hasher, services.settings.store_full_text
            )
    except Exception:
        log.exception("failed to record events", extra={"request_id": items[0].verdict.request_id})


async def _parse_body(request: Request) -> tuple[dict[str, Any], ChatCompletionRequest]:
    try:
        body = json.loads(await request.body())
    except ValueError as exc:
        raise GatewayError(
            400, "invalid_request", "invalid_json", "Body is not valid JSON"
        ) from exc
    if not isinstance(body, dict):
        raise GatewayError(400, "invalid_request", "invalid_json", "Body must be a JSON object")
    try:
        return body, ChatCompletionRequest.model_validate(body)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors()})
        raise GatewayError(
            422,
            "invalid_request",
            "validation_error",
            f"Invalid request body ({', '.join(fields)})",
        ) from exc


@router.post("/v1/chat/completions", response_model=None)
async def chat_completions(
    request: Request,
    principal: ClientPrincipal,
    services: ServicesDep,
    x_gateway_app: Annotated[str | None, Header(max_length=128)] = None,
    x_gateway_user: Annotated[str | None, Header(max_length=256)] = None,
    x_gateway_session: Annotated[str | None, Header(max_length=128)] = None,
) -> JSONResponse | StreamingResponse:
    request_id = request_id_of(request)
    body, parsed = await _parse_body(request)
    pipeline = services.pipeline
    context: dict[str, Any] = {
        "app": x_gateway_app,
        "session": x_gateway_session,
        "key_id": principal.key_id,
    }

    call = _CallInfo(pipeline.policy.version, x_gateway_app, x_gateway_user, x_gateway_session)
    request_text = last_user_text(parsed.messages)
    request_verdict = await pipeline.inspect(request_text, Role.USER, context, request_id)
    request_event = call.event("request", Role.USER, request_text, request_verdict, parsed.model)
    log.info(
        "request inspected",
        extra={
            "request_id": request_id,
            "action": request_verdict.action.value,
            "risk_score": request_verdict.risk_score,
            "latency_ms": round(request_verdict.latency_ms, 3),
            "key_id": principal.key_id,
        },
    )
    if request_verdict.action is not Action.ALLOW:
        await _record(services, [request_event])
        raise _blocked(request_verdict)

    if parsed.stream:
        return await _stream(services, body, call, request_event, context, request_id)

    try:
        data = await services.provider.chat_completion(body)
    except UpstreamError as exc:
        await _record(services, [request_event])
        raise GatewayError(exc.status_code, "upstream_error", exc.code, exc.message) from exc

    response_text = completion_text(data)
    model = data.get("model") if isinstance(data.get("model"), str) else parsed.model
    response_verdict = await pipeline.inspect(response_text, Role.ASSISTANT, context, request_id)
    response_event = call.event("response", Role.ASSISTANT, response_text, response_verdict, model)
    # Until redaction lands in M2, any non-allow response verdict blocks rather than ships.
    if response_verdict.action is not Action.ALLOW:
        await _record(services, [request_event, response_event])
        raise _blocked(response_verdict)

    return JSONResponse(
        data,
        headers={VERDICT_HEADER: _VERDICT_LABELS[Action.ALLOW]},
        background=BackgroundTask(_record, services, [request_event, response_event]),
    )


async def _stream(
    services: Services,
    body: dict[str, Any],
    call: _CallInfo,
    request_event: EventInput,
    context: dict[str, Any],
    request_id: str,
) -> StreamingResponse:
    """Relay the upstream SSE stream. M1 inspects the full text after the stream ends, for the
    event log only; the hold-back scan that can stop a stream mid-way arrives in M2."""
    stack = AsyncExitStack()
    try:
        chunks = await stack.enter_async_context(services.provider.stream_chat_completion(body))
    except UpstreamError as exc:
        await stack.aclose()
        await _record(services, [request_event])
        raise GatewayError(exc.status_code, "upstream_error", exc.code, exc.message) from exc

    collector = SSETextCollector()

    async def relay() -> AsyncIterator[bytes]:
        try:
            async for chunk in chunks:
                collector.feed(chunk)
                yield chunk
        except UpstreamError as exc:
            error = error_body("upstream_error", exc.code, exc.message, request_id)
            # Leading blank line ends any partial event the upstream left behind.
            yield f"\n\ndata: {json.dumps(error)}\n\n".encode()
        finally:
            await stack.aclose()

    async def finish() -> None:
        text = collector.text
        verdict = await services.pipeline.inspect(text, Role.ASSISTANT, context, request_id)
        model = collector.model or request_event.upstream_model
        await _record(
            services, [request_event, call.event("response", Role.ASSISTANT, text, verdict, model)]
        )

    return StreamingResponse(
        relay(),
        media_type="text/event-stream",
        headers={VERDICT_HEADER: _VERDICT_LABELS[Action.ALLOW], "Cache-Control": "no-cache"},
        background=BackgroundTask(finish),
    )
