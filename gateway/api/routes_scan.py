"""Explicit scan endpoints for apps that call the gateway directly (spec section 5).

M2 has ``/v1/scan/text``; ``/v1/scan/document`` and ``/v1/scan/tool-call`` arrive in M3.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask

from gateway.api.deps import ClientPrincipal, ServicesDep
from gateway.api.errors import request_id_of
from gateway.api.events import record
from gateway.core.context import CallContext
from gateway.core.verdict import Role, Verdict
from gateway.storage.repo import EventInput

router = APIRouter()

_DIRECTIONS = {
    Role.USER: "request",
    Role.SYSTEM: "request",
    Role.ASSISTANT: "response",
    Role.RETRIEVED: "document",
    Role.TOOL_RESULT: "document",
}


class ScanTextContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    app: str | None = Field(default=None, max_length=128)
    session: str | None = Field(default=None, max_length=128)
    user: str | None = Field(default=None, max_length=256)
    # Lets assistant text be checked for echoes of the system prompt.
    system_prompt: str | None = None


class ScanTextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    role: Role
    context: ScanTextContext = Field(default_factory=ScanTextContext)


@router.post("/v1/scan/text", response_model=Verdict)
async def scan_text(
    payload: ScanTextRequest, request: Request, principal: ClientPrincipal, services: ServicesDep
) -> JSONResponse:
    """Scan one text and return its verdict. A ``block`` verdict is still HTTP 200: the
    caller asked for an opinion, and decides what to do with it."""
    request_id = request_id_of(request)
    runtime = services.store.current()
    ctx = payload.context
    call = CallContext(
        app=ctx.app, session=ctx.session, key_id=principal.key_id, system_prompt=ctx.system_prompt
    )
    inspection = await runtime.pipeline.inspect(payload.text, payload.role, call, request_id)
    event = EventInput(
        direction=_DIRECTIONS[payload.role],
        role=payload.role,
        text=payload.text,
        verdict=inspection.verdict,
        ruleset_version=runtime.version,
        app=ctx.app,
        user=ctx.user,
        session=ctx.session,
    )
    return JSONResponse(
        inspection.verdict.model_dump(mode="json"),
        background=BackgroundTask(record, services, runtime, [event]),
    )
