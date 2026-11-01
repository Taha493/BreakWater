"""Explicit scan endpoints for apps that call the gateway directly (spec section 5)."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.background import BackgroundTask

from gateway.api.deps import ClientPrincipal, Services, ServicesDep
from gateway.api.errors import GatewayError, request_id_of
from gateway.api.events import record, record_all
from gateway.core.context import CallContext
from gateway.core.pipeline import allowed, merge
from gateway.core.policy import TrustLevel
from gateway.core.verdict import Action, Finding, Role, Verdict
from gateway.detectors.tool_guard import ToolCall, ToolDecision
from gateway.rag.extract import DocumentFormat, ExtractionError, extract
from gateway.rag.scanner import (
    QUARANTINED,
    VISIBLE,
    ChunkInput,
    chunks_from_extracted,
    persist,
    scan_chunks,
)
from gateway.storage import repo
from gateway.storage.repo import EventInput

router = APIRouter()

EXTRACTION_TIMEOUT_SECONDS = 15.0
MAX_CHUNKS = 500
_UNTRUSTED_ROLES = frozenset({Role.RETRIEVED, Role.TOOL_RESULT})
_DIRECTIONS = {
    Role.USER: "request",
    Role.SYSTEM: "request",
    Role.ASSISTANT: "response",
    Role.RETRIEVED: "document",
    Role.TOOL_RESULT: "document",
}


# ---- /v1/scan/text -------------------------------------------------------------------


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
        app=ctx.app,
        session=ctx.session,
        key_id=principal.key_id,
        system_prompt=ctx.system_prompt,
        max_layer=principal.max_layer,
    )
    inspection = await runtime.pipeline.inspect(payload.text, payload.role, call, request_id)
    event = EventInput(
        direction=_DIRECTIONS[payload.role],
        role=payload.role,
        text=payload.text,
        verdict=inspection.verdict,
        ruleset_version=runtime.scan_version(call.max_layer),
        app=ctx.app,
        user=ctx.user,
        session=ctx.session,
    )
    untrusted = [payload.text] if payload.role in _UNTRUSTED_ROLES else []
    return JSONResponse(
        inspection.verdict.model_dump(mode="json"),
        background=BackgroundTask(record_all, services, runtime, [event], ctx.session, untrusted),
    )


# ---- /v1/scan/document ---------------------------------------------------------------


class ScanDocumentRequest(BaseModel):
    """Exactly one of ``content`` (text, markdown, or HTML), ``content_base64`` (any format),
    or ``chunks`` (the caller's own chunks). Retrieval mode takes chunks."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["ingest", "retrieval"] = "ingest"
    doc_id: str | None = Field(default=None, min_length=1, max_length=256)
    source: str | None = Field(default=None, max_length=512)
    trust_level: TrustLevel = TrustLevel.PUBLIC_WEB
    format: DocumentFormat | None = None
    content: str | None = None
    content_base64: str | None = None
    chunks: list[str] | None = Field(default=None, min_length=1, max_length=MAX_CHUNKS)
    app: str | None = Field(default=None, max_length=128)
    # Retrieved text is recorded for this session's taint check (tool guard).
    session: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def _check_inputs(self) -> ScanDocumentRequest:
        given = [x is not None for x in (self.content, self.content_base64, self.chunks)]
        if sum(given) != 1:
            raise ValueError("give exactly one of content, content_base64, chunks")
        if self.mode == "retrieval" and self.chunks is None:
            raise ValueError("retrieval mode scans chunks")
        if self.mode == "ingest" and self.doc_id is None:
            raise ValueError("ingest mode needs a doc_id")
        binary = self.format in (DocumentFormat.PDF, DocumentFormat.DOCX)
        if self.content is not None and binary:
            raise ValueError("pdf and docx need content_base64")
        if self.content_base64 is not None and self.format is None:
            raise ValueError("content_base64 needs a format")
        return self


class ChunkVerdict(BaseModel):
    index: int
    chunk_id: str | None
    status: str
    allowed: bool
    risk_score: float
    cached: bool
    # "visible", or where the text was found: metadata, alt_text, or a hiding technique
    # such as html_css_hidden or pdf_white_text.
    origin: str
    hidden: bool
    # Only for visible chunks the gateway extracted; hidden text is never returned.
    text: str | None
    findings: list[Finding]


class DocumentVerdict(BaseModel):
    request_id: str
    doc_id: str
    mode: str
    status: str
    risk_score: float
    chunks: list[ChunkVerdict]
    latency_ms: float


async def _document_inputs(payload: ScanDocumentRequest) -> list[ChunkInput]:
    if payload.chunks is not None:
        return [ChunkInput(text) for text in payload.chunks]
    if payload.content_base64 is not None:
        try:
            data = base64.b64decode(payload.content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise GatewayError(
                400, "invalid_request", "invalid_base64", "content_base64 is not valid base64"
            ) from exc
    else:
        data = (payload.content or "").encode()
    fmt = payload.format or DocumentFormat.TEXT
    try:
        extracted = await asyncio.wait_for(
            asyncio.to_thread(extract, data, fmt), EXTRACTION_TIMEOUT_SECONDS
        )
    except ExtractionError as exc:
        raise GatewayError(422, "invalid_request", "extraction_failed", str(exc)) from exc
    except TimeoutError as exc:
        raise GatewayError(
            422, "invalid_request", "extraction_timeout", "Document extraction took too long"
        ) from exc
    return chunks_from_extracted(extracted)


@router.post("/v1/scan/document", response_model=DocumentVerdict)
async def scan_document(
    payload: ScanDocumentRequest,
    request: Request,
    principal: ClientPrincipal,
    services: ServicesDep,
) -> JSONResponse:
    """Scan a document at ingest, or retrieved chunks before they enter a prompt. Chunks at
    or above the trust level's threshold are quarantined: callers must leave out every chunk
    whose ``allowed`` is false."""
    started = time.perf_counter()
    request_id = request_id_of(request)
    runtime = services.store.current()
    inputs = await _document_inputs(payload)
    doc_id = payload.doc_id or "retrieval"
    call = CallContext(
        app=payload.app,
        session=payload.session,
        key_id=principal.key_id,
        max_layer=principal.max_layer,
    )
    content_hash = services.hasher.text("\x00".join(c.text for c in inputs))

    async with services.sessionmaker() as session:
        scan = await scan_chunks(
            runtime, services.hasher, session, inputs, payload.trust_level, call, request_id
        )
        await persist(
            session,
            runtime,
            scan,
            doc_id=doc_id,
            source=payload.source,
            trust=payload.trust_level,
            mode=payload.mode,
            content_hash=content_hash,
        )

    fresh = [c.inspection for c in scan.chunks if c.inspection is not None]
    verdict = merge(request_id, fresh).verdict if fresh else allowed(request_id).verdict
    event = EventInput(
        direction="document",
        role=Role.RETRIEVED,
        text="\n\n".join(c.text for c in scan.chunks if c.origin == VISIBLE),
        verdict=verdict.model_copy(update={"risk_score": scan.risk_score}),
        ruleset_version=runtime.scan_version(call.max_layer),
        app=payload.app,
        session=payload.session,
        action=Action.QUARANTINE.value if scan.status == QUARANTINED else Action.ALLOW.value,
    )
    body = DocumentVerdict(
        request_id=request_id,
        doc_id=doc_id,
        mode=payload.mode,
        status=scan.status,
        risk_score=scan.risk_score,
        chunks=[
            ChunkVerdict(
                index=c.index,
                chunk_id=c.chunk_id,
                status=c.status,
                allowed=c.allowed,
                risk_score=c.risk_score,
                cached=c.cached,
                origin=c.origin,
                hidden=c.origin != VISIBLE,
                text=c.text if c.returnable and c.allowed else None,
                findings=c.findings,
            )
            for c in scan.chunks
        ],
        latency_ms=(time.perf_counter() - started) * 1000,
    )
    taint = [c.text for c in scan.chunks] if payload.session else []
    return JSONResponse(
        body.model_dump(mode="json"),
        background=BackgroundTask(record_all, services, runtime, [event], payload.session, taint),
    )


# ---- /v1/scan/tool-call --------------------------------------------------------------


class ScanToolCallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    triggering_text: str | None = None
    # Needed for the taint check and per-session rate limits; X-Gateway-Session also works.
    session: str | None = Field(default=None, max_length=128)


class ToolCallVerdict(BaseModel):
    request_id: str
    decision: ToolDecision
    rule_id: str
    reason: str
    findings: list[Finding]
    latency_ms: float


class _DbGuardState:
    def __init__(self, services: Services) -> None:
        self._services = services

    async def tainted(self, session: str, fingerprints: set[str]) -> set[str]:
        async with self._services.sessionmaker() as db:
            return await repo.tainted(db, session, fingerprints)

    async def recent_calls(self, agent_id: str, session: str | None) -> tuple[int, int]:
        async with self._services.sessionmaker() as db:
            return await repo.recent_tool_calls(db, agent_id, session)


_EVENT_ACTIONS = {
    ToolDecision.ALLOW: "allow",
    ToolDecision.DENY: "block",
    ToolDecision.REQUIRE_CONFIRMATION: "require_confirmation",
}


@router.post("/v1/scan/tool-call", response_model=ToolCallVerdict)
async def scan_tool_call(
    payload: ScanToolCallRequest,
    request: Request,
    principal: ClientPrincipal,
    services: ServicesDep,
    x_gateway_session: Annotated[str | None, Header(max_length=128)] = None,
) -> ToolCallVerdict:
    """Check a proposed agent tool call before it runs. Decisions are HTTP 200."""
    started = time.perf_counter()
    request_id = request_id_of(request)
    runtime = services.store.current()
    session = payload.session or x_gateway_session
    call = ToolCall(
        agent_id=payload.agent_id,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
        session=session,
        triggering_text=payload.triggering_text,
        max_layer=principal.max_layer,
    )
    check = await runtime.tool_guard.check(
        call, _DbGuardState(services), services.hasher, runtime.pipeline, request_id
    )
    denied = check.decision is ToolDecision.DENY
    verdict = Verdict(
        request_id=request_id,
        action=Action.BLOCK if denied else Action.ALLOW,
        risk_score=max((f.score for f in check.findings), default=0.0),
        findings=check.findings,
        latency_ms=(time.perf_counter() - started) * 1000,
    )
    # Recorded before responding: the per-minute rate limits count these events.
    await record(
        services,
        runtime,
        [
            EventInput(
                direction="tool_call",
                role="tool_call",
                text=json.dumps(
                    {"tool": payload.tool_name, "arguments": payload.arguments}, default=str
                ),
                verdict=verdict,
                ruleset_version=runtime.scan_version(call.max_layer),
                app=payload.agent_id,
                session=session,
                action=_EVENT_ACTIONS[check.decision],
            )
        ],
    )
    return ToolCallVerdict(
        request_id=request_id,
        decision=check.decision,
        rule_id=check.rule_id,
        reason=check.reason,
        findings=check.findings,
        latency_ms=verdict.latency_ms,
    )
