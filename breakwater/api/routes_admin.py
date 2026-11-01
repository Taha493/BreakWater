"""Admin routes (spec sections 5 and 10): keys, the quarantine review queue, the stats,
events, and documents behind the dashboard, and versioned policies."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from breakwater.api.deps import AdminPrincipal, Services, ServicesDep, SessionDep
from breakwater.api.errors import GatewayError
from breakwater.core.keys import KeyRole
from breakwater.core.pipeline import MAX_LAYER
from breakwater.storage import queries, repo
from breakwater.storage.models import Event, PolicyVersion, QuarantineItem

router = APIRouter(prefix="/admin")


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: KeyRole
    # Client keys only: run detection layers up to this one (1 rules, 2 classifier,
    # 3 judge). For comparing layers in red-team runs; leave unset in production.
    max_layer: int | None = Field(default=None, ge=1, le=MAX_LAYER)

    @model_validator(mode="after")
    def _client_only(self) -> CreateKeyRequest:
        if self.max_layer is not None and self.role is not KeyRole.CLIENT:
            raise ValueError("max_layer applies to client keys only")
        return self


class CreatedKey(BaseModel):
    id: str
    name: str
    role: KeyRole
    max_layer: int | None = None
    created_at: datetime
    key: str = Field(description="Shown once. Only a hash is stored.")


class RevokedKey(BaseModel):
    id: str
    revoked_at: datetime


@router.post("/keys", status_code=201)
async def create_key(
    payload: CreateKeyRequest, principal: AdminPrincipal, services: ServicesDep, session: SessionDep
) -> CreatedKey:
    row, plaintext = await repo.create_api_key(
        session, services.hasher, payload.name, payload.role, payload.max_layer
    )
    detail = f"role={payload.role}"
    if payload.max_layer is not None:
        detail += f" max_layer={payload.max_layer}"
    repo.add_audit(session, principal.key_id, "api_key.create", row.id, detail)
    await session.commit()
    return CreatedKey(
        id=row.id,
        name=row.name,
        role=payload.role,
        max_layer=row.max_layer,
        created_at=row.created_at,
        key=plaintext,
    )


@router.post("/keys/{key_id}/revoke")
async def revoke_key(key_id: str, principal: AdminPrincipal, session: SessionDep) -> RevokedKey:
    row, changed = await repo.revoke_api_key(session, key_id)
    if row is None or row.revoked_at is None:
        raise GatewayError(404, "invalid_request", "key_not_found", "No such API key")
    if changed:
        repo.add_audit(session, principal.key_id, "api_key.revoke", row.id)
        await session.commit()
    return RevokedKey(id=row.id, revoked_at=row.revoked_at)


# ---- quarantine ----------------------------------------------------------------------


class QuarantineEntry(BaseModel):
    id: str
    doc_id: str
    source: str | None
    trust_level: str
    chunk_id: str
    chunk_index: int
    hidden_kind: str | None
    risk_score: float
    reason: str
    excerpt_redacted: str
    created_at: datetime
    decision: str | None
    reviewed_by: str | None
    reviewed_at: datetime | None


def _entry(item: QuarantineItem) -> QuarantineEntry:
    return QuarantineEntry(
        id=item.id,
        doc_id=item.document.doc_id,
        source=item.document.source,
        trust_level=item.document.trust_level,
        chunk_id=item.chunk_id,
        chunk_index=item.chunk.idx,
        hidden_kind=item.chunk.hidden_kind,
        risk_score=item.chunk.risk_score,
        reason=item.reason,
        excerpt_redacted=item.chunk.excerpt_redacted,
        created_at=item.created_at,
        decision=item.decision,
        reviewed_by=item.reviewed_by,
        reviewed_at=item.reviewed_at,
    )


@router.get("/quarantine")
async def list_quarantine(
    principal: AdminPrincipal,
    session: SessionDep,
    status: Literal["pending", "all"] = "pending",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[QuarantineEntry]:
    items = await repo.list_quarantine(session, pending_only=status == "pending", limit=limit)
    return [_entry(item) for item in items]


async def _review(
    item_id: str, actor: str, decision: str, session: AsyncSession
) -> QuarantineEntry:
    item = await repo.review_quarantine(session, item_id, actor, decision)
    if item is None:
        raise GatewayError(
            404, "invalid_request", "quarantine_not_found", "No such quarantine item"
        )
    await session.commit()
    return _entry(item)


@router.post("/quarantine/{item_id}/release")
async def release_quarantine(
    item_id: str, principal: AdminPrincipal, session: SessionDep
) -> QuarantineEntry:
    """Mark a quarantined chunk as reviewed and safe: that exact content is allowed at
    retrieval from now on."""
    return await _review(item_id, principal.key_id, "released", session)


@router.post("/quarantine/{item_id}/keep")
async def keep_quarantine(
    item_id: str, principal: AdminPrincipal, session: SessionDep
) -> QuarantineEntry:
    """Record that a reviewer confirmed the quarantine."""
    return await _review(item_id, principal.key_id, "kept", session)


# ---- stats, events, documents (dashboard) ----------------------------------------------


@router.get("/stats")
async def get_stats(
    principal: AdminPrincipal,
    session: SessionDep,
    range: Literal["1h", "24h", "7d", "30d"] = "24h",
    app: Annotated[str | None, Query(max_length=128)] = None,
) -> dict[str, Any]:
    """Counts, block rate, gateway latency, and blocked/redacted events over time by attack
    class, for the overview page."""
    return await queries.stats(session, range, app)


class FindingOut(BaseModel):
    detector: str
    attack_class: str
    severity: str
    score: float
    rule_id: str | None
    reason: str
    span: tuple[int, int] | None
    layer: int
    message_index: int | None


class EventOut(BaseModel):
    id: str
    request_id: str
    ts: datetime
    app: str | None
    session: str | None
    direction: str
    role: str
    action: str
    risk_score: float
    latency_ms: float
    judge_used: bool
    upstream_model: str | None
    ruleset_version: str
    attack_classes: list[str]
    detectors: list[str]
    # Secrets and PII were redacted before storage; the dashboard still renders it as text.
    excerpt_redacted: str


class EventDetail(EventOut):
    findings: list[FindingOut]


class EventPage(BaseModel):
    events: list[EventOut]
    next_cursor: str | None


def _event_fields(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "request_id": event.request_id,
        "ts": event.ts,
        "app": event.app,
        "session": event.session,
        "direction": event.direction,
        "role": event.role,
        "action": event.action,
        "risk_score": event.risk_score,
        "latency_ms": event.latency_ms,
        "judge_used": event.judge_used,
        "upstream_model": event.upstream_model,
        "ruleset_version": event.ruleset_version,
        "attack_classes": sorted({f.attack_class for f in event.findings}),
        "detectors": sorted({f.detector for f in event.findings}),
        "excerpt_redacted": event.excerpt_redacted,
    }


@router.get("/events")
async def list_events(
    principal: AdminPrincipal,
    session: SessionDep,
    since: datetime | None = None,
    until: datetime | None = None,
    range: Literal["1h", "24h", "7d", "30d"] | None = None,
    app: Annotated[str | None, Query(max_length=128)] = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    direction: Annotated[str | None, Query(max_length=16)] = None,
    attack_class: Literal["A1", "A2", "A3", "A4"] | None = None,
    detector: Annotated[str | None, Query(max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[str | None, Query(max_length=128)] = None,
) -> EventPage:
    """Newest first. ``range`` is a shortcut for ``since`` (now minus the range)."""
    if range is not None and since is None:
        since = datetime.now(UTC) - timedelta(seconds=queries.RANGES[range][0])
    for value in (since, until):
        if value is not None and value.tzinfo is None:
            raise GatewayError(
                422, "invalid_request", "naive_datetime", "since and until need a time zone"
            )
    filters = queries.EventFilter(since, until, app, action, direction, attack_class, detector)
    try:
        events, next_cursor = await queries.list_events(session, filters, limit, cursor)
    except ValueError as exc:
        raise GatewayError(422, "invalid_request", "invalid_cursor", "Invalid cursor") from exc
    return EventPage(events=[EventOut(**_event_fields(e)) for e in events], next_cursor=next_cursor)


@router.get("/events/{event_id}")
async def get_event(event_id: str, principal: AdminPrincipal, session: SessionDep) -> EventDetail:
    event = await queries.get_event(session, event_id)
    if event is None:
        raise GatewayError(404, "invalid_request", "event_not_found", "No such event")
    findings = [
        FindingOut(
            detector=f.detector,
            attack_class=f.attack_class,
            severity=f.severity,
            score=f.score,
            rule_id=f.rule_id,
            reason=f.reason,
            span=(f.span_start, f.span_end)
            if f.span_start is not None and f.span_end is not None
            else None,
            layer=f.layer,
            message_index=f.message_index,
        )
        for f in sorted(event.findings, key=lambda f: (f.layer, -f.score))
    ]
    return EventDetail(**_event_fields(event), findings=findings)


@router.get("/documents")
async def list_documents(
    principal: AdminPrincipal,
    session: SessionDep,
    status: Literal["clean", "suspicious", "quarantined"] | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
) -> dict[str, Any]:
    """Ingested documents: counts by status, the riskiest, and the most recent."""
    return await queries.documents(session, status, limit)


# ---- policies --------------------------------------------------------------------------

MAX_POLICY_BYTES = 64 * 1024


class PolicyVersionInfo(BaseModel):
    id: int
    created_at: datetime
    created_by: str
    comment: str | None
    active: bool


class PolicyVersionOut(PolicyVersionInfo):
    content: str


class ActivePolicy(PolicyVersionOut):
    ruleset_version: str
    config: dict[str, Any]


class UpdatePolicy(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_POLICY_BYTES)
    comment: str | None = Field(default=None, max_length=256)


def _version(row: PolicyVersion) -> dict[str, Any]:
    return {
        "id": row.id,
        "created_at": row.created_at,
        "created_by": row.created_by,
        "comment": row.comment,
        "active": row.active,
    }


async def _active(services: Services, session: AsyncSession) -> ActivePolicy:
    row = await repo.active_policy(session)
    if row is None:
        raise GatewayError(503, "server_error", "no_active_policy", "No active policy yet")
    runtime = services.store.current()
    return ActivePolicy(
        **_version(row),
        content=row.content,
        ruleset_version=runtime.version,
        config=runtime.policy.config.model_dump(mode="json"),
    )


@router.get("/policies")
async def get_policy(
    principal: AdminPrincipal, services: ServicesDep, session: SessionDep
) -> ActivePolicy:
    """The active policy: its YAML, the parsed configuration, and its version."""
    return await _active(services, session)


@router.put("/policies")
async def update_policy(
    payload: UpdatePolicy, principal: AdminPrincipal, services: ServicesDep, session: SessionDep
) -> ActivePolicy:
    """Validate and activate a new policy version. It applies to this process at once and to
    the others within CONFIG_RELOAD_SECONDS."""
    raw = payload.content.encode("utf-8")
    try:
        services.store.check_policy(raw)
    except Exception as exc:
        raise GatewayError(
            422, "invalid_request", "invalid_policy", f"Invalid policy: {exc}"[:2000]
        ) from exc
    row = await repo.add_policy_version(session, payload.content, principal.key_id, payload.comment)
    repo.add_audit(session, principal.key_id, "policy.update", str(row.id), payload.comment)
    await session.commit()
    services.store.set_policy(raw, row.id)
    return await _active(services, session)


@router.get("/policies/versions")
async def list_policy_versions(
    principal: AdminPrincipal,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[PolicyVersionInfo]:
    rows = await repo.list_policy_versions(session, limit)
    return [PolicyVersionInfo(**_version(r)) for r in rows]


@router.get("/policies/versions/{version_id}")
async def get_policy_version(
    version_id: int, principal: AdminPrincipal, session: SessionDep
) -> PolicyVersionOut:
    row = await session.get(PolicyVersion, version_id)
    if row is None:
        raise GatewayError(404, "invalid_request", "policy_not_found", "No such policy version")
    return PolicyVersionOut(**_version(row), content=row.content)


@router.post("/policies/versions/{version_id}/activate")
async def activate_policy_version(
    version_id: int, principal: AdminPrincipal, services: ServicesDep, session: SessionDep
) -> ActivePolicy:
    """Roll back (or forward) to an earlier version."""
    row = await session.get(PolicyVersion, version_id)
    if row is None:
        raise GatewayError(404, "invalid_request", "policy_not_found", "No such policy version")
    raw = row.content.encode("utf-8")
    try:
        services.store.check_policy(raw)
    except Exception as exc:
        raise GatewayError(
            422, "invalid_request", "invalid_policy", f"Version no longer loads: {exc}"[:2000]
        ) from exc
    await repo.activate_policy_version(session, version_id)
    repo.add_audit(session, principal.key_id, "policy.activate", str(version_id))
    await session.commit()
    services.store.set_policy(raw, version_id)
    return await _active(services, session)
