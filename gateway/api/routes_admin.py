"""Admin routes: key management and the quarantine review queue. Events, stats, and
policies follow in later milestones."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.api.deps import AdminPrincipal, ServicesDep, SessionDep
from gateway.api.errors import GatewayError
from gateway.core.keys import KeyRole
from gateway.storage import repo
from gateway.storage.models import QuarantineItem

router = APIRouter(prefix="/admin")


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: KeyRole


class CreatedKey(BaseModel):
    id: str
    name: str
    role: KeyRole
    created_at: datetime
    key: str = Field(description="Shown once. Only a hash is stored.")


class RevokedKey(BaseModel):
    id: str
    revoked_at: datetime


@router.post("/keys", status_code=201)
async def create_key(
    payload: CreateKeyRequest, principal: AdminPrincipal, services: ServicesDep, session: SessionDep
) -> CreatedKey:
    row, plaintext = await repo.create_api_key(session, services.hasher, payload.name, payload.role)
    repo.add_audit(session, principal.key_id, "api_key.create", row.id, f"role={payload.role}")
    await session.commit()
    return CreatedKey(
        id=row.id, name=row.name, role=payload.role, created_at=row.created_at, key=plaintext
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
