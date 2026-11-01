"""Admin routes. M1 has key management only; events, stats, quarantine, and policies follow."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

from gateway.api.deps import AdminPrincipal, ServicesDep, SessionDep
from gateway.api.errors import GatewayError
from gateway.core.keys import KeyRole
from gateway.storage import repo

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
