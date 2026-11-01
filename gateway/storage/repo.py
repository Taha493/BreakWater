"""Database reads and writes. Text is hashed and redacted here, before any row is created."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.keys import KeyRole, generate_key
from gateway.core.redact import Hasher, excerpt
from gateway.core.verdict import Role, Verdict
from gateway.storage.models import ApiKey, AuditLog, Event, Finding, utcnow


async def get_api_key(session: AsyncSession, key_id: str) -> ApiKey | None:
    return await session.get(ApiKey, key_id)


async def has_active_admin_key(session: AsyncSession) -> bool:
    stmt = (
        select(ApiKey.id).where(ApiKey.role == KeyRole.ADMIN, ApiKey.revoked_at.is_(None)).limit(1)
    )
    return (await session.scalar(stmt)) is not None


async def create_api_key(
    session: AsyncSession, hasher: Hasher, name: str, role: KeyRole
) -> tuple[ApiKey, str]:
    """Create a key and return the row plus the plaintext, which is never stored."""
    generated = generate_key()
    row = ApiKey(
        id=generated.key_id,
        name=name,
        role=role.value,
        key_hash=hasher.api_key(generated.plaintext),
        created_at=utcnow(),
    )
    session.add(row)
    return row, generated.plaintext


async def revoke_api_key(session: AsyncSession, key_id: str) -> tuple[ApiKey | None, bool]:
    """Revoke a key. Returns the row (None if unknown) and whether this call revoked it."""
    row = await session.get(ApiKey, key_id)
    if row is None or row.revoked_at is not None:
        return row, False
    row.revoked_at = utcnow()
    return row, True


def add_audit(
    session: AsyncSession, actor: str, action: str, target: str | None, detail: str | None = None
) -> None:
    session.add(AuditLog(actor=actor, action=action, target=target, detail=detail))


@dataclass(frozen=True)
class EventInput:
    """Everything needed to log one inspected item. ``text`` is raw and never stored as-is."""

    direction: str
    role: Role
    text: str
    verdict: Verdict
    ruleset_version: str
    app: str | None = None
    user: str | None = None
    session: str | None = None
    upstream_model: str | None = None


def build_event(item: EventInput, hasher: Hasher, store_full_text: bool) -> Event:
    event = Event(
        request_id=item.verdict.request_id,
        app=item.app,
        user_hash=hasher.user(item.user) if item.user else None,
        session=item.session,
        direction=item.direction,
        role=item.role.value,
        action=item.verdict.action.value,
        risk_score=item.verdict.risk_score,
        latency_ms=item.verdict.latency_ms,
        judge_used=item.verdict.judge_used,
        text_hash=hasher.text(item.text),
        excerpt_redacted=excerpt(item.text),
        full_text=item.text if store_full_text else None,
        upstream_model=item.upstream_model,
        ruleset_version=item.ruleset_version,
    )
    event.findings = [
        Finding(
            detector=f.detector,
            attack_class=f.attack_class.value,
            severity=f.severity.value,
            score=f.score,
            rule_id=f.rule_id,
            reason=f.reason,
            span_start=f.span[0] if f.span else None,
            span_end=f.span[1] if f.span else None,
            layer=f.layer,
        )
        for f in item.verdict.findings
    ]
    return event


async def record_events(
    session: AsyncSession, items: list[EventInput], hasher: Hasher, store_full_text: bool
) -> None:
    session.add_all([build_event(item, hasher, store_full_text) for item in items])
    await session.commit()
