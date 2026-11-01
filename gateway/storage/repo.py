"""Database reads and writes. Text is hashed and redacted here, before any row is created."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from gateway.core.keys import KeyRole, generate_key
from gateway.core.redact import Hasher, Redactor
from gateway.core.verdict import Role, Verdict
from gateway.storage.models import (
    ApiKey,
    AuditLog,
    Chunk,
    Event,
    Finding,
    QuarantineItem,
    RedteamResult,
    RedteamRun,
    TaintMark,
    utcnow,
)


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
    role: Role | str  # a Role, or "tool_call" for tool guard events
    text: str
    verdict: Verdict
    ruleset_version: str
    app: str | None = None
    user: str | None = None
    session: str | None = None
    upstream_model: str | None = None
    # Overrides the verdict's action, for decisions outside the Action enum
    # (the tool guard's "require_confirmation").
    action: str | None = None


def build_event(
    item: EventInput, hasher: Hasher, redactor: Redactor, store_full_text: bool
) -> Event:
    event = Event(
        request_id=item.verdict.request_id,
        app=item.app,
        user_hash=hasher.user(item.user) if item.user else None,
        session=item.session,
        direction=item.direction,
        role=str(item.role),
        action=item.action or item.verdict.action.value,
        risk_score=item.verdict.risk_score,
        latency_ms=item.verdict.latency_ms,
        judge_used=item.verdict.judge_used,
        text_hash=hasher.text(item.text),
        excerpt_redacted=redactor.excerpt(item.text),
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
            message_index=f.message_index,
        )
        for f in item.verdict.findings
    ]
    return event


async def record_events(
    session: AsyncSession,
    items: list[EventInput],
    hasher: Hasher,
    redactor: Redactor,
    store_full_text: bool,
) -> None:
    session.add_all([build_event(item, hasher, redactor, store_full_text) for item in items])
    await session.commit()


# ---- documents, chunks, quarantine ---------------------------------------------------


@dataclass(frozen=True)
class CachedChunk:
    chunk_id: str
    status: str
    risk_score: float


def _batches(values: list[str], size: int = 500) -> list[list[str]]:
    return [values[i : i + size] for i in range(0, len(values), size)]


async def cached_chunks(
    session: AsyncSession, text_hashes: list[str], ruleset_version: str
) -> dict[str, CachedChunk]:
    """The newest scan of each text under this ruleset. A chunk a reviewer released stays
    released for that exact content under any ruleset (spec section 7, quarantine)."""
    found: dict[str, CachedChunk] = {}
    released: dict[str, CachedChunk] = {}
    for batch in _batches(sorted(set(text_hashes))):
        stmt = (
            select(Chunk)
            .where(
                Chunk.text_hash.in_(batch),
                or_(Chunk.ruleset_version == ruleset_version, Chunk.status == "released"),
            )
            .order_by(Chunk.created_at)
        )
        for row in await session.scalars(stmt):
            entry = CachedChunk(row.id, row.status, row.risk_score)
            if row.status == "released":
                released[row.text_hash] = entry
            elif row.ruleset_version == ruleset_version:
                found[row.text_hash] = entry
    return {**found, **released}


async def list_quarantine(
    session: AsyncSession, pending_only: bool, limit: int
) -> list[QuarantineItem]:
    stmt = (
        select(QuarantineItem)
        .options(selectinload(QuarantineItem.chunk), selectinload(QuarantineItem.document))
        .order_by(QuarantineItem.created_at.desc())
        .limit(limit)
    )
    if pending_only:
        stmt = stmt.where(QuarantineItem.decision.is_(None))
    return list(await session.scalars(stmt))


async def review_quarantine(
    session: AsyncSession, item_id: str, actor: str, decision: str
) -> QuarantineItem | None:
    item = await session.get(
        QuarantineItem,
        item_id,
        options=[selectinload(QuarantineItem.chunk), selectinload(QuarantineItem.document)],
    )
    if item is None:
        return None
    item.decision = decision
    item.reviewed_by = actor
    item.reviewed_at = utcnow()
    item.chunk.status = "released" if decision == "released" else "quarantined"
    add_audit(session, actor, f"quarantine.{decision}", item.id, f"chunk={item.chunk_id}")
    return item


# ---- tool guard state ----------------------------------------------------------------


async def record_taint(
    session: AsyncSession, session_hash: str, fingerprints: set[str], ttl_seconds: int
) -> None:
    now = utcnow()
    await session.execute(delete(TaintMark).where(TaintMark.expires_at < now))
    expires = now + timedelta(seconds=ttl_seconds)
    known: set[str] = set()
    for batch in _batches(sorted(fingerprints)):
        stmt = select(TaintMark).where(
            TaintMark.session_hash == session_hash, TaintMark.fingerprint.in_(batch)
        )
        for mark in await session.scalars(stmt):
            mark.expires_at = expires
            known.add(mark.fingerprint)
    session.add_all(
        TaintMark(session_hash=session_hash, fingerprint=fp, expires_at=expires)
        for fp in fingerprints - known
    )
    await session.commit()


async def tainted(session: AsyncSession, session_hash: str, fingerprints: set[str]) -> set[str]:
    hits: set[str] = set()
    now = utcnow()
    for batch in _batches(sorted(fingerprints)):
        stmt = select(TaintMark.fingerprint).where(
            TaintMark.session_hash == session_hash,
            TaintMark.fingerprint.in_(batch),
            TaintMark.expires_at >= now,
        )
        hits.update(await session.scalars(stmt))
    return hits


async def recent_tool_calls(
    session: AsyncSession, agent_id: str, session_id: str | None, seconds: int = 60
) -> tuple[int, int]:
    """Tool calls in the last ``seconds`` for the agent, and for the agent's session."""
    since = utcnow() - timedelta(seconds=seconds)
    base = (
        select(func.count())
        .select_from(Event)
        .where(Event.direction == "tool_call", Event.app == agent_id, Event.ts >= since)
    )
    agent_count = int(await session.scalar(base) or 0)
    session_count = 0
    if session_id is not None:
        session_count = int(await session.scalar(base.where(Event.session == session_id)) or 0)
    return agent_count, session_count


async def list_redteam_runs(session: AsyncSession, limit: int) -> list[RedteamRun]:
    rows = await session.scalars(
        select(RedteamRun).order_by(RedteamRun.started_at.desc()).limit(limit)
    )
    return list(rows)


async def redteam_results(session: AsyncSession, run_id: str) -> list[RedteamResult]:
    rows = await session.scalars(
        select(RedteamResult).where(RedteamResult.run_id == run_id).order_by(RedteamResult.position)
    )
    return list(rows)
