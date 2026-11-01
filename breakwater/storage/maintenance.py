"""Retention and per-user data requests (spec section 9).

- ``cleanup`` deletes what is past ``RETENTION_DAYS``: events and their findings, red-team
  transcripts (run summaries stay), expired taint marks, and retrieval-scan records without
  a quarantine item. Quarantine items, ingested documents, and red-team runs are kept until
  an admin deletes them.
- ``export_user`` and ``delete_user`` act on everything stored for one ``user_hash``. Only
  events carry a user; what they hold is already hashed and redacted.

Child rows are deleted explicitly rather than relying on ON DELETE CASCADE, which SQLite
enforces only when foreign keys are switched on.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from breakwater.storage.models import (
    Chunk,
    Document,
    Event,
    Finding,
    QuarantineItem,
    RedteamResult,
    TaintMark,
    utcnow,
)


async def cleanup(
    session: AsyncSession, retention_days: int, now: datetime | None = None
) -> dict[str, int]:
    """Delete data older than the retention period. Returns rows deleted per table."""
    now = now or utcnow()
    cutoff = now - timedelta(days=retention_days)
    old_events = select(Event.id).where(Event.ts < cutoff)
    old_retrievals = select(Document.id).where(
        Document.scan_mode == "retrieval",
        Document.created_at < cutoff,
        ~exists().where(QuarantineItem.document_id == Document.id),
    )
    counts = {
        "findings": await _delete(session, delete(Finding).where(Finding.event_id.in_(old_events))),
        "events": await _delete(session, delete(Event).where(Event.ts < cutoff)),
        "redteam_results": await _delete(
            session, delete(RedteamResult).where(RedteamResult.created_at < cutoff)
        ),
        "taint": await _delete(session, delete(TaintMark).where(TaintMark.expires_at < now)),
        "chunks": await _delete(
            session, delete(Chunk).where(Chunk.document_id.in_(old_retrievals))
        ),
    }
    counts["documents"] = await _delete(
        session, delete(Document).where(Document.id.in_(old_retrievals))
    )
    return counts


async def _delete(session: AsyncSession, statement: Any) -> int:
    result = await session.execute(statement.execution_options(synchronize_session=False))
    return int(getattr(result, "rowcount", 0) or 0)


async def export_user(session: AsyncSession, user_hash: str) -> dict[str, Any]:
    events = await session.scalars(
        select(Event)
        .where(Event.user_hash == user_hash)
        .options(selectinload(Event.findings))
        .order_by(Event.ts)
    )
    return {
        "user_hash": user_hash,
        "events": [
            {
                "id": e.id,
                "request_id": e.request_id,
                "ts": e.ts.isoformat(),
                "app": e.app,
                "session": e.session,
                "direction": e.direction,
                "role": e.role,
                "action": e.action,
                "risk_score": e.risk_score,
                "text_hash": e.text_hash,
                "excerpt_redacted": e.excerpt_redacted,
                "full_text": e.full_text,
                "upstream_model": e.upstream_model,
                "findings": [
                    {
                        "detector": f.detector,
                        "attack_class": f.attack_class,
                        "score": f.score,
                        "rule_id": f.rule_id,
                        "reason": f.reason,
                    }
                    for f in e.findings
                ],
            }
            for e in events
        ],
    }


async def delete_user(session: AsyncSession, user_hash: str) -> dict[str, int]:
    events = select(Event.id).where(Event.user_hash == user_hash)
    return {
        "findings": await _delete(session, delete(Finding).where(Finding.event_id.in_(events))),
        "events": await _delete(session, delete(Event).where(Event.user_hash == user_hash)),
    }
