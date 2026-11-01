"""Read-only queries behind the dashboard (spec section 10): stats over a time range, the
event log with filters, and documents by status. Aggregation runs in the database, so the
cost does not grow with what a page shows."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import (
    BigInteger,
    ColumnElement,
    Integer,
    and_,
    cast,
    distinct,
    exists,
    func,
    or_,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from breakwater.storage.models import Chunk, Document, Event, Finding, QuarantineItem

RangeName = Literal["1h", "24h", "7d", "30d"]
# Range length and chart bucket size, in seconds.
RANGES: dict[str, tuple[int, int]] = {
    "1h": (3600, 300),
    "24h": (86_400, 3600),
    "7d": (7 * 86_400, 6 * 3600),
    "30d": (30 * 86_400, 86_400),
}
ATTACK_CLASSES = ("A1", "A2", "A3", "A4")
BLOCKING_ACTIONS = ("block", "quarantine")


def _epoch(session: AsyncSession, column: Any) -> ColumnElement[int]:
    if session.get_bind().dialect.name == "sqlite":
        return cast(func.strftime("%s", column), Integer)
    return cast(func.extract("epoch", column), BigInteger)


async def _percentile(session: AsyncSession, where: list[Any], q: float) -> float | None:
    """Nearest-rank percentile of event latency, computed in the database."""
    total = await session.scalar(select(func.count()).select_from(Event).where(*where))
    if not total:
        return None
    rank = max(1, math.ceil(q / 100 * total))
    value = await session.scalar(
        select(Event.latency_ms).where(*where).order_by(Event.latency_ms).offset(rank - 1).limit(1)
    )
    return None if value is None else round(float(value), 3)


async def stats(
    session: AsyncSession, range_name: str, app: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    length, bucket = RANGES[range_name]
    until = now or datetime.now(UTC)
    since = until - timedelta(seconds=length)
    where: list[Any] = [Event.ts >= since, Event.ts <= until]
    if app:
        where.append(Event.app == app)

    actions = dict(
        (
            await session.execute(
                select(Event.action, func.count()).where(*where).group_by(Event.action)
            )
        ).all()
    )
    directions = dict(
        (
            await session.execute(
                select(Event.direction, func.count()).where(*where).group_by(Event.direction)
            )
        ).all()
    )
    judge_calls = await session.scalar(
        select(func.count()).select_from(Event).where(*where, Event.judge_used.is_(True))
    )
    total = sum(actions.values())
    blocked = sum(actions.get(a, 0) for a in BLOCKING_ACTIONS)

    # Blocked and redacted events per bucket and attack class (an event with findings in two
    # classes counts once in each).
    epoch = _epoch(session, Event.ts)
    bucket_start = (epoch // bucket) * bucket
    rows = (
        await session.execute(
            select(bucket_start, Event.action, Finding.attack_class, func.count(distinct(Event.id)))
            .join(Finding, Finding.event_id == Event.id)
            .where(*where, Event.action.in_((*BLOCKING_ACTIONS, "redact")))
            .group_by(bucket_start, Event.action, Finding.attack_class)
        )
    ).all()
    first = (int(since.timestamp()) // bucket) * bucket
    series: dict[int, dict[str, Any]] = {
        start: {
            "ts": datetime.fromtimestamp(start, UTC).isoformat(),
            "blocked": dict.fromkeys(ATTACK_CLASSES, 0),
            "redacted": dict.fromkeys(ATTACK_CLASSES, 0),
        }
        for start in range(first, int(until.timestamp()) + 1, bucket)
    }
    by_class = {c: {"blocked": 0, "redacted": 0} for c in ATTACK_CLASSES}
    for start, action, attack_class, count in rows:
        kind = "redacted" if action == "redact" else "blocked"
        point = series.get(int(start))
        if point is not None and attack_class in point[kind]:
            point[kind][attack_class] += count
        if attack_class in by_class:
            by_class[attack_class][kind] += count

    return {
        "range": range_name,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "bucket_seconds": bucket,
        "totals": {
            "events": total,
            "requests": directions.get("request", 0),
            "blocked": blocked,
            "redacted": actions.get("redact", 0),
            "allowed": actions.get("allow", 0),
            "block_rate": round(blocked / total, 4) if total else None,
            "judge_calls": judge_calls or 0,
            "by_direction": directions,
            "by_action": actions,
        },
        "latency_ms": {
            "p50": await _percentile(session, where, 50),
            "p95": await _percentile(session, where, 95),
        },
        "by_class": by_class,
        "series": list(series.values()),
    }


@dataclass(frozen=True)
class EventFilter:
    since: datetime | None = None
    until: datetime | None = None
    app: str | None = None
    action: str | None = None
    direction: str | None = None
    attack_class: str | None = None
    detector: str | None = None


def encode_cursor(event: Event) -> str:
    """URL-safe: the event's time in microseconds and its id."""
    micros = round(event.ts.timestamp() * 1_000_000)
    return f"{micros}_{event.id}"


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    micros, _, event_id = cursor.partition("_")
    if not micros.isdigit() or not event_id:
        raise ValueError("invalid cursor")
    return datetime.fromtimestamp(int(micros) / 1_000_000, UTC), event_id


async def list_events(
    session: AsyncSession, filters: EventFilter, limit: int, cursor: str | None = None
) -> tuple[list[Event], str | None]:
    """Newest first. Returns a page and the cursor for the next one (None at the end)."""
    stmt = select(Event).options(selectinload(Event.findings))
    if filters.since:
        stmt = stmt.where(Event.ts >= filters.since)
    if filters.until:
        stmt = stmt.where(Event.ts <= filters.until)
    for column, value in (
        (Event.app, filters.app),
        (Event.action, filters.action),
        (Event.direction, filters.direction),
    ):
        if value:
            stmt = stmt.where(column == value)
    conditions = []
    if filters.attack_class:
        conditions.append(Finding.attack_class == filters.attack_class)
    if filters.detector:
        conditions.append(Finding.detector == filters.detector)
    if conditions:
        stmt = stmt.where(exists().where(Finding.event_id == Event.id, *conditions))
    if cursor:
        ts, event_id = decode_cursor(cursor)
        stmt = stmt.where(or_(Event.ts < ts, and_(Event.ts == ts, Event.id < event_id)))
    rows = list(
        await session.scalars(stmt.order_by(Event.ts.desc(), Event.id.desc()).limit(limit + 1))
    )
    page = rows[:limit]
    return page, encode_cursor(page[-1]) if len(rows) > limit else None


async def get_event(session: AsyncSession, event_id: str) -> Event | None:
    return await session.scalar(
        select(Event).where(Event.id == event_id).options(selectinload(Event.findings))
    )


async def documents(session: AsyncSession, status: str | None, limit: int) -> dict[str, Any]:
    """Ingest scans (retrieval scans are batches of chunks, not documents): counts by
    status, the riskiest, and the most recent."""
    ingest = Document.scan_mode == "ingest"
    counts = dict(
        (
            await session.execute(
                select(Document.status, func.count()).where(ingest).group_by(Document.status)
            )
        ).all()
    )
    chunk_counts = (
        select(
            Chunk.document_id,
            func.count().label("chunks"),
            func.count(QuarantineItem.id).label("quarantined"),
        )
        .outerjoin(QuarantineItem, QuarantineItem.chunk_id == Chunk.id)
        .group_by(Chunk.document_id)
        .subquery()
    )
    base = (
        select(Document, chunk_counts.c.chunks, chunk_counts.c.quarantined)
        .outerjoin(chunk_counts, chunk_counts.c.document_id == Document.id)
        .where(ingest)
    )
    if status:
        base = base.where(Document.status == status)

    def rows(result: Any) -> list[dict[str, Any]]:
        return [
            {
                "id": doc.id,
                "doc_id": doc.doc_id,
                "source": doc.source,
                "trust_level": doc.trust_level,
                "status": doc.status,
                "risk_score": doc.risk_score,
                "ruleset_version": doc.ruleset_version,
                "created_at": doc.created_at,
                "chunks": chunks or 0,
                "quarantined_chunks": quarantined or 0,
            }
            for doc, chunks, quarantined in result
        ]

    risky = await session.execute(
        base.where(Document.risk_score > 0)
        .order_by(Document.risk_score.desc(), Document.created_at.desc())
        .limit(limit)
    )
    recent = await session.execute(base.order_by(Document.created_at.desc()).limit(limit))
    return {"counts": counts, "top_risky": rows(risky), "recent": rows(recent)}
