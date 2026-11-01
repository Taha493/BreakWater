"""SQLAlchemy models for the tables in spec section 9."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Dialect,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def _uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Timezone-aware UTC datetimes on every backend (SQLite drops tzinfo on its own)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetimes are not allowed; use UTC-aware values")
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError(f"expected datetime from database, got {type(value).__name__}")
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(16), primary_key=True)  # public part of the key
    name: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class Event(Base):
    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    request_id: Mapped[str] = mapped_column(String(36), index=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    app: Mapped[str | None] = mapped_column(String(128))
    user_hash: Mapped[str | None] = mapped_column(String(64))
    session: Mapped[str | None] = mapped_column(String(128))
    direction: Mapped[str] = mapped_column(String(16))
    role: Mapped[str] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    latency_ms: Mapped[float] = mapped_column(Float)
    judge_used: Mapped[bool] = mapped_column(Boolean, default=False)
    text_hash: Mapped[str] = mapped_column(String(64))
    excerpt_redacted: Mapped[str] = mapped_column(Text)
    # Only populated when STORE_FULL_TEXT is on.
    full_text: Mapped[str | None] = mapped_column(Text)
    upstream_model: Mapped[str | None] = mapped_column(String(128))
    ruleset_version: Mapped[str] = mapped_column(String(64))

    findings: Mapped[list[Finding]] = relationship(
        back_populates="event", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    detector: Mapped[str] = mapped_column(String(64))
    attack_class: Mapped[str] = mapped_column(String(4), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    score: Mapped[float] = mapped_column(Float)
    rule_id: Mapped[str | None] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text)
    span_start: Mapped[int | None] = mapped_column(Integer)
    span_end: Mapped[int | None] = mapped_column(Integer)
    layer: Mapped[int] = mapped_column(Integer)
    message_index: Mapped[int | None] = mapped_column(Integer)

    event: Mapped[Event] = relationship(back_populates="findings")


class AuditLog(Base):
    """Security-relevant admin actions (spec section 11, audit log)."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[str | None] = mapped_column(Text)


class Document(Base):
    """One scan of a document (ingest) or of a batch of retrieved chunks (retrieval)."""

    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    doc_id: Mapped[str] = mapped_column(String(256), index=True)
    source: Mapped[str | None] = mapped_column(String(512))
    trust_level: Mapped[str] = mapped_column(String(16))
    scan_mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    content_hash: Mapped[str] = mapped_column(String(64))
    ruleset_version: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    chunks: Mapped[list[Chunk]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class Chunk(Base):
    __tablename__ = "chunks"
    __table_args__ = (Index("ix_chunks_cache", "text_hash", "ruleset_version"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    document_id: Mapped[str] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    idx: Mapped[int] = mapped_column(Integer)
    text_hash: Mapped[str] = mapped_column(String(64), index=True)
    ruleset_version: Mapped[str] = mapped_column(String(64))
    # clean, suspicious, quarantined, or released (a quarantined chunk a reviewer cleared)
    status: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[float] = mapped_column(Float)
    excerpt_redacted: Mapped[str] = mapped_column(Text)
    hidden_kind: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow)

    document: Mapped[Document] = relationship(back_populates="chunks")


class QuarantineItem(Base):
    __tablename__ = "quarantine"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    document_id: Mapped[str] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    chunk_id: Mapped[str] = mapped_column(ForeignKey("chunks.id", ondelete="CASCADE"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128))
    reviewed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    # None while pending review, then "released" or "kept".
    decision: Mapped[str | None] = mapped_column(String(16), index=True)

    chunk: Mapped[Chunk] = relationship()
    document: Mapped[Document] = relationship()


class TaintMark(Base):
    """A fingerprint of untrusted text seen in a session (hashes only), for the tool guard."""

    __tablename__ = "taint"
    __table_args__ = (Index("ix_taint_lookup", "session_hash", "fingerprint"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    session_hash: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)


class RedteamRun(Base):
    """One red-team run against one target (spec section 8). Kept until an admin deletes it."""

    __tablename__ = "redteam_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(128), index=True)
    # running, completed, or failed
    status: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    seed: Mapped[int] = mapped_column(Integer)
    config_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON)
    summary: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(Text)
    previous_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("redteam_runs.id", ondelete="SET NULL")
    )

    results: Mapped[list[RedteamResult]] = relationship(
        back_populates="run", cascade="all, delete-orphan", order_by="RedteamResult.position"
    )


class RedteamResult(Base):
    """One probe in one mode. Transcripts are redacted before they are stored."""

    __tablename__ = "redteam_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("redteam_runs.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(16))  # attack or benign
    attack_id: Mapped[str] = mapped_column(String(64), index=True)  # or the benign case id
    variant: Mapped[str] = mapped_column(String(32))
    category: Mapped[str] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(16))  # unprotected or protected
    success: Mapped[bool] = mapped_column(Boolean)
    blocked: Mapped[bool] = mapped_column(Boolean)
    caught_by_layer: Mapped[int | None] = mapped_column(Integer)
    detectors: Mapped[list[str]] = mapped_column(JSON)
    latency_ms: Mapped[float] = mapped_column(Float)
    error: Mapped[str | None] = mapped_column(Text)
    transcript_redacted: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=utcnow, index=True)

    run: Mapped[RedteamRun] = relationship(back_populates="results")
