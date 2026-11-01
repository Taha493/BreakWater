"""Document and chunk scanning (spec section 7).

Every chunk runs through the shared pipeline with role ``retrieved``. A chunk's status comes
from its risk score and the document's trust level: ``quarantined`` at or above the trust
level's block threshold, ``suspicious`` at or above ``allow_below``, otherwise ``clean``.
A document takes its worst chunk's status and its highest chunk risk.

Scan results are cached by keyed content hash plus ruleset version, so repeated retrievals
of the same chunk run no detectors.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.context import CallContext
from gateway.core.pipeline import Inspection
from gateway.core.policy import TrustLevel
from gateway.core.redact import Hasher
from gateway.core.runtime import Runtime
from gateway.core.verdict import Finding, Role
from gateway.rag.chunking import chunk_text
from gateway.rag.extract import Extracted
from gateway.storage import repo
from gateway.storage.models import Chunk, Document, QuarantineItem

CLEAN, SUSPICIOUS, QUARANTINED, RELEASED = "clean", "suspicious", "quarantined", "released"
ALLOWED_STATUSES = frozenset({CLEAN, SUSPICIOUS, RELEASED})
_RANK = {CLEAN: 0, RELEASED: 0, SUSPICIOUS: 1, QUARANTINED: 2}
# Hidden segments that are ordinary parts of documents: scanned, but not reported as hidden.
_UNFLAGGED_HIDDEN = frozenset({"alt_text", "metadata"})


VISIBLE = "visible"


@dataclass(frozen=True)
class ChunkInput:
    text: str
    # "visible", or the extracted kind it came from (see rag/extract.py): metadata,
    # alt_text, html_comment, pdf_white_text, ...
    origin: str = VISIBLE
    # Whether the response may return this chunk's text (only visible chunks the gateway made).
    returnable: bool = False

    @property
    def hidden_kind(self) -> str | None:
        """The hiding technique to report, or None for visible and ordinary extra text."""
        return None if self.origin == VISIBLE or self.origin in _UNFLAGGED_HIDDEN else self.origin


@dataclass
class ChunkResult:
    index: int
    text: str
    text_hash: str
    origin: str
    hidden_kind: str | None
    returnable: bool
    status: str
    risk_score: float
    cached: bool
    chunk_id: str | None = None
    inspection: Inspection | None = None

    @property
    def allowed(self) -> bool:
        return self.status in ALLOWED_STATUSES

    @property
    def findings(self) -> list[Finding]:
        return self.inspection.verdict.findings if self.inspection else []


@dataclass
class DocumentScan:
    status: str
    risk_score: float
    chunks: list[ChunkResult] = field(default_factory=list)


def chunks_from_extracted(extracted: Extracted) -> list[ChunkInput]:
    inputs = [ChunkInput(text, returnable=True) for text in chunk_text(extracted.visible)]
    for segment in extracted.hidden:
        for text in chunk_text(segment.text):
            inputs.append(ChunkInput(text, origin=segment.kind))
    return inputs


def chunk_status(risk: float, block_at: float, allow_below: float) -> str:
    if risk >= block_at:
        return QUARANTINED
    if risk >= allow_below:
        return SUSPICIOUS
    return CLEAN


async def scan_chunks(
    runtime: Runtime,
    hasher: Hasher,
    session: AsyncSession,
    inputs: Sequence[ChunkInput],
    trust: TrustLevel,
    call: CallContext,
    request_id: str,
) -> DocumentScan:
    policy = runtime.policy
    block_at = policy.document_block_at(trust)
    allow_below = policy.config.thresholds.allow_below
    hashes = [hasher.text(c.text) for c in inputs]
    cache = await repo.cached_chunks(session, hashes, runtime.version)

    results: list[ChunkResult] = []
    to_scan: list[ChunkResult] = []
    for index, (chunk, text_hash) in enumerate(zip(inputs, hashes, strict=True)):
        hit = cache.get(text_hash)
        result = ChunkResult(
            index=index,
            text=chunk.text,
            text_hash=text_hash,
            origin=chunk.origin,
            hidden_kind=chunk.hidden_kind,
            returnable=chunk.returnable,
            status=hit.status if hit else CLEAN,
            risk_score=hit.risk_score if hit else 0.0,
            cached=hit is not None,
            chunk_id=hit.chunk_id if hit else None,
        )
        if hit is not None and hit.status != RELEASED:
            # The cached status was computed for some trust level; recompute for this one.
            result.status = chunk_status(hit.risk_score, block_at, allow_below)
        results.append(result)
        if hit is None:
            to_scan.append(result)

    async def inspect(result: ChunkResult) -> None:
        ctx = CallContext(
            app=call.app, session=call.session, key_id=call.key_id, hidden_kind=result.hidden_kind
        )
        inspection = await runtime.pipeline.inspect(
            result.text, Role.RETRIEVED, ctx, request_id, result.index
        )
        result.inspection = inspection
        result.risk_score = inspection.verdict.risk_score
        result.status = chunk_status(result.risk_score, block_at, allow_below)

    await asyncio.gather(*(inspect(r) for r in to_scan))
    worst = max(results, key=lambda r: _RANK[r.status], default=None)
    return DocumentScan(
        status=CLEAN if worst is None or worst.status == RELEASED else worst.status,
        risk_score=max((r.risk_score for r in results), default=0.0),
        chunks=results,
    )


def _reason(result: ChunkResult) -> str:
    top = max(result.findings, key=lambda f: f.score, default=None)
    if top is None:
        return "Risk score above the document threshold"
    return f"{top.rule_id or top.detector}: {top.reason}"


async def persist(
    session: AsyncSession,
    runtime: Runtime,
    scan: DocumentScan,
    *,
    doc_id: str,
    source: str | None,
    trust: TrustLevel,
    mode: str,
    content_hash: str,
) -> Document:
    """Store the scan, its newly scanned chunks, and a quarantine item for each newly
    quarantined chunk. Cached chunks are not stored again."""
    document = Document(
        doc_id=doc_id,
        source=source,
        trust_level=trust.value,
        scan_mode=mode,
        status=scan.status,
        risk_score=scan.risk_score,
        content_hash=content_hash,
        ruleset_version=runtime.version,
    )
    session.add(document)
    for result in scan.chunks:
        if result.cached:
            continue
        chunk = Chunk(
            document=document,
            idx=result.index,
            text_hash=result.text_hash,
            ruleset_version=runtime.version,
            status=result.status,
            risk_score=result.risk_score,
            excerpt_redacted=runtime.redactor.excerpt(result.text),
            hidden_kind=None if result.origin == VISIBLE else result.origin,
        )
        session.add(chunk)
        await session.flush()
        result.chunk_id = chunk.id
        if result.status == QUARANTINED:
            session.add(
                QuarantineItem(document_id=document.id, chunk_id=chunk.id, reason=_reason(result))
            )
    await session.commit()
    return document
