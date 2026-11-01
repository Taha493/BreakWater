"""Event logging shared by the routes. Failures are logged and never fail the request."""

from __future__ import annotations

import logging

from gateway.api.deps import Services
from gateway.core.runtime import Runtime
from gateway.core.taint import fingerprints
from gateway.storage import repo
from gateway.storage.repo import EventInput

log = logging.getLogger("gateway.events")


async def record(services: Services, runtime: Runtime, items: list[EventInput]) -> None:
    try:
        async with services.sessionmaker() as session:
            await repo.record_events(
                session,
                items,
                services.hasher,
                runtime.redactor,
                services.settings.store_full_text,
            )
    except Exception:
        log.exception("failed to record events", extra={"request_id": items[0].verdict.request_id})


async def record_taint(
    services: Services, runtime: Runtime, session_id: str, texts: list[str]
) -> None:
    """Remember fingerprints of untrusted text seen in a session, for the tool guard."""
    prints: set[str] = set()
    for text in texts:
        prints |= fingerprints(text, services.hasher)
    if not prints:
        return
    try:
        async with services.sessionmaker() as session:
            await repo.record_taint(
                session,
                services.hasher.session(session_id),
                prints,
                runtime.tool_guard.policy.defaults.taint_ttl_seconds,
            )
    except Exception:
        log.exception("failed to record taint")


async def record_all(
    services: Services,
    runtime: Runtime,
    items: list[EventInput],
    taint_session: str | None,
    taint_texts: list[str],
) -> None:
    """Background task: events, then taint marks."""
    await record(services, runtime, items)
    if taint_session and taint_texts:
        await record_taint(services, runtime, taint_session, taint_texts)
