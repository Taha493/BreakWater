"""Event logging shared by the routes. Failures are logged and never fail the request."""

from __future__ import annotations

import logging

from gateway.api.deps import Services
from gateway.core.runtime import Runtime
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
