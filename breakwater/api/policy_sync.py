"""Keeps each gateway process on the active database policy (spec section 9,
``policy_versions``).

On the first start against an empty table, policies.yaml is stored as version 1. After that
the database is the source of truth: ``PUT /admin/policies`` and rollbacks change the active
version, and every process picks it up within ``CONFIG_RELOAD_SECONDS`` (the process that
made the change applies it at once).
"""

from __future__ import annotations

import asyncio
import logging

from breakwater.api.deps import Services
from breakwater.storage import repo

log = logging.getLogger("gateway.policy")

SEED_ACTOR = "policies.yaml"
MIN_POLL_SECONDS = 0.5


class PolicySync:
    def __init__(self, services: Services) -> None:
        self._services = services
        self._failed_version: int | None = None

    async def sync(self) -> None:
        """Apply the active version (seeding it from the file if there is none)."""
        store = self._services.store
        async with self._services.sessionmaker() as session:
            row = await repo.active_policy(session)
            if row is None:
                content = store.policy_file.read_text("utf-8")
                row = await repo.add_policy_version(
                    session, content, SEED_ACTOR, "seeded from policies.yaml"
                )
                repo.add_audit(session, SEED_ACTOR, "policy.seed", str(row.id))
                await session.commit()
            version_id, content = row.id, row.content
        if version_id in (store.policy_version, self._failed_version):
            return
        try:
            store.set_policy(content.encode("utf-8"), version_id)
        except Exception:
            # Validated when it was saved, so this means the rule files changed under it.
            self._failed_version = version_id
            log.exception(
                "active policy version %s does not load; keeping the current one", version_id
            )

    async def run(self, interval: float) -> None:
        while True:
            await asyncio.sleep(max(interval, MIN_POLL_SECONDS))
            try:
                await self.sync()
            except Exception:
                log.exception("policy sync failed")
