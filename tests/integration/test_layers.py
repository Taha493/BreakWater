"""Keys capped at a detection layer (for red-team layer comparisons): the cap applies to
every scan the key makes, is recorded on events, and keeps its own scan cache."""

from __future__ import annotations

from typing import ClassVar

import httpx
from fastapi import FastAPI
from sqlalchemy import select

from breakwater.core.context import ScanContext
from breakwater.core.keys import KeyRole
from breakwater.core.verdict import AttackClass, Finding, Role, Severity
from breakwater.detectors.base import Detector
from breakwater.storage.models import AuditLog, Event
from tests.conftest import make_key, pin_runtime, runtime_with


class FlagEverything(Detector):
    """A stand-in layer 2 detector that flags any text."""

    name = "layer2_stub"
    layer = 2
    roles: ClassVar[frozenset[Role]] = frozenset({Role.USER, Role.RETRIEVED})

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        return [
            Finding(
                detector=self.name,
                attack_class=AttackClass.A1 if role is Role.USER else AttackClass.A2,
                severity=Severity.HIGH,
                score=0.95,
                reason="stub",
                layer=self.layer,
            )
        ]


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def capped_key(client: httpx.AsyncClient, admin: str, layer: int) -> str:
    created = await client.post(
        "/admin/keys",
        json={"name": f"capped-{layer}", "role": "client", "max_layer": layer},
        headers=bearer(admin),
    )
    assert created.status_code == 201 and created.json()["max_layer"] == layer
    key: str = created.json()["key"]
    return key


async def test_max_layer_only_for_client_keys(app: FastAPI, client: httpx.AsyncClient) -> None:
    admin = await make_key(app, KeyRole.ADMIN)
    for body in (
        {"name": "a", "role": "admin", "max_layer": 1},
        {"name": "c", "role": "client", "max_layer": 0},
        {"name": "c", "role": "client", "max_layer": 4},
    ):
        response = await client.post("/admin/keys", json=body, headers=bearer(admin))
        assert response.status_code == 422, body
    await capped_key(client, admin, 1)
    async with app.state.services.sessionmaker() as session:
        details = [a.detail for a in await session.scalars(select(AuditLog))]
    assert "role=client max_layer=1" in details


async def test_capped_key_skips_higher_layers(app: FastAPI, client: httpx.AsyncClient) -> None:
    pin_runtime(app, runtime_with(FlagEverything()))
    admin = await make_key(app, KeyRole.ADMIN)
    full, capped = await make_key(app, KeyRole.CLIENT), await capped_key(client, admin, 1)
    body = {"text": "What are your opening hours?", "role": "user"}

    as_full = (await client.post("/v1/scan/text", json=body, headers=bearer(full))).json()
    assert as_full["action"] == "block"
    as_capped = (await client.post("/v1/scan/text", json=body, headers=bearer(capped))).json()
    assert as_capped["action"] == "allow" and as_capped["findings"] == []

    async with app.state.services.sessionmaker() as session:
        versions = sorted(e.ruleset_version for e in await session.scalars(select(Event)))
    version = app.state.services.store.current().version
    assert versions == [version, f"{version}/L1"]


async def test_capped_scans_keep_their_own_cache(app: FastAPI, client: httpx.AsyncClient) -> None:
    pin_runtime(app, runtime_with(FlagEverything()))
    admin = await make_key(app, KeyRole.ADMIN)
    full, capped = await make_key(app, KeyRole.CLIENT), await capped_key(client, admin, 1)
    body = {"mode": "retrieval", "chunks": ["Store hours are 9 to 5."]}

    first = (await client.post("/v1/scan/document", json=body, headers=bearer(capped))).json()
    assert first["chunks"][0]["allowed"] and not first["chunks"][0]["cached"]
    # The capped result must not stand in for a full scan of the same text.
    second = (await client.post("/v1/scan/document", json=body, headers=bearer(full))).json()
    assert not second["chunks"][0]["allowed"] and not second["chunks"][0]["cached"]
    again = (await client.post("/v1/scan/document", json=body, headers=bearer(capped))).json()
    assert again["chunks"][0]["allowed"] and again["chunks"][0]["cached"]
