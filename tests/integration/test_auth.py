from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from fastapi import FastAPI
from sqlalchemy import select

from gateway.core.keys import KeyRole, generate_key
from gateway.main import create_app
from gateway.storage.models import AuditLog
from tests.conftest import (
    BOOTSTRAP_KEY,
    chat_body,
    completion,
    create_schema,
    make_key,
    make_settings,
)

PROXY = "/v1/chat/completions"


def _bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def _assert_unauthorized(response: httpx.Response) -> None:
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    error = response.json()["error"]
    assert error["type"] == "unauthorized"
    assert error["request_id"] == response.headers["X-Gateway-Request-Id"]


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": ""},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer not-a-key"},
        {"Authorization": "Bearer " + generate_key().plaintext},  # well formed, unknown
    ],
)
async def test_missing_or_wrong_key_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, headers: dict[str, str]
) -> None:
    route = upstream.post("/chat/completions").respond(200, json=completion("ok"))
    await _assert_unauthorized(await client.post(PROXY, json=chat_body("hi"), headers=headers))
    assert not route.called


async def test_right_id_wrong_secret_rejected(
    client: httpx.AsyncClient, upstream: respx.MockRouter, client_key: str
) -> None:
    route = upstream.post("/chat/completions")
    prefix, key_id, secret = client_key.split(".")
    forged = f"{prefix}.{key_id}.{'A' * len(secret)}"
    await _assert_unauthorized(
        await client.post(PROXY, json=chat_body("hi"), headers=_bearer(forged))
    )
    assert not route.called


async def test_valid_client_key_accepted(
    client: httpx.AsyncClient, upstream: respx.MockRouter, client_key: str
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("ok"))
    response = await client.post(PROXY, json=chat_body("hi"), headers=_bearer(client_key))
    assert response.status_code == 200


async def test_revoked_key_rejected(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, client_key: str
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("ok"))
    admin = await make_key(app, KeyRole.ADMIN)
    key_id = client_key.split(".")[1]
    revoked = await client.post(f"/admin/keys/{key_id}/revoke", headers=_bearer(admin))
    assert revoked.status_code == 200
    await _assert_unauthorized(
        await client.post(PROXY, json=chat_body("hi"), headers=_bearer(client_key))
    )
    # Revoking again is idempotent and does not add a second audit entry.
    again = await client.post(f"/admin/keys/{key_id}/revoke", headers=_bearer(admin))
    assert again.status_code == 200
    assert again.json()["revoked_at"] == revoked.json()["revoked_at"]
    async with app.state.services.sessionmaker() as session:
        key_actions = select(AuditLog.action).where(AuditLog.action.like("api_key.%"))
        actions = (await session.scalars(key_actions)).all()
    assert actions == ["api_key.revoke"]
    unknown = await client.post("/admin/keys/0000000000000000/revoke", headers=_bearer(admin))
    assert unknown.status_code == 404


async def test_roles_are_separate(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, client_key: str
) -> None:
    route = upstream.post("/chat/completions")
    admin = await make_key(app, KeyRole.ADMIN)

    as_admin = await client.post(PROXY, json=chat_body("hi"), headers=_bearer(admin))
    assert as_admin.status_code == 403
    assert as_admin.json()["error"]["code"] == "wrong_key_role"
    assert not route.called

    as_client = await client.post(
        "/admin/keys", json={"name": "x", "role": "client"}, headers=_bearer(client_key)
    )
    assert as_client.status_code == 403


async def test_bootstrap_flow(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("ok"))

    # The bootstrap key is an admin credential, so it cannot call the proxy.
    proxied = await client.post(PROXY, json=chat_body("hi"), headers=_bearer(BOOTSTRAP_KEY))
    assert proxied.status_code == 403

    created = await client.post(
        "/admin/keys", json={"name": "first-admin", "role": "admin"}, headers=_bearer(BOOTSTRAP_KEY)
    )
    assert created.status_code == 201
    admin_key = created.json()["key"]

    # Once an admin key exists, the bootstrap key stops working.
    await _assert_unauthorized(
        await client.post(
            "/admin/keys", json={"name": "x", "role": "client"}, headers=_bearer(BOOTSTRAP_KEY)
        )
    )

    made = await client.post(
        "/admin/keys", json={"name": "app", "role": "client"}, headers=_bearer(admin_key)
    )
    assert made.status_code == 201
    assert made.json()["role"] == "client"
    response = await client.post(PROXY, json=chat_body("hi"), headers=_bearer(made.json()["key"]))
    assert response.status_code == 200

    async with app.state.services.sessionmaker() as session:
        key_rows = select(AuditLog).where(AuditLog.action.like("api_key.%"))
        rows = (await session.scalars(key_rows.order_by(AuditLog.ts))).all()
    assert [(r.actor, r.action) for r in rows] == [
        ("bootstrap", "api_key.create"),
        (created.json()["id"], "api_key.create"),
    ]


async def test_create_key_validates_body(app: FastAPI, client: httpx.AsyncClient) -> None:
    admin = await make_key(app, KeyRole.ADMIN)
    response = await client.post(
        "/admin/keys", json={"name": "", "role": "root"}, headers=_bearer(admin)
    )
    assert response.status_code == 422
    assert response.json()["error"]["type"] == "invalid_request"


async def test_startup_requires_bootstrap_key_when_no_admin(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, admin_bootstrap_key=None)
    await create_schema(settings)
    app = create_app(settings)
    with pytest.raises(RuntimeError, match="ADMIN_BOOTSTRAP_KEY"):
        async with app.router.lifespan_context(app):
            pass


async def test_startup_explains_unmigrated_database(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))
    with pytest.raises(RuntimeError, match="gateway db upgrade"):
        async with app.router.lifespan_context(app):
            pass
