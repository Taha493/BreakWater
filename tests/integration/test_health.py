from __future__ import annotations

import httpx
from fastapi import FastAPI

from breakwater.storage.db import make_engine


async def test_healthz_ok_without_auth(client: httpx.AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "ok"}


async def test_healthz_reports_database_down(app: FastAPI, client: httpx.AsyncClient) -> None:
    services = app.state.services
    healthy = services.engine
    services.engine = make_engine("sqlite:////nonexistent-dir/never/gateway.db")
    try:
        response = await client.get("/healthz")
    finally:
        await services.engine.dispose()
        services.engine = healthy
    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"
