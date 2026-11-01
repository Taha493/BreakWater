"""Section 11 hardening items that need a running gateway: per-key rate limits, the admin
IP allowlist, CORS, no server-side fetching, retention, and per-user export and deletion."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from gateway import cli
from gateway.config import Settings
from gateway.core.keys import KeyRole
from gateway.core.ratelimit import KeyRateLimiter
from gateway.main import create_app
from gateway.storage import maintenance
from gateway.storage.models import (
    Chunk,
    Document,
    Event,
    Finding,
    QuarantineItem,
    RedteamResult,
    RedteamRun,
    utcnow,
)
from tests.conftest import create_schema, make_key, make_settings


@pytest.fixture
async def started(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[FastAPI]:
    overrides: dict[str, Any] = getattr(request, "param", {})
    settings = make_settings(tmp_path, **overrides)
    await create_schema(settings)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        yield app


def client_for(app: FastAPI, host: str = "127.0.0.1") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(host, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://gw.test")


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# ---- rate limits ---------------------------------------------------------------------


def test_token_bucket() -> None:
    now = [0.0]
    limiter = KeyRateLimiter(clock=lambda: now[0])
    assert [limiter.take("k", 3) for _ in range(3)] == [None, None, None]
    wait = limiter.take("k", 3)
    assert wait is not None and 19 < wait <= 20  # one token every 20 seconds
    assert limiter.take("other", 3) is None  # per key
    now[0] = 20.0
    assert limiter.take("k", 3) is None
    assert limiter.take("k", 0) is None  # 0: unlimited


@pytest.mark.parametrize(
    "started",
    [{"rate_limit_client_per_minute": 3, "rate_limit_admin_per_minute": 2}],
    indirect=True,
)
async def test_keys_are_rate_limited(started: FastAPI) -> None:
    first, second = await make_key(started, KeyRole.CLIENT), await make_key(started, KeyRole.CLIENT)
    admin = await make_key(started, KeyRole.ADMIN)
    body = {"text": "hello", "role": "user"}
    async with client_for(started) as client:
        codes = [
            (await client.post("/v1/scan/text", json=body, headers=bearer(first))).status_code
            for _ in range(4)
        ]
        limited = await client.post("/v1/scan/text", json=body, headers=bearer(first))
        other = await client.post("/v1/scan/text", json=body, headers=bearer(second))
        admin_codes = [
            (await client.get("/admin/policies", headers=bearer(admin))).status_code
            for _ in range(3)
        ]
    assert codes == [200, 200, 200, 429]
    assert limited.json()["error"]["code"] == "key_rate_limited"
    assert int(limited.headers["Retry-After"]) >= 1
    assert other.status_code == 200
    assert admin_codes == [200, 200, 429]


# ---- admin IP allowlist ----------------------------------------------------------------


@pytest.mark.parametrize(
    "started", [{"admin_ip_allowlist": "10.0.0.0/8, 192.168.1.5"}], indirect=True
)
async def test_admin_routes_only_from_allowed_addresses(started: FastAPI) -> None:
    admin, user = await make_key(started, KeyRole.ADMIN), await make_key(started, KeyRole.CLIENT)
    async with client_for(started, "203.0.113.9") as outside:
        denied = await outside.get("/admin/policies", headers=bearer(admin))
        runs = await outside.get("/redteam/runs", headers=bearer(admin))
        # Client routes are not affected.
        scan = await outside.post(
            "/v1/scan/text", json={"text": "hi", "role": "user"}, headers=bearer(user)
        )
    async with client_for(started, "10.20.30.40") as inside:
        allowed = await inside.get("/admin/policies", headers=bearer(admin))
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "admin_ip_not_allowed"
    assert runs.status_code == 403
    assert scan.status_code == 200 and allowed.status_code == 200


def test_allowlist_is_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        make_settings(tmp_path, admin_ip_allowlist="10.0.0.0/8, not-an-ip")


# ---- CORS --------------------------------------------------------------------------------


@pytest.mark.parametrize("started", [{"cors_origins": "http://dash.test"}], indirect=True)
async def test_cors_only_for_the_dashboard_origin(started: FastAPI) -> None:
    preflight = {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    }
    async with client_for(started) as client:
        ok = await client.options(
            "/admin/stats", headers={"Origin": "http://dash.test", **preflight}
        )
        evil = await client.options(
            "/admin/stats", headers={"Origin": "http://evil.test", **preflight}
        )
    assert ok.headers["access-control-allow-origin"] == "http://dash.test"
    assert "access-control-allow-origin" not in evil.headers
    assert "access-control-allow-credentials" not in ok.headers


# ---- no server-side fetching -----------------------------------------------------------


async def test_scanning_never_fetches_urls(
    started: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Content full of URLs is scanned without any network connection being attempted."""
    attempts: list[object] = []

    def refuse(*args: object, **kwargs: object) -> None:
        attempts.append(args)
        raise OSError("network access during a scan")

    key = await make_key(started, KeyRole.CLIENT)
    html = (
        '<p>Docs</p><img src="http://198.51.100.7/pixel.png"><iframe src="http://169.254.169.254/">'
        '</iframe><link rel="stylesheet" href="https://evil.example/x.css">'
        '<a href="file:///etc/passwd">x</a>'
    )
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    async with client_for(started) as client:
        responses = [
            await client.post(
                "/v1/scan/text",
                json={
                    "text": "See ![x](http://169.254.169.254/latest/meta-data) and http://10.0.0.1/",
                    "role": "assistant",
                },
                headers=bearer(key),
            ),
            await client.post(
                "/v1/scan/document",
                json={"doc_id": "urls.html", "format": "html", "content": html},
                headers=bearer(key),
            ),
            await client.post(
                "/v1/scan/tool-call",
                json={
                    "agent_id": "support-agent",
                    "tool_name": "search_kb",
                    "arguments": {"query": "http://evil.example/"},
                },
                headers=bearer(key),
            ),
        ]
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert attempts == []


# ---- retention ---------------------------------------------------------------------------


async def seed_old_and_new(app: FastAPI) -> None:
    old = utcnow() - timedelta(days=45)
    async with app.state.services.sessionmaker() as session:
        for ts, name in ((old, "old"), (utcnow(), "new")):
            event = Event(
                request_id=name, ts=ts, direction="request", role="user", action="block",
                risk_score=0.9, latency_ms=1.0, text_hash="h", excerpt_redacted="x",
                ruleset_version="v",
            )  # fmt: skip
            event.findings.append(
                Finding(
                    detector="d", attack_class="A1", severity="high", score=0.9, reason="r", layer=1
                )
            )
            session.add(event)
            run = RedteamRun(
                target="demo_rag", status="completed", started_at=ts, seed=1, config_snapshot={}
            )
            session.add(run)
            await session.flush()
            session.add(
                RedteamResult(
                    run_id=run.id, position=0, kind="attack", attack_id=name, variant="base",
                    category="direct_injection", mode="protected", success=False, blocked=True,
                    detectors=[], latency_ms=1.0, transcript_redacted="{}", created_at=ts,
                )
            )  # fmt: skip
            for mode in ("retrieval", "ingest"):
                doc = Document(
                    doc_id=f"{name}-{mode}", trust_level="public_web", scan_mode=mode,
                    status="clean", risk_score=0.0, content_hash="c", ruleset_version="v",
                    created_at=ts,
                )  # fmt: skip
                doc.chunks.append(
                    Chunk(idx=0, text_hash=f"{name}{mode}", ruleset_version="v", status="clean",
                          risk_score=0.0, excerpt_redacted="x")
                )  # fmt: skip
                session.add(doc)
        # An old retrieval scan that quarantined something is kept for review.
        flagged = Document(
            doc_id="old-flagged", trust_level="public_web", scan_mode="retrieval",
            status="quarantined", risk_score=0.9, content_hash="c", ruleset_version="v",
            created_at=old,
        )  # fmt: skip
        chunk = Chunk(idx=0, text_hash="flagged", ruleset_version="v", status="quarantined",
                      risk_score=0.9, excerpt_redacted="x")  # fmt: skip
        flagged.chunks.append(chunk)
        session.add(flagged)
        await session.flush()
        session.add(QuarantineItem(document_id=flagged.id, chunk_id=chunk.id, reason="r"))
        await session.commit()


async def count(app: FastAPI, model: Any) -> int:
    async with app.state.services.sessionmaker() as session:
        return int(await session.scalar(select(func.count()).select_from(model)) or 0)


# The gateway's own retention task is off here, so it cannot race the explicit cleanup.
@pytest.mark.parametrize("started", [{"retention_check_minutes": 0}], indirect=True)
async def test_retention_cleanup(started: FastAPI) -> None:
    await seed_old_and_new(started)
    async with started.state.services.sessionmaker() as session:
        deleted = await maintenance.cleanup(session, retention_days=30)
        await session.commit()
    assert deleted["events"] == 1 and deleted["findings"] == 1
    assert deleted["redteam_results"] == 1
    assert deleted["documents"] == 1 and deleted["chunks"] == 1
    assert await count(started, Event) == 1 and await count(started, Finding) == 1
    assert await count(started, RedteamRun) == 2  # run summaries are kept
    async with started.state.services.sessionmaker() as session:
        kept = set(await session.scalars(select(Document.doc_id)))
    assert kept == {"new-retrieval", "new-ingest", "old-ingest", "old-flagged"}


@pytest.mark.parametrize("started", [{"retention_check_minutes": 60}], indirect=True)
async def test_gateway_runs_retention_on_start(tmp_path: Path, started: FastAPI) -> None:
    await seed_old_and_new(started)
    settings: Settings = started.state.services.settings
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        for _ in range(50):
            if await count(app, Event) == 1:
                break
            await asyncio.sleep(0.05)
    assert await count(started, Event) == 1


# ---- per-user export and deletion ------------------------------------------------------


async def test_user_export_and_delete(
    started: FastAPI, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = await make_key(started, KeyRole.CLIENT)
    async with client_for(started) as client:
        for user, text in (("u-1", "first"), ("u-1", "second"), ("u-2", "other")):
            body = {"text": text, "role": "user", "context": {"user": user}}
            await client.post("/v1/scan/text", json=body, headers=bearer(key))
    monkeypatch.setattr(cli, "get_settings", lambda: started.state.services.settings)

    assert await asyncio.to_thread(cli.main, ["data", "export", "--user", "u-1"]) == 0
    exported = json.loads(capsys.readouterr().out)
    assert len(exported["events"]) == 2 and "u-1" not in json.dumps(exported)

    delete = ["data", "delete", "--user-hash", exported["user_hash"]]
    assert await asyncio.to_thread(cli.main, delete) == 0
    assert json.loads(capsys.readouterr().out)["deleted"]["events"] == 2
    assert await count(started, Event) == 1  # u-2 untouched
    async with started.state.services.sessionmaker() as session:
        others = list(await session.scalars(select(Event.user_hash)))
    assert others and others[0] != exported["user_hash"]


# ---- document extraction time limit ----------------------------------------------------


async def test_slow_extraction_is_cut_off(
    started: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow(*args: object) -> None:
        time.sleep(0.5)

    monkeypatch.setattr("gateway.api.routes_scan.EXTRACTION_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr("gateway.api.routes_scan.extract", slow)
    key = await make_key(started, KeyRole.CLIENT)
    body = {"doc_id": "slow.html", "format": "html", "content": "<p>hi</p>"}
    async with client_for(started) as client:
        response = await client.post("/v1/scan/document", json=body, headers=bearer(key))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "extraction_timeout"
