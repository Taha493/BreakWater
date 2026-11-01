"""Events are written for every proxied call, and nothing raw reaches the database or logs."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import respx
from fastapi import FastAPI
from sqlalchemy import select, text

from gateway.core.keys import KeyRole
from gateway.main import create_app
from gateway.storage.models import Event, Finding
from tests.conftest import chat_body, completion, create_schema, make_key, make_settings
from tests.integration.test_proxy import install_trigger

FAKE_SECRET = "sk-" + "z" * 40
FAKE_EMAIL = "someone.private@example.org"


async def _events(app: FastAPI) -> list[Event]:
    async with app.state.services.sessionmaker() as session:
        return list((await session.scalars(select(Event).order_by(Event.direction))).all())


async def _dump_all_tables(app: FastAPI) -> str:
    async with app.state.services.engine.connect() as conn:
        out: list[str] = []
        for table in ("events", "findings", "api_keys", "audit_log"):
            rows = (await conn.execute(text(f"SELECT * FROM {table}"))).all()  # noqa: S608
            out.extend(repr(tuple(r)) for r in rows)
    return "\n".join(out)


async def test_events_written_for_allowed_call(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").respond(200, json=completion("Paris.", model="m-2"))
    response = await client.post(
        "/v1/chat/completions",
        json=chat_body("Capital of France?"),
        headers={
            **auth,
            "X-Gateway-App": "support-bot",
            "X-Gateway-User": "user-42",
            "X-Gateway-Session": "sess-1",
        },
    )
    assert response.status_code == 200

    request_event, response_event = await _events(app)
    request_id = response.headers["X-Gateway-Request-Id"]
    policy_version = app.state.services.pipeline.policy.version
    hasher = app.state.services.hasher

    assert (request_event.direction, request_event.role) == ("request", "user")
    assert (response_event.direction, response_event.role) == ("response", "assistant")
    for event in (request_event, response_event):
        assert event.request_id == request_id
        assert event.action == "allow"
        assert event.app == "support-bot"
        assert event.session == "sess-1"
        assert event.user_hash == hasher.user("user-42")
        assert event.ruleset_version == policy_version
        assert event.full_text is None
        assert re.fullmatch(r"[0-9a-f]{64}", event.text_hash)
    assert request_event.excerpt_redacted == "Capital of France?"
    assert request_event.upstream_model == "test-model"
    assert response_event.excerpt_redacted == "Paris."
    assert response_event.upstream_model == "m-2"
    assert request_event.text_hash == hasher.text("Capital of France?")


async def test_secrets_never_stored_raw(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    prompt = f"my key is {FAKE_SECRET} and mail me at {FAKE_EMAIL}"
    upstream.post("/chat/completions").respond(200, json=completion(f"echo: {prompt}"))
    response = await client.post(
        "/v1/chat/completions",
        json=chat_body(prompt),
        headers={**auth, "X-Gateway-User": FAKE_EMAIL},
    )
    assert response.status_code == 200

    request_event, response_event = await _events(app)
    for event in (request_event, response_event):
        assert "[REDACTED:api_key]" in event.excerpt_redacted
        assert "[REDACTED:email]" in event.excerpt_redacted

    dump = await _dump_all_tables(app)
    assert FAKE_SECRET not in dump
    assert "z" * 20 not in dump
    assert FAKE_EMAIL not in dump


async def test_full_text_stored_only_when_enabled(
    tmp_path: Path, upstream: respx.MockRouter
) -> None:
    settings = make_settings(tmp_path, store_full_text=True)
    await create_schema(settings)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        key = await make_key(app, KeyRole.CLIENT)
        upstream.post("/chat/completions").respond(200, json=completion("Paris."))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
        ) as client:
            await client.post(
                "/v1/chat/completions",
                json=chat_body("Capital of France?"),
                headers={"Authorization": f"Bearer {key}"},
            )
        request_event, response_event = await _events(app)
    assert request_event.full_text == "Capital of France?"
    assert response_event.full_text == "Paris."


async def test_blocked_call_logs_event_with_findings(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    install_trigger(app)
    upstream.post("/chat/completions")
    response = await client.post(
        "/v1/chat/completions", json=chat_body("please TRIGGER now"), headers=auth
    )
    assert response.status_code == 403

    (event,) = await _events(app)
    assert (event.direction, event.action, event.risk_score) == ("request", "block", 0.95)
    async with app.state.services.sessionmaker() as session:
        (finding,) = (await session.scalars(select(Finding))).all()
    assert finding.event_id == event.id
    assert (finding.rule_id, finding.attack_class, finding.span_start, finding.span_end) == (
        "test-001",
        "A1",
        7,
        14,
    )


async def test_upstream_failure_still_logs_request(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    upstream.post("/chat/completions").mock(side_effect=httpx.ConnectError("refused"))
    await client.post("/v1/chat/completions", json=chat_body("hello"), headers=auth)
    (event,) = await _events(app)
    assert event.direction == "request"


async def test_streaming_events_written(
    app: FastAPI, client: httpx.AsyncClient, upstream: respx.MockRouter, auth: dict[str, str]
) -> None:
    async def sse() -> AsyncIterator[bytes]:
        for word in ("my ", "key ", FAKE_SECRET):
            chunk = {"model": "s-1", "choices": [{"delta": {"content": word}}]}
            yield f"data: {json.dumps(chunk)}\n\n".encode()
        yield b"data: [DONE]\n\n"

    upstream.post("/chat/completions").mock(
        return_value=httpx.Response(
            200, content=sse(), headers={"Content-Type": "text/event-stream"}
        )
    )
    response = await client.post(
        "/v1/chat/completions", json=chat_body("hi", stream=True), headers=auth
    )
    assert FAKE_SECRET in response.text  # M1 does not filter streams yet; M2 adds hold-back

    _, response_event = await _events(app)
    assert response_event.excerpt_redacted == "my key [REDACTED:api_key]"
    assert response_event.upstream_model == "s-1"
    assert FAKE_SECRET not in await _dump_all_tables(app)


async def test_logs_contain_no_prompt_or_secret(
    client: httpx.AsyncClient,
    upstream: respx.MockRouter,
    auth: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    prompt = f"confidential plan {FAKE_SECRET}"
    upstream.post("/chat/completions").respond(200, json=completion(prompt))
    await client.post("/v1/chat/completions", json=chat_body(prompt), headers=auth)
    assert caplog.records, "expected the gateway to log something"
    logged = "\n".join(
        f"{r.getMessage()} {r.__dict__}" for r in caplog.records if r.name.startswith("gateway")
    )
    assert FAKE_SECRET not in logged
    assert "confidential plan" not in logged
