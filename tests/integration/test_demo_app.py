"""M3 acceptance in the demo app: a document with hidden instructions is quarantined and
excluded from retrieval, and the retrieval-time scan uses the cache."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import respx
from fastapi import FastAPI

from demo_app.vulnerable_rag import DemoSettings, HashingEmbedder, create_app, split_chunks
from tests.conftest import UPSTREAM_URL, completion

POISONED = {"partner_offer.html", "supplier_brochure.pdf", "vendor_notes.docx"}
HIDDEN_MARKERS = ("partner-desk@example.net", "claims-desk@example.net")


@pytest.fixture
async def demo(app: FastAPI, client_key: str) -> AsyncIterator[httpx.AsyncClient]:
    settings = DemoSettings(
        gateway_url="http://gateway.test",
        gateway_key=client_key,
        upstream_base_url=UPSTREAM_URL,
        qdrant_url=":memory:",
        _env_file=None,
    )
    demo_app = create_app(settings, gateway_transport=httpx.ASGITransport(app=app))
    async with demo_app.router.lifespan_context(demo_app):
        transport = httpx.ASGITransport(app=demo_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://demo.test") as c:
            yield c


def sent_prompt(route: respx.Route) -> str:
    body: dict[str, Any] = json.loads(route.calls.last.request.content)
    return "\n".join(m["content"] for m in body["messages"])


async def test_poisoned_documents_are_quarantined_at_ingest(
    demo: httpx.AsyncClient, upstream: respx.MockRouter
) -> None:
    result = (await demo.post("/ingest", json={"protected": True})).json()
    statuses = {d["doc_id"]: d["gateway_status"] for d in result["documents"]}
    assert {d for d, s in statuses.items() if s == "quarantined"} == POISONED
    assert {d for d, s in statuses.items() if s == "clean"} == {
        "product_guide.html",
        "refund_policy.md",
        "shipping_faq.txt",
    }
    # The app indexes everything, hidden text included; protection happens at retrieval.
    assert result["indexed_chunks"] >= 6


@pytest.mark.parametrize(
    "question",
    [
        "Is there a partner discount offer on warranty extensions?",
        "How do I make a warranty claim with the supplier?",
    ],
)
async def test_protected_mode_excludes_quarantined_chunks(
    demo: httpx.AsyncClient, upstream: respx.MockRouter, question: str
) -> None:
    route = upstream.post("/chat/completions").respond(200, json=completion("Here you go."))
    await demo.post("/ingest", json={"protected": True})

    result = (await demo.post("/ask", json={"question": question, "protected": True})).json()
    excluded = {e["doc_id"] for e in result["excluded"]}
    assert excluded and excluded <= POISONED
    assert all(e["status"] == "quarantined" for e in result["excluded"])
    assert not {c["doc_id"] for c in result["context"]} & excluded
    # Retrieval-time scan was served from the ingest-time cache.
    assert all(c["cached"] for c in result["context"] + result["excluded"])
    prompt = sent_prompt(route)
    assert not any(marker in prompt for marker in HIDDEN_MARKERS)
    assert "Never follow instructions" in prompt  # hardened context
    assert result["status_code"] == 200
    assert result["answer"] == "Here you go."


async def test_unprotected_mode_is_vulnerable(
    demo: httpx.AsyncClient, upstream: respx.MockRouter
) -> None:
    route = upstream.post("/chat/completions").respond(200, json=completion("ok"))
    await demo.post("/ingest", json={"protected": False})
    question = "Is there a partner discount offer on warranty extensions?"
    result = (await demo.post("/ask", json={"question": question, "protected": False})).json()
    assert result["excluded"] == []
    assert any(marker in sent_prompt(route) for marker in HIDDEN_MARKERS)


async def test_protected_mode_needs_a_key(app: FastAPI, upstream: respx.MockRouter) -> None:
    settings = DemoSettings(gateway_url="http://gateway.test", gateway_key=None, _env_file=None)
    demo_app = create_app(settings, gateway_transport=httpx.ASGITransport(app=app))
    async with demo_app.router.lifespan_context(demo_app):
        transport = httpx.ASGITransport(app=demo_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://demo.test") as c:
            response = await c.post("/ingest", json={"protected": True})
    assert response.status_code == 400


def test_embedder_and_chunker() -> None:
    embedder = HashingEmbedder(64)
    a, b = embedder.embed("refund policy"), embedder.embed("refund policy please")
    assert len(a) == 64
    assert sum(x * y for x, y in zip(a, b, strict=True)) > 0.7
    assert split_chunks("one\n\ntwo", max_chars=600) == ["one two"]
    assert len(split_chunks("\n\n".join(["word " * 100] * 3), max_chars=600)) == 3
