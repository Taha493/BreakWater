"""A deliberately vulnerable RAG app: the red-team target (spec sections 4 and 8).

Its ingestion is naive on purpose: text hidden from human readers (CSS-hidden HTML, white
PDF text, hidden Word runs) is extracted and indexed like any other text. Each request picks
a mode:

- ``protected: false`` sends retrieved chunks straight to the model, the way many RAG apps
  do. Hidden instructions reach the model.
- ``protected: true`` re-scans retrieved chunks with the gateway, leaves out quarantined
  ones, wraps the rest in hardened delimiters, and calls the model through the gateway.

Never expose this app to the public internet.

Run: uv run uvicorn demo_app.vulnerable_rag:app --port 8100
"""

from __future__ import annotations

import hashlib
import io
import math
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from qdrant_client import QdrantClient, models

SAMPLE_DOCS = Path(__file__).parent / "sample_docs"
COLLECTION = "demo_docs"
SYSTEM_PROMPT = (
    "You are the support assistant for Contoso. Answer the customer's question using only "
    "the provided context. Be brief."
)
_WORD = re.compile(r"\w+")
_STOPWORDS = frozenset(
    "a an and are as at be by can do for from how i in is it of on or the to what when "
    "with you your".split()
)


class DemoSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DEMO_", env_file=".env", extra="ignore")

    gateway_url: str = "http://localhost:8000"
    gateway_key: str | None = None
    upstream_base_url: str = "http://localhost:9000/v1"
    upstream_api_key: str = "demo-upstream-key"
    model: str = "mock-model"
    qdrant_url: str = ":memory:"
    docs_dir: Path = SAMPLE_DOCS
    top_k: int = Field(default=3, ge=1, le=20)
    embedding_dim: int = Field(default=512, ge=64)


# ---- naive ingestion -----------------------------------------------------------------


def naive_extract(path: Path) -> str:
    """Extract all text, hidden or not: the vulnerability this demo exists to show."""
    data = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix in (".html", ".htm"):
        return BeautifulSoup(data, "html.parser").get_text(" ")
    if suffix == ".pdf":
        import pdfplumber

        with pdfplumber.open(io.BytesIO(data)) as pdf:
            return "\n\n".join(page.extract_text() or "" for page in pdf.pages)
    if suffix == ".docx":
        import docx

        document = docx.Document(io.BytesIO(data))
        return "\n\n".join(p.text for p in document.paragraphs)
    return data.decode("utf-8")


def split_chunks(text: str, max_chars: int = 600) -> list[str]:
    paragraphs = [" ".join(p.split()) for p in re.split(r"\n\s*\n", text)]
    chunks: list[str] = []
    current = ""
    for paragraph in (p for p in paragraphs if p):
        if current and len(current) + len(paragraph) + 1 > max_chars:
            chunks.append(current)
            current = ""
        current = f"{current} {paragraph}".strip()
    if current:
        chunks.append(current)
    return chunks


class HashingEmbedder:
    """Deterministic bag-of-words embeddings via feature hashing. No model download: crude,
    but reproducible and enough for keyword-style retrieval over a few documents."""

    def __init__(self, dim: int) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for word in (w.lower() for w in _WORD.findall(text)):
            if word in _STOPWORDS:
                continue
            digest = hashlib.blake2b(word.encode(), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dim
            vector[index] += 1.0 if digest[4] % 2 else -1.0
        norm = math.sqrt(sum(v * v for v in vector)) or 1.0
        return [v / norm for v in vector]


# ---- API -----------------------------------------------------------------------------


class IngestRequest(BaseModel):
    protected: bool = True


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    protected: bool = True
    session: str | None = Field(default=None, max_length=128)


def _point_id(doc_id: str, index: int) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"demo:{doc_id}:{index}"))


def create_app(
    settings: DemoSettings | None = None,
    gateway_transport: httpx.AsyncBaseTransport | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    settings = settings or DemoSettings()
    embedder = HashingEmbedder(settings.embedding_dim)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if settings.qdrant_url == ":memory:":
            qdrant = QdrantClient(location=":memory:")
        else:
            qdrant = QdrantClient(url=settings.qdrant_url)
        if not qdrant.collection_exists(COLLECTION):
            qdrant.create_collection(
                COLLECTION,
                vectors_config=models.VectorParams(
                    size=settings.embedding_dim, distance=models.Distance.COSINE
                ),
            )
        app.state.qdrant = qdrant
        app.state.gateway = httpx.AsyncClient(
            base_url=settings.gateway_url, timeout=60, transport=gateway_transport
        )
        app.state.upstream = httpx.AsyncClient(
            base_url=settings.upstream_base_url,
            headers={"Authorization": f"Bearer {settings.upstream_api_key}"},
            timeout=60,
            transport=upstream_transport,
        )
        try:
            yield
        finally:
            await app.state.gateway.aclose()
            await app.state.upstream.aclose()
            qdrant.close()

    app = FastAPI(title="Vulnerable RAG demo", lifespan=lifespan)

    def gateway_headers(key: str | None) -> dict[str, str]:
        key = key or settings.gateway_key
        if not key:
            raise HTTPException(400, "Protected mode needs a gateway key (X-Gateway-Key)")
        return {"Authorization": f"Bearer {key}"}

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/ingest")
    async def ingest(
        payload: IngestRequest,
        x_gateway_key: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        documents: list[dict[str, Any]] = []
        points: list[models.PointStruct] = []
        for path in sorted(settings.docs_dir.iterdir()):
            if path.name.startswith(".") or path.suffix == ".py":
                continue
            chunks = split_chunks(naive_extract(path))
            for index, chunk in enumerate(chunks):
                points.append(
                    models.PointStruct(
                        id=_point_id(path.name, index),
                        vector=embedder.embed(chunk),
                        payload={"doc_id": path.name, "index": index, "text": chunk},
                    )
                )
            entry: dict[str, Any] = {"doc_id": path.name, "chunks": len(chunks)}
            if payload.protected and chunks:
                response = await app.state.gateway.post(
                    "/v1/scan/document",
                    json={
                        "mode": "ingest",
                        "doc_id": path.name,
                        "source": "demo_app/sample_docs",
                        "trust_level": "public_web",
                        "chunks": chunks,
                        "app": "demo_rag",
                    },
                    headers=gateway_headers(x_gateway_key),
                )
                response.raise_for_status()
                entry["gateway_status"] = response.json()["status"]
            documents.append(entry)
        # Everything is indexed, hidden text included: protection happens at retrieval.
        app.state.qdrant.upsert(COLLECTION, points=points)
        return {"documents": documents, "indexed_chunks": len(points)}

    @app.post("/ask")
    async def ask(
        payload: AskRequest,
        x_gateway_key: Annotated[str | None, Header()] = None,
    ) -> dict[str, Any]:
        hits = app.state.qdrant.query_points(
            COLLECTION, query=embedder.embed(payload.question), limit=settings.top_k
        ).points
        retrieved = [
            {"doc_id": h.payload["doc_id"], "index": h.payload["index"], "text": h.payload["text"]}
            for h in hits
            if h.payload
        ]
        excluded: list[dict[str, Any]] = []
        context = retrieved
        if payload.protected and retrieved:
            headers = gateway_headers(x_gateway_key)
            scan = await app.state.gateway.post(
                "/v1/scan/document",
                json={
                    "mode": "retrieval",
                    "chunks": [c["text"] for c in retrieved],
                    "trust_level": "public_web",
                    "app": "demo_rag",
                    **({"session": payload.session} if payload.session else {}),
                },
                headers=headers,
            )
            scan.raise_for_status()
            context = []
            for chunk, verdict in zip(retrieved, scan.json()["chunks"], strict=True):
                chunk["cached"] = verdict["cached"]
                if verdict["allowed"]:
                    context.append(chunk)
                else:
                    excluded.append({**chunk, "status": verdict["status"]})

        texts = [c["text"] for c in context]
        if payload.protected:
            from aisg_client import harden_context

            context_block = harden_context(texts)
        else:
            context_block = "\n\n".join(texts)
        body = {
            "model": settings.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Context:\n{context_block}\n\nQuestion: {payload.question}",
                },
            ],
        }
        if payload.protected:
            headers = {**gateway_headers(x_gateway_key), "X-Gateway-App": "demo_rag"}
            if payload.session:
                headers["X-Gateway-Session"] = payload.session
            response = await app.state.gateway.post(
                "/v1/chat/completions", json=body, headers=headers
            )
        else:
            response = await app.state.upstream.post("/chat/completions", json=body)

        result: dict[str, Any] = {
            "protected": payload.protected,
            "context": [{k: v for k, v in c.items() if k != "text"} for c in context],
            "excluded": [{k: v for k, v in c.items() if k != "text"} for c in excluded],
            "status_code": response.status_code,
            "gateway_verdict": response.headers.get("X-Gateway-Verdict"),
        }
        data = response.json()
        if response.is_success:
            result["answer"] = data["choices"][0]["message"]["content"]
        else:
            result["error"] = data.get("error")
        return result

    return app


app = create_app()
