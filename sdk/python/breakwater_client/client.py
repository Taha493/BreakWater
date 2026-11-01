"""HTTP client for the gateway's scan endpoints, with sync and async methods."""

from __future__ import annotations

from typing import Any

import httpx

DEFAULT_TIMEOUT = 30.0


class GatewayError(Exception):
    """The gateway returned an error (its ``error`` object is in ``body``)."""

    def __init__(self, status_code: int, body: Any) -> None:
        error = body.get("error", {}) if isinstance(body, dict) else {}
        super().__init__(f"gateway returned {status_code}: {error.get('code', 'error')}")
        self.status_code = status_code
        self.body = body
        self.code = error.get("code")


def _result(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.is_error or not isinstance(body, dict):
        raise GatewayError(response.status_code, body)
    return body


class GatewayClient:
    """``base_url`` is the gateway root (for example ``http://localhost:8000``).

    ``transport`` and ``async_transport`` let tests or custom setups supply httpx transports.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
        async_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"}
        self._sync = httpx.Client(
            base_url=base_url, headers=headers, timeout=timeout, transport=transport
        )
        self._async = httpx.AsyncClient(
            base_url=base_url, headers=headers, timeout=timeout, transport=async_transport
        )

    def close(self) -> None:
        self._sync.close()

    async def aclose(self) -> None:
        await self._async.aclose()

    # ---- text --------------------------------------------------------------------------

    def scan_text(self, text: str, role: str, **context: Any) -> dict[str, Any]:
        return _result(
            self._sync.post("/v1/scan/text", json={"text": text, "role": role, "context": context})
        )

    async def ascan_text(self, text: str, role: str, **context: Any) -> dict[str, Any]:
        payload = {"text": text, "role": role, "context": context}
        return _result(await self._async.post("/v1/scan/text", json=payload))

    # ---- documents ---------------------------------------------------------------------

    @staticmethod
    def _chunks_payload(
        chunks: list[str],
        mode: str,
        doc_id: str | None,
        source: str | None,
        trust_level: str,
        session: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"mode": mode, "chunks": chunks, "trust_level": trust_level}
        for key, value in (("doc_id", doc_id), ("source", source), ("session", session)):
            if value is not None:
                payload[key] = value
        return payload

    def scan_chunks(
        self,
        chunks: list[str],
        doc_id: str,
        source: str | None = None,
        trust_level: str = "public_web",
        mode: str = "ingest",
        session: str | None = None,
    ) -> dict[str, Any]:
        """Scan chunks at ingest (default) or retrieval. Index or use only chunks whose
        result has ``allowed: true``."""
        payload = self._chunks_payload(chunks, mode, doc_id, source, trust_level, session)
        return _result(self._sync.post("/v1/scan/document", json=payload))

    async def ascan_chunks(
        self,
        chunks: list[str],
        doc_id: str | None = None,
        source: str | None = None,
        trust_level: str = "public_web",
        mode: str = "ingest",
        session: str | None = None,
    ) -> dict[str, Any]:
        payload = self._chunks_payload(chunks, mode, doc_id, source, trust_level, session)
        return _result(await self._async.post("/v1/scan/document", json=payload))

    def filter_retrieved(
        self, chunks: list[str], trust_level: str = "public_web", session: str | None = None
    ) -> list[str]:
        """Re-scan retrieved chunks and return only the allowed ones, in order."""
        if not chunks:
            return []
        result = self.scan_chunks(
            chunks, doc_id="retrieval", trust_level=trust_level, mode="retrieval", session=session
        )
        return [c for c, r in zip(chunks, result["chunks"], strict=True) if r["allowed"]]

    async def afilter_retrieved(
        self, chunks: list[str], trust_level: str = "public_web", session: str | None = None
    ) -> list[str]:
        if not chunks:
            return []
        result = await self.ascan_chunks(
            chunks, trust_level=trust_level, mode="retrieval", session=session
        )
        return [c for c, r in zip(chunks, result["chunks"], strict=True) if r["allowed"]]

    # ---- tool calls --------------------------------------------------------------------

    @staticmethod
    def _tool_payload(
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        session: str | None,
        triggering_text: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": arguments,
        }
        if session is not None:
            payload["session"] = session
        if triggering_text is not None:
            payload["triggering_text"] = triggering_text
        return payload

    def check_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        session: str | None = None,
        triggering_text: str | None = None,
    ) -> dict[str, Any]:
        payload = self._tool_payload(agent_id, tool_name, arguments, session, triggering_text)
        return _result(self._sync.post("/v1/scan/tool-call", json=payload))

    async def acheck_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        session: str | None = None,
        triggering_text: str | None = None,
    ) -> dict[str, Any]:
        payload = self._tool_payload(agent_id, tool_name, arguments, session, triggering_text)
        return _result(await self._async.post("/v1/scan/tool-call", json=payload))
