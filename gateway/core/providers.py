"""Upstream LLM provider adapters. M1 ships one: any OpenAI-compatible chat completions API."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx


class UpstreamError(Exception):
    """The upstream could not produce a usable response.

    ``message`` is safe to return. ``detail`` is the upstream's own error message, which can
    echo request content: callers must redact it before returning or logging it.
    """

    def __init__(self, status_code: int, code: str, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.detail = detail


def _status_error(response: httpx.Response, body: bytes) -> UpstreamError:
    detail = ""
    try:
        data = json.loads(body)
        if isinstance(data, dict) and isinstance(data.get("error"), dict):
            detail = str(data["error"].get("message", ""))
    except ValueError:
        pass
    message = f"Upstream returned HTTP {response.status_code}"
    return UpstreamError(502, f"upstream_status_{response.status_code}", message, detail)


def _transport_error(exc: httpx.TransportError) -> UpstreamError:
    if isinstance(exc, httpx.TimeoutException):
        return UpstreamError(504, "upstream_timeout", "Upstream did not respond in time")
    return UpstreamError(502, "upstream_unreachable", "Could not reach the upstream provider")


class OpenAICompatibleProvider:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=httpx.Timeout(timeout_seconds),
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def chat_completion(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = await self._client.post("/chat/completions", json=body)
        except httpx.TransportError as exc:
            raise _transport_error(exc) from exc
        if response.is_error:
            raise _status_error(response, response.content)
        try:
            data = response.json()
        except ValueError as exc:
            raise UpstreamError(
                502, "upstream_invalid_response", "Upstream sent invalid JSON"
            ) from exc
        if not isinstance(data, dict):
            raise UpstreamError(502, "upstream_invalid_response", "Upstream sent invalid JSON")
        return data

    @asynccontextmanager
    async def stream_chat_completion(
        self, body: dict[str, Any]
    ) -> AsyncIterator[AsyncIterator[bytes]]:
        """Open a streaming request. Status errors raise before any byte reaches the client;
        transport errors while iterating raise ``UpstreamError``."""
        request = self._client.build_request("POST", "/chat/completions", json=body)
        try:
            response = await self._client.send(request, stream=True)
        except httpx.TransportError as exc:
            raise _transport_error(exc) from exc
        try:
            if response.is_error:
                raise _status_error(response, await response.aread())
            yield self._iter_bytes(response)
        finally:
            await response.aclose()

    @staticmethod
    async def _iter_bytes(response: httpx.Response) -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        except httpx.TransportError as exc:
            raise _transport_error(exc) from exc
