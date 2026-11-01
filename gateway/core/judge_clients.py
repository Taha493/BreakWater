"""Model clients for the LLM judge (spec section 6, layer 3). The provider and model come
from settings; no model name is built in.

- ``anthropic``: the Anthropic Messages API through the official SDK, with structured
  outputs (``output_config.format``) so the reply is JSON matching the verdict schema.
- ``groq``, ``gemini``, ``openai_compatible``: a ``/chat/completions`` endpoint (Groq's and
  Gemini's OpenAI-compatible APIs, or any other, hosted or local such as vLLM or Ollama),
  with ``response_format`` set to the JSON schema, to JSON object mode, or left out.

Clients never retry: the judge has a hard timeout, and a failed call goes to the policy's
``judge_error`` failure mode.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

import anthropic
import httpx
import httpx2
from anthropic.types import MessageParam, OutputConfigParam

Effort = Literal["low", "medium", "high", "xhigh", "max"]
JsonMode = Literal["json_schema", "json_object", "none"]


class JudgeCallError(RuntimeError):
    """The judge model could not give a usable answer (error, refusal, truncation)."""


class JudgeClient(Protocol):
    @property
    def model(self) -> str: ...

    async def complete(
        self, system: str, user: str, schema: dict[str, Any], time_limit: float
    ) -> str:
        """The model's reply text, which should be JSON matching ``schema``."""
        ...

    async def aclose(self) -> None: ...


class AnthropicJudgeClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        max_tokens: int,
        effort: Effort | None = None,
        base_url: str | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        http_client = httpx2.AsyncClient(transport=transport) if transport else None
        self._client = anthropic.AsyncAnthropic(
            api_key=api_key, base_url=base_url, max_retries=0, http_client=http_client
        )
        self._model = model
        self._max_tokens = max_tokens
        self._effort = effort

    @property
    def model(self) -> str:
        return self._model

    async def complete(
        self, system: str, user: str, schema: dict[str, Any], time_limit: float
    ) -> str:
        output_config: OutputConfigParam = {"format": {"type": "json_schema", "schema": schema}}
        if self._effort:
            output_config["effort"] = self._effort
        messages: list[MessageParam] = [{"role": "user", "content": user}]
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=system,
                messages=messages,
                output_config=output_config,
                timeout=time_limit,
            )
        except anthropic.APIStatusError as exc:
            raise JudgeCallError(f"judge API error: HTTP {exc.status_code}") from exc
        except anthropic.APIConnectionError as exc:
            raise JudgeCallError(f"judge API unreachable: {type(exc).__name__}") from exc
        if response.stop_reason in ("refusal", "max_tokens"):
            raise JudgeCallError(f"judge stopped early: {response.stop_reason}")
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            raise JudgeCallError("judge reply had no text")
        return text

    async def aclose(self) -> None:
        await self._client.close()


def _error_kind(response: httpx.Response) -> str:
    """The provider's error type and code, never its message (which can quote the
    inspected text or the model's output)."""
    try:
        error = response.json().get("error")
    except (ValueError, AttributeError):
        return ""
    if not isinstance(error, dict):
        return ""
    parts = [str(error[k])[:64] for k in ("type", "code") if isinstance(error.get(k), str)]
    return f" ({', '.join(parts)})" if parts else ""


class OpenAICompatibleJudgeClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        max_tokens: int,
        json_mode: JsonMode = "json_schema",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"), headers=headers, transport=transport
        )
        self._model = model
        self._max_tokens = max_tokens
        self._json_mode = json_mode

    @property
    def model(self) -> str:
        return self._model

    async def complete(
        self, system: str, user: str, schema: dict[str, Any], time_limit: float
    ) -> str:
        body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if self._json_mode == "json_schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "verdict", "schema": schema, "strict": True},
            }
        elif self._json_mode == "json_object":
            body["response_format"] = {"type": "json_object"}
        try:
            response = await self._client.post("/chat/completions", json=body, timeout=time_limit)
        except httpx.HTTPError as exc:
            raise JudgeCallError(f"judge API unreachable: {type(exc).__name__}") from exc
        if not response.is_success:
            raise JudgeCallError(
                f"judge API error: HTTP {response.status_code}{_error_kind(response)}"
            )
        try:
            choice = response.json()["choices"][0]
            content = choice["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise JudgeCallError("judge reply was not a chat completion") from exc
        if choice.get("finish_reason") == "length" or not isinstance(content, str):
            raise JudgeCallError("judge reply was cut off or empty")
        reply: str = content
        return reply

    async def aclose(self) -> None:
        await self._client.aclose()
