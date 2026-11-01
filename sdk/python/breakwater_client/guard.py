"""``guarded_tool``: check each tool call with the gateway before running it."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, TypeVar, cast

from breakwater_client.client import GatewayClient

F = TypeVar("F", bound=Callable[..., Any])
SessionSource = str | Callable[[], str | None] | None


class ToolDenied(PermissionError):
    def __init__(self, tool_name: str, verdict: dict[str, Any]) -> None:
        super().__init__(f"{tool_name} denied by gateway: {verdict.get('reason')}")
        self.tool_name = tool_name
        self.verdict = verdict
        self.rule_id = verdict.get("rule_id")


class ConfirmationRequired(PermissionError):
    def __init__(self, tool_name: str, verdict: dict[str, Any]) -> None:
        super().__init__(f"{tool_name} needs human confirmation: {verdict.get('reason')}")
        self.tool_name = tool_name
        self.verdict = verdict
        self.rule_id = verdict.get("rule_id")


def _session(source: SessionSource) -> str | None:
    return source() if callable(source) else source


def _arguments(
    func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    bound = inspect.signature(func).bind(*args, **kwargs)
    bound.apply_defaults()
    return {k: v for k, v in bound.arguments.items() if k not in ("self", "cls")}


def _decide(
    tool_name: str, verdict: dict[str, Any], confirm: Callable[[str, dict[str, Any]], bool] | None
) -> None:
    decision = verdict.get("decision")
    if decision == "allow":
        return
    if decision == "require_confirmation":
        if confirm is not None and confirm(tool_name, verdict):
            return
        raise ConfirmationRequired(tool_name, verdict)
    raise ToolDenied(tool_name, verdict)


def guarded_tool(
    client: GatewayClient,
    agent_id: str,
    tool_name: str | None = None,
    session: SessionSource = None,
    confirm: Callable[[str, dict[str, Any]], bool] | None = None,
) -> Callable[[F], F]:
    """Decorate a tool function (sync or async). Its bound arguments are sent to
    ``/v1/scan/tool-call`` before every call; the function runs only on ``allow``, or on
    ``require_confirmation`` when ``confirm(tool_name, verdict)`` returns True.

    ``session`` is a session id or a callable returning one (for the taint check)."""

    def decorate(func: F) -> F:
        name = tool_name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                verdict = await client.acheck_tool_call(
                    agent_id, name, _arguments(func, args, kwargs), session=_session(session)
                )
                _decide(name, verdict, confirm)
                return await func(*args, **kwargs)

            return cast(F, async_wrapper)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            verdict = client.check_tool_call(
                agent_id, name, _arguments(func, args, kwargs), session=_session(session)
            )
            _decide(name, verdict, confirm)
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorate
