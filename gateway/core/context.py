"""What a detector gets besides the text: Layer 0 views and facts about the call."""

from __future__ import annotations

from dataclasses import dataclass, field

from gateway.core.normalize import Views, build_views


@dataclass(frozen=True)
class CallContext:
    """Facts about the call being inspected. Raw text here is never stored or logged."""

    app: str | None = None
    session: str | None = None
    key_id: str | None = None
    # The request's system prompt, so responses can be checked for echoes of it.
    system_prompt: str | None = None
    # The canary appended to the system prompt for this call, if canaries are enabled.
    canary: str | None = None


@dataclass(frozen=True)
class ScanContext:
    views: Views
    call: CallContext = field(default_factory=CallContext)

    @classmethod
    def for_text(cls, text: str, call: CallContext | None = None) -> ScanContext:
        return cls(views=build_views(text), call=call or CallContext())
