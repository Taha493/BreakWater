"""Keyed hashing, and redaction applied before anything is stored, logged, or shipped (spec 9).

Excerpt redaction uses the same secret and PII detectors as response inspection, so a format
the gateway can detect is also a format it never stores.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from collections.abc import Sequence

from breakwater.core.normalize import build_views
from breakwater.core.policy import Redaction
from breakwater.detectors.leak_pii import LeakPii
from breakwater.detectors.leak_secrets import LeakSecrets

EXCERPT_CHARS = 160
# Excerpts redact only a prefix of the text: enough to cover the excerpt plus any secret
# that starts inside it (private key blocks are the longest formats).
EXCERPT_WINDOW_CHARS = EXCERPT_CHARS + 8192
_CONTROL_CATEGORIES = {"Cc", "Cf"}


class Hasher:
    """HMAC-SHA256 with a server secret, domain-separated per use."""

    def __init__(self, secret: str) -> None:
        self._secret = secret.encode()

    def _digest(self, domain: str, value: str) -> str:
        message = domain.encode() + b"\x00" + value.encode("utf-8", "surrogatepass")
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()

    def text(self, value: str) -> str:
        return self._digest("text", value)

    def user(self, value: str) -> str:
        return self._digest("user", value)

    def api_key(self, value: str) -> str:
        return self._digest("api_key", value)

    def session(self, value: str) -> str:
        return self._digest("session", value)

    def taint(self, value: str) -> str:
        return self._digest("taint", value)

    def canary(self, seed: str) -> str:
        """A stable canary per seed (session), so the gateway needs no state to check it."""
        return "cnry-" + self._digest("canary", seed)[:20]


def placeholder(label: str) -> str:
    return f"[REDACTED:{label}]"


def apply_redactions(text: str, redactions: Sequence[Redaction]) -> str:
    """Replace each span with a placeholder. Overlapping spans merge; a None span is the
    whole text."""
    for r in redactions:
        if r.span is None:
            return placeholder(r.label)
    spans = sorted((r.span[0], r.span[1], r.label) for r in redactions if r.span is not None)
    out: list[str] = []
    pos = 0
    for start, end, label in spans:
        if end <= pos:
            continue
        if start >= pos:
            out.append(text[pos:start])
            out.append(placeholder(label))
        pos = end
    out.append(text[pos:])
    return "".join(out)


class Redactor:
    """Finds every secret and PII span, including low-confidence ones, for safe storage."""

    def __init__(self, secrets: LeakSecrets, pii: LeakPii) -> None:
        self._secrets = secrets
        self._pii = pii

    def redactions(self, text: str) -> list[Redaction]:
        views = build_views(text)
        findings = self._secrets.hits(views) + self._pii.hits(views)
        return [Redaction(f.span, f.rule_id or f.detector) for f in findings if f.span]

    def redact(self, text: str) -> str:
        return apply_redactions(text, self.redactions(text))

    def excerpt(self, text: str, limit: int = EXCERPT_CHARS) -> str:
        """A short, redacted, single-line excerpt that is safe to store and display.

        Redaction runs before truncation, so a secret cut by the limit cannot leave a raw
        prefix behind.
        """
        redacted = self.redact(text[:EXCERPT_WINDOW_CHARS])
        cleaned = "".join(
            " " if unicodedata.category(ch) in _CONTROL_CATEGORIES else ch for ch in redacted
        )
        collapsed = " ".join(cleaned.split())
        if len(collapsed) <= limit:
            return collapsed
        return collapsed[: limit - 1] + "…"
