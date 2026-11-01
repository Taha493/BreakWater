"""Keyed hashing and excerpt redaction, applied before anything is stored or logged (spec 9).

The patterns here are a stopgap so M1 never stores a raw secret. M2 replaces them with the
``leak_secrets`` and ``leak_pii`` detectors and ``rules/secrets.yaml``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata

EXCERPT_CHARS = 160

# Order matters: multi-line and specific formats run before the generic catch-alls.
# Every pattern is linear (no nested quantifiers) so crafted input cannot cause backtracking.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
            r".*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|\Z)",
            re.DOTALL,
        ),
    ),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("gateway_key", re.compile(r"\bgw\.[0-9a-f]{16}\.[A-Za-z0-9_-]{16,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    (
        "credential",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token)\b[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{6,}"
        ),
    ),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")),
    ("national_id", re.compile(r"\b\d{5}-\d{7}-\d\b")),
    ("number", re.compile(r"(?<![\w-])\+?(?:\d[ -]?){8,18}\d(?![\w-])")),
]

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


def redact(text: str) -> str:
    """Replace known secret and PII formats with ``[REDACTED:<kind>]``."""
    for kind, pattern in _PATTERNS:
        text = pattern.sub(f"[REDACTED:{kind}]", text)
    return text


def excerpt(text: str, limit: int = EXCERPT_CHARS) -> str:
    """A short, redacted, single-line excerpt that is safe to store and display.

    Redaction runs on the whole text before truncation, so a secret cut by the limit
    cannot leave a raw prefix behind.
    """
    cleaned = "".join(
        " " if unicodedata.category(ch) in _CONTROL_CATEGORIES else ch for ch in redact(text)
    )
    collapsed = " ".join(cleaned.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"
