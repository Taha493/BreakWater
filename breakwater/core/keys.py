"""Gateway API key format: ``gw.<16 hex id>.<secret>``. Only an HMAC of the full key is stored."""

from __future__ import annotations

import hmac
import re
import secrets
from dataclasses import dataclass
from enum import StrEnum

KEY_PREFIX = "gw"
_KEY_RE = re.compile(r"gw\.([0-9a-f]{16})\.([A-Za-z0-9_-]{32,128})")


class KeyRole(StrEnum):
    CLIENT = "client"
    ADMIN = "admin"


@dataclass(frozen=True)
class GeneratedKey:
    key_id: str
    plaintext: str


def generate_key() -> GeneratedKey:
    key_id = secrets.token_hex(8)
    return GeneratedKey(
        key_id=key_id, plaintext=f"{KEY_PREFIX}.{key_id}.{secrets.token_urlsafe(32)}"
    )


def parse_key_id(plaintext: str) -> str | None:
    """Return the public key id, or None if the string is not a well-formed gateway key."""
    match = _KEY_RE.fullmatch(plaintext)
    return match.group(1) if match else None


def hashes_match(expected: str, actual: str) -> bool:
    return hmac.compare_digest(expected.encode(), actual.encode())
