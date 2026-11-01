"""Fingerprints of untrusted text, for the tool guard's taint check (spec section 7).

Untrusted text (retrieved chunks, tool results) seen in a session is reduced to keyed hashes
of 6-word shingles and of "entities" (URLs, emails, domains, file paths, long numbers).
Entities matter because injected arguments are often too short for shingles, such as one
email address. Only hashes are stored, never the text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from gateway.core.normalize import normalize
from gateway.core.redact import Hasher

SHINGLE_WORDS = 6
MAX_FINGERPRINTS = 5000

_WORD = re.compile(r"\w+")
_ENTITIES = (
    re.compile(r"https?://[^\s<>\"'()\[\]]{3,2000}"),
    re.compile(r"\b[\w.%+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b"),
    re.compile(
        r"\b(?:[a-z0-9-]{1,63}\.){1,8}(?:com|net|org|io|dev|app|co|info|biz|xyz|ai|[a-z]{2})\b"
    ),
    re.compile(r"(?:~|\.{1,2})?(?:/[\w.-]{1,255}){2,32}"),
    re.compile(r"\b[A-Za-z]:\\(?:[\w.-]{1,255}\\?){1,32}"),
    re.compile(r"\b\d{6,}\b"),
)
_TRAILING = ".,;:!?)]}'\""


def entities(text: str) -> Iterator[str]:
    lowered = text.lower()
    for pattern in _ENTITIES:
        for match in pattern.finditer(lowered):
            value = match.group().rstrip(_TRAILING)
            if len(value) >= 4:
                yield value


def shingles(text: str) -> Iterator[str]:
    words = [w.lower() for w in _WORD.findall(text)]
    for i in range(len(words) - SHINGLE_WORDS + 1):
        yield " ".join(words[i : i + SHINGLE_WORDS])


def fingerprints(text: str, hasher: Hasher) -> set[str]:
    text = normalize(text).text
    found: set[str] = set()
    for value in entities(text):
        found.add(hasher.taint("e:" + value))
    for value in shingles(text):
        found.add(hasher.taint("s:" + value))
        if len(found) >= MAX_FINGERPRINTS:
            break
    return found


def argument_strings(arguments: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string value in a JSON-like structure, with its dotted path."""
    if isinstance(arguments, str):
        yield path or "$", arguments
    elif isinstance(arguments, dict):
        for key, value in arguments.items():
            yield from argument_strings(value, f"{path}.{key}" if path else str(key))
    elif isinstance(arguments, list):
        for index, value in enumerate(arguments):
            yield from argument_strings(value, f"{path}[{index}]")
