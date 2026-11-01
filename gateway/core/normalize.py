"""Layer 0: normalize text so obfuscation cannot hide an attack (spec section 6).

``build_views`` returns the original text plus derived views: a normalized copy (NFKC,
invisible characters removed, homoglyphs folded, whitespace collapsed), and the contents of
HTML/markdown comments and base64, hex, or URL-encoded segments, decoded up to two levels.
Detectors scan every view; ``View.to_original`` maps a match back to a span in the original.

All scanning here is linear in the input size: comment and token extraction use ``str.find``
or single character-class runs, never patterns that can backtrack.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote_plus

MAX_DECODE_DEPTH = 2
MAX_EXTRACTED_VIEWS = 32
MAX_EXTRACTED_CHARS = 200_000

# Characters that render as nothing but are not in the Cf/Mn categories.
_INVISIBLE = frozenset("ᅟᅠㅤﾠ⠀")
_DROPPED_CATEGORIES = frozenset({"Cf", "Mn", "Me", "Co", "Cs", "Cn"})

# Common Cyrillic and Greek lookalikes of Latin letters. NFKC already folds fullwidth and
# mathematical alphanumerics, so only cross-script confusables need a table.
_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic lowercase
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
        "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ү": "y",
        # Cyrillic uppercase
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
        "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S", "Ү": "Y",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ι": "i", "ρ": "p", "κ": "k", "υ": "u", "τ": "t",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
        "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
        # Latin variants
        "ı": "i", "ɡ": "g", "ⅼ": "l",
    }
)  # fmt: skip

# Text that is plain printable ASCII with single spaces is already normalized.
_NEEDS_NORMALIZING = re.compile(r"[^\x20-\x7e]|  ")

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_ESCAPED_HEX_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_URL_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_NON_SPACE_RUN = re.compile(r"\S+")
_MARKDOWN_COMMENT = re.compile(r"\[(?://|comment)\]: ?(?:#|<>) ?\(([^()\[\]]{0,4000})\)")


@lru_cache(maxsize=8192)
def _fold_char(ch: str) -> str:
    out: list[str] = []
    for c in unicodedata.normalize("NFKC", ch):
        if c.isspace():
            out.append(" ")
            continue
        category = unicodedata.category(c)
        if c in _INVISIBLE or category in _DROPPED_CATEGORIES or category == "Cc":
            continue
        out.append(c.translate(_HOMOGLYPHS))
    return "".join(out)


@dataclass(frozen=True)
class Normalized:
    text: str
    # offsets[i] is the index in the input of the character that produced text[i].
    offsets: tuple[int, ...]
    # How many input characters were dropped as invisible or control characters.
    removed: int


def normalize(text: str) -> Normalized:
    if _NEEDS_NORMALIZING.search(text) is None:
        return Normalized(text, tuple(range(len(text))), 0)
    chars: list[str] = []
    offsets: list[int] = []
    removed = 0
    for i, ch in enumerate(text):
        folded = _fold_char(ch)
        if not folded and not ch.isspace():
            removed += 1
        for c in folded:
            if c == " " and chars and chars[-1] == " ":
                continue
            chars.append(c)
            offsets.append(i)
    return Normalized("".join(chars), tuple(offsets), removed)


@dataclass(frozen=True)
class View:
    """One way of reading the input. ``kind`` says how it was derived."""

    kind: str
    text: str
    offsets: tuple[int, ...] | None = None  # per-character map into the original
    origin: tuple[int, int] | None = None  # extracted views map to this whole original span

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        if self.origin is not None:
            return self.origin
        if self.offsets is None:
            return (start, end)
        if not self.offsets:
            return (0, 0)
        start = min(start, len(self.offsets) - 1)
        last = min(max(end - 1, start), len(self.offsets) - 1)
        return (self.offsets[start], self.offsets[last] + 1)


@dataclass(frozen=True)
class Views:
    original: View
    all: tuple[View, ...]
    # Invisible characters removed and comments found: signals of hidden text (used in M3).
    removed_chars: int
    comment_count: int


def _printable_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 6:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    letters = sum(1 for c in text if c.isalpha())
    if printable / len(text) < 0.9 or letters < 3:
        return None
    return text


def _decode_base64(token: str) -> str | None:
    stripped = token.rstrip("=")
    if stripped.isalpha() or stripped.isdigit() or _HEX_RUN.fullmatch(stripped):
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    altchars = b"-_" if ("-" in padded or "_" in padded) else None
    try:
        raw = base64.b64decode(padded, altchars=altchars, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable_text(raw)


def _decode_hex(token: str) -> str | None:
    try:
        return _printable_text(bytes.fromhex(token.replace("\\x", "")))
    except ValueError:
        return None


def _comments(text: str) -> list[tuple[int, int, str]]:
    """HTML ``<!-- -->`` and markdown ``[//]: # (...)`` comments as (start, end, content)."""
    found: list[tuple[int, int, str]] = []
    pos = 0
    while (start := text.find("<!--", pos)) != -1:
        close = text.find("-->", start + 4)
        end = len(text) if close == -1 else close + 3
        found.append((start, end, text[start + 4 : close if close != -1 else len(text)]))
        pos = end
    for m in _MARKDOWN_COMMENT.finditer(text):
        found.append((m.start(), m.end(), m.group(1)))
    return found


def _encoded(text: str) -> list[tuple[int, int, str, str]]:
    """Decodable segments as (start, end, kind, decoded text)."""
    found: list[tuple[int, int, str, str]] = []
    for m in _BASE64_RUN.finditer(text):
        if (decoded := _decode_base64(m.group())) is not None:
            found.append((m.start(), m.end(), "base64", decoded))
    for pattern in (_HEX_RUN, _ESCAPED_HEX_RUN):
        for m in pattern.finditer(text):
            if (decoded := _decode_hex(m.group())) is not None:
                found.append((m.start(), m.end(), "hex", decoded))
    for m in _NON_SPACE_RUN.finditer(text):
        token = m.group()
        if "%" in token and len(_URL_ESCAPE.findall(token)) >= 2:
            decoded = unquote_plus(token)
            if decoded != token:
                found.append((m.start(), m.end(), "url", decoded))
    return found


def build_views(text: str) -> Views:
    original = View("original", text)
    norm = normalize(text)
    views: list[View] = [original]
    if norm.text != text:
        views.append(View("normalized", norm.text, offsets=norm.offsets))
    base = views[-1]

    budget = MAX_EXTRACTED_CHARS
    comments = _comments(base.text)

    def add(kind: str, content: str, origin: tuple[int, int]) -> View | None:
        nonlocal budget
        if len(views) - 2 >= MAX_EXTRACTED_VIEWS or budget <= 0:
            return None
        content = normalize(content[:budget]).text
        budget -= len(content)
        view = View(kind, content, origin=origin)
        views.append(view)
        return view

    for start, end, content in comments:
        add("comment", content, base.to_original(start, end))

    frontier = [(base, base.to_original)]
    for depth in range(MAX_DECODE_DEPTH):
        next_frontier = []
        for view, mapper in frontier:
            for start, end, kind, decoded in _encoded(view.text):
                origin = view.origin if view.origin is not None else mapper(start, end)
                child = add(kind if depth == 0 else f"{kind}(nested)", decoded, origin)
                if child is not None:
                    next_frontier.append((child, child.to_original))
        frontier = next_frontier

    return Views(
        original=original,
        all=tuple(views),
        removed_chars=norm.removed,
        comment_count=len(comments),
    )
