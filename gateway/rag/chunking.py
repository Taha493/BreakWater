"""Paragraph-aware fixed-size chunking with overlap, for documents the gateway extracts."""

from __future__ import annotations

DEFAULT_CHUNK_CHARS = 1000
DEFAULT_OVERLAP_CHARS = 200


def chunk_text(
    text: str, max_chars: int = DEFAULT_CHUNK_CHARS, overlap: int = DEFAULT_OVERLAP_CHARS
) -> list[str]:
    """Split on blank lines, pack paragraphs up to ``max_chars``, and start each chunk with
    the last ``overlap`` characters of the previous one. Paragraphs longer than ``max_chars``
    are cut on whitespace where possible."""
    if overlap >= max_chars:
        raise ValueError("overlap must be smaller than max_chars")
    pieces: list[str] = []
    for paragraph in (p.strip() for p in text.split("\n\n")):
        while len(paragraph) > max_chars:
            cut = paragraph.rfind(" ", 0, max_chars)
            cut = cut if cut > max_chars // 2 else max_chars
            pieces.append(paragraph[:cut].strip())
            paragraph = paragraph[cut:].strip()
        if paragraph:
            pieces.append(paragraph)

    chunks: list[str] = []
    current = ""
    for piece in pieces:
        candidate = f"{current}\n\n{piece}" if current else piece
        if len(candidate) <= max_chars:
            current = candidate
            continue
        chunks.append(current)
        tail = current[-overlap:] if overlap else ""
        space = tail.find(" ")
        tail = tail[space + 1 :] if 0 <= space < len(tail) - 1 else tail
        current = (
            f"{tail}\n\n{piece}" if tail and len(tail) + len(piece) + 2 <= max_chars else piece
        )
    if current:
        chunks.append(current)
    return chunks
