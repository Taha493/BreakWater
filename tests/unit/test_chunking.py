from __future__ import annotations

import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gateway.rag.chunking import chunk_text


def test_short_text_is_one_chunk() -> None:
    assert chunk_text("one\n\ntwo", max_chars=100, overlap=10) == ["one\n\ntwo"]


def test_empty_text_has_no_chunks() -> None:
    assert chunk_text("   \n\n  ") == []


def test_paragraphs_are_packed_and_overlapped() -> None:
    paragraphs = [f"paragraph {i} " + "word " * 30 for i in range(6)]
    chunks = chunk_text("\n\n".join(paragraphs), max_chars=400, overlap=60)
    assert len(chunks) > 1
    assert all(len(c) <= 400 for c in chunks)
    for previous, current in itertools.pairwise(chunks):
        head = current.split("\n\n", 1)[0]
        assert head in previous  # each chunk starts with the tail of the one before


def test_long_paragraph_is_cut_on_whitespace() -> None:
    chunks = chunk_text("word " * 500, max_chars=200, overlap=0)
    assert all(len(c) <= 200 for c in chunks)
    assert all(not c.startswith(" ") and "wor d" not in c for c in chunks)


def test_overlap_must_be_smaller() -> None:
    with pytest.raises(ValueError):
        chunk_text("x", max_chars=10, overlap=10)


@given(st.text(max_size=3000))
def test_no_text_is_lost(text: str) -> None:
    chunks = chunk_text(text, max_chars=300, overlap=50)
    assert all(len(c) <= 300 for c in chunks)
    joined = " ".join(chunks)
    for word in text.split():
        assert word in joined
