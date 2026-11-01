from __future__ import annotations

import pytest

from breakwater.core.keys import generate_key, hashes_match, parse_key_id
from breakwater.core.redact import Hasher


def test_generated_key_round_trips() -> None:
    key = generate_key()
    assert key.plaintext.startswith(f"gw.{key.key_id}.")
    assert parse_key_id(key.plaintext) == key.key_id


def test_generated_keys_are_unique() -> None:
    keys = {generate_key().plaintext for _ in range(50)}
    assert len(keys) == 50


@pytest.mark.parametrize(
    "value",
    [
        "",
        "gw",
        "gw.0123456789abcdef",
        "gw.0123456789abcdef.short",
        "gw.0123456789ABCDEF." + "a" * 40,  # id must be lowercase hex
        "xx.0123456789abcdef." + "a" * 40,
        "gw.0123456789abcdef." + "a" * 40 + "\n",
        "gw.0123456789abcdef." + "a" * 200,
    ],
)
def test_malformed_keys_have_no_id(value: str) -> None:
    assert parse_key_id(value) is None


def test_hashes_match() -> None:
    assert hashes_match("abc", "abc")
    assert not hashes_match("abc", "abd")
    assert not hashes_match("abc", "ab")


def test_hasher_is_keyed_and_domain_separated() -> None:
    a = Hasher("a" * 32)
    b = Hasher("b" * 32)
    assert a.text("hello") == a.text("hello")
    assert a.text("hello") != b.text("hello")
    assert len({a.text("hello"), a.user("hello"), a.api_key("hello")}) == 3
    assert len(a.text("hello")) == 64


def test_hasher_accepts_lone_surrogates() -> None:
    assert len(Hasher("a" * 32).text("\ud800")) == 64
