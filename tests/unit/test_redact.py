"""Hashing, redaction, and excerpts. Fake secrets are built at runtime."""

from __future__ import annotations

import base64
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gateway.core.policy import Redaction
from gateway.core.redact import EXCERPT_CHARS, Hasher, apply_redactions
from tests.conftest import default_runtime

REDACTOR = default_runtime().redactor

FAKE = {
    "secret-private-key": "-----BEGIN RSA PRIVATE KEY-----\nMIIB"
    + "Q" * 60
    + "\n-----END RSA PRIVATE KEY-----",
    "secret-jwt": "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20,
    "secret-gateway-key": "gw.0123456789abcdef." + "k" * 43,
    "secret-aws-access-key": "AKIA" + "Z" * 16,
    "secret-api-key": "sk-" + "p" * 40,
    "secret-github-token": "ghp_" + "g" * 36,
    "secret-bearer-token": "Bearer " + "t" * 30,
    "pii-email": "jane.doe@example.com",
    "pii-national-id-pk": "12345-1234567-1",
    "pii-card-number": "4111 1111 1111 1111",
    "pii-phone": "+92 300 1234567",
}
# A distinctive piece of each value that must not survive redaction.
CORE = {
    "secret-private-key": "Q" * 60,
    "secret-jwt": "b" * 20,
    "secret-gateway-key": "k" * 43,
    "secret-aws-access-key": "Z" * 16,
    "secret-api-key": "p" * 40,
    "secret-github-token": "g" * 36,
    "secret-bearer-token": "t" * 30,
    "pii-email": "jane.doe",
    "pii-national-id-pk": "1234567",
    "pii-card-number": "1111 1111",
    "pii-phone": "1234567",
}


def test_hasher_is_keyed_and_domain_separated() -> None:
    a, b = Hasher("a" * 32), Hasher("b" * 32)
    assert a.text("x") == a.text("x") != b.text("x")
    assert len({a.text("x"), a.user("x"), a.api_key("x"), a.canary("x")}) == 4


def test_canary_is_stable_per_seed() -> None:
    h = Hasher("a" * 32)
    assert h.canary("s1") == h.canary("s1") != h.canary("s2")
    assert h.canary("s1").startswith("cnry-")


def test_apply_redactions_merges_overlaps() -> None:
    redactions = [Redaction((2, 5), "a"), Redaction((4, 7), "b"), Redaction((8, 9), "c")]
    assert apply_redactions("0123456789", redactions) == "01[REDACTED:a]7[REDACTED:c]9"


def test_apply_redactions_whole_text() -> None:
    assert apply_redactions("abc", [Redaction((0, 1), "a"), Redaction(None, "x")]) == (
        "[REDACTED:x]"
    )


@pytest.mark.parametrize("label", sorted(FAKE))
def test_redactor_removes_secret_and_pii(label: str) -> None:
    result = REDACTOR.redact(f"before {FAKE[label]} after")
    assert CORE[label] not in result
    assert f"[REDACTED:{label}]" in result
    assert result.startswith("before ")


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "The meeting is on 2026-10-30 at 10:30, order #12345.",
        "Use the token bucket algorithm.",
        "Server at 192.168.100.200 responded.",
    ],
)
def test_benign_text_unchanged(text: str) -> None:
    assert REDACTOR.redact(text) == text


def test_excerpt_truncates_and_redacts_before_cutting() -> None:
    assert len(REDACTOR.excerpt("word " * 100)) == EXCERPT_CHARS
    secret = "sk-" + "p" * 40
    result = REDACTOR.excerpt("x" * (EXCERPT_CHARS - 10) + " " + secret)
    assert "ppp" not in result
    assert result.endswith("…")


def test_excerpt_collapses_whitespace_and_control_chars() -> None:
    assert REDACTOR.excerpt("a\n\tb\x00c​d   e") == "a b c d e"


def test_excerpt_redacts_encoded_secret() -> None:
    hidden = base64.b64encode(("key sk-" + "p" * 40).encode()).decode()
    assert hidden not in REDACTOR.excerpt(f"look: {hidden}")


@given(st.text(max_size=500))
def test_excerpt_never_crashes_and_is_bounded(text: str) -> None:
    assert len(REDACTOR.excerpt(text)) <= EXCERPT_CHARS


@given(
    st.text(alphabet=st.characters(exclude_categories=["Cs"]), max_size=100),
    st.sampled_from(sorted(FAKE)),
    st.text(max_size=100),
)
def test_planted_secret_always_removed(prefix: str, label: str, suffix: str) -> None:
    assert CORE[label] not in REDACTOR.redact(f"{prefix} {FAKE[label]} {suffix}")


@pytest.mark.parametrize(
    "text",
    ["a" * 200_000, "1 " * 100_000, "a@" * 100_000, "](http://x" * 20_000, "[" * 200_000],
)
def test_excerpt_is_fast_on_large_input(text: str) -> None:
    started = time.perf_counter()
    REDACTOR.excerpt(text)
    assert time.perf_counter() - started < 2.0
