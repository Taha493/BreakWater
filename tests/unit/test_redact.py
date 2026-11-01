"""Excerpt redaction. Fake secrets are built at runtime so no secret-shaped literal is committed."""

from __future__ import annotations

import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gateway.core.redact import EXCERPT_CHARS, excerpt, redact

FAKE_SECRETS = {
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIB"
    + "Q" * 60
    + "\n-----END RSA PRIVATE KEY-----",
    "jwt": "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 20,
    "gateway_key": "gw.0123456789abcdef." + "k" * 43,
    "aws_access_key": "AKIA" + "Z" * 16,
    "api_key": "sk-" + "p" * 40,
    "github_token": "ghp_" + "g" * 36,
    "slack_token": "xoxb-" + "1" * 12 + "-" + "s" * 12,
    "google_api_key": "AIza" + "G" * 35,
    "bearer_token": "Bearer " + "t" * 30,
    "credential": "password=" + "hunter2hunter2",
    "email": "jane.doe@example.com",
    "national_id": "12345-1234567-1",
    "number": "4111 1111 1111 1111",
}

SECRET_PARTS = {
    "private_key": "Q" * 60,
    "jwt": "b" * 20,
    "gateway_key": "k" * 43,
    "aws_access_key": "Z" * 16,
    "api_key": "p" * 40,
    "github_token": "g" * 36,
    "slack_token": "s" * 12,
    "google_api_key": "G" * 35,
    "bearer_token": "t" * 30,
    "credential": "hunter2hunter2",
    "email": "jane.doe",
    "national_id": "1234567",
    "number": "1111 1111",
}


@pytest.mark.parametrize("kind", sorted(FAKE_SECRETS))
def test_secret_formats_redacted(kind: str) -> None:
    text = f"before {FAKE_SECRETS[kind]} after"
    result = redact(text)
    assert SECRET_PARTS[kind] not in result
    assert "[REDACTED:" in result
    assert result.startswith("before ")
    assert result.endswith(" after")


def test_unterminated_private_key_redacted_to_end() -> None:
    result = redact("key: -----BEGIN PRIVATE KEY-----\nMIIE" + "A" * 100)
    assert "A" * 10 not in result


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "The meeting is on 2026-10-30 at 10:30, order #12345.",
        "Use the token bucket algorithm for rate limiting.",
        "Version 1.2.3 of the library",
    ],
)
def test_benign_text_unchanged(text: str) -> None:
    assert redact(text) == text


def test_excerpt_truncates_with_ellipsis() -> None:
    result = excerpt("word " * 100)
    assert len(result) == EXCERPT_CHARS
    assert result.endswith("…")


def test_excerpt_redacts_secret_cut_by_limit() -> None:
    secret = "sk-" + "p" * 40
    text = "x" * (EXCERPT_CHARS - 10) + " " + secret
    result = excerpt(text)
    assert "ppp" not in result


def test_excerpt_collapses_whitespace_and_control_chars() -> None:
    assert excerpt("a\n\tb\x00c​d   e") == "a b c d e"


@given(st.text())
def test_excerpt_never_crashes_and_is_bounded(text: str) -> None:
    assert len(excerpt(text)) <= EXCERPT_CHARS


@given(
    st.text(alphabet=st.characters(exclude_categories=["Cs"])),
    st.sampled_from(sorted(FAKE_SECRETS)),
    st.text(),
)
def test_planted_secret_always_removed(prefix: str, kind: str, suffix: str) -> None:
    result = redact(f"{prefix} {FAKE_SECRETS[kind]} {suffix}")
    assert SECRET_PARTS[kind] not in result


@pytest.mark.parametrize(
    "text",
    [
        "a" * 200_000,
        "1" * 200_000,
        "1 " * 100_000,
        "-----BEGIN PRIVATE KEY-----" * 5_000,
        "password" + " " * 200_000,
        "bearer " * 30_000,
        "a@" * 100_000,
        "eyJ" + "a" * 200_000,
    ],
)
def test_pathological_input_is_fast(text: str) -> None:
    started = time.perf_counter()
    redact(text)
    assert time.perf_counter() - started < 2.0
