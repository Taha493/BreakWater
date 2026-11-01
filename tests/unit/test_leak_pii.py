from __future__ import annotations

import pytest

from gateway.core.context import ScanContext
from gateway.core.policy import PiiSettings
from gateway.core.verdict import AttackClass, Role
from gateway.detectors.leak_pii import LeakPii, luhn_valid

DETECTOR = LeakPii(PiiSettings())


def hits(text: str, detector: LeakPii = DETECTOR) -> list[tuple[str, str]]:
    findings = detector.hits(ScanContext.for_text(text).views)
    return [(f.rule_id or "", text[f.span[0] : f.span[1]]) for f in findings if f.span]


@pytest.mark.parametrize(
    ("text", "rule", "value"),
    [
        ("Mail jane.doe@example.com today", "pii-email", "jane.doe@example.com"),
        ("contact: a.b+tag@mail.example.co.uk.", "pii-email", "a.b+tag@mail.example.co.uk"),
        ("Card 4111 1111 1111 1111 on file", "pii-card-number", "4111 1111 1111 1111"),
        ("card 5500-0000-0000-0004", "pii-card-number", "5500-0000-0000-0004"),
        ("card 4111 1111 1111 1111 000 x", "pii-card-number", "4111 1111 1111 1111"),
        ("ref 99 4111-1111-1111-1111", "pii-card-number", "4111-1111-1111-1111"),
        ("CNIC 35202-1234567-1 is his", "pii-national-id-pk", "35202-1234567-1"),
        ("Call +92 300 1234567 now", "pii-phone", "+92 300 1234567"),
        ("phone (555) 123-4567 ext", "pii-phone", "(555) 123-4567"),
    ],
)
def test_detects(text: str, rule: str, value: str) -> None:
    assert (rule, value) in hits(text)


@pytest.mark.parametrize(
    "text",
    [
        "Card 4111 1111 1111 1112 fails Luhn",
        "0000 0000 0000 0000",
        "Tracking 1234 5678 9012 3456 789",  # no group-aligned Luhn-valid window
        "Server 192.168.100.200 is up",
        "Released on 2026-10-30 at noon",
        "Order 12345678901 shipped",  # bare digit run: an id, not a phone
        "version 1.2.3",
        "email me at the usual address",
    ],
)
def test_benign(text: str) -> None:
    assert hits(text) == []


def test_allowlisted_email_domains() -> None:
    detector = LeakPii(PiiSettings(allowed_email_domains=["example.com"]))
    assert hits("help@example.com or a@sub.example.com", detector) == []
    assert hits("x@evil-example.com", detector) == [("pii-email", "x@evil-example.com")]


async def test_finding_shape_and_role() -> None:
    text = "jane@example.org"
    (finding,) = await DETECTOR.scan(text, Role.ASSISTANT, ScanContext.for_text(text))
    assert finding.attack_class is AttackClass.A3
    assert finding.score >= 0.7
    assert DETECTOR.roles == {Role.ASSISTANT}


@pytest.mark.parametrize(
    ("digits", "valid"),
    [("4111111111111111", True), ("4111111111111112", False), ("79927398713", True)],
)
def test_luhn(digits: str, valid: bool) -> None:
    assert luhn_valid(digits) is valid
