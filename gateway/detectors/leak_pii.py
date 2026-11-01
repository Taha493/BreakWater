"""Personal data in responses: emails, card numbers (Luhn), Pakistani CNIC, phone numbers (A3).

Presidio is not used yet; it can be added later as an optional extra behind this detector.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from gateway.core.context import ScanContext
from gateway.core.normalize import Views
from gateway.core.policy import PiiSettings
from gateway.core.verdict import AttackClass, Finding, Role, Severity
from gateway.detectors.base import Detector, view_note

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24})\b")
_CNIC = re.compile(r"\b\d{5}-\d{7}-\d\b")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
_PHONE = re.compile(r"\+?\(?\d[\d ().-]{7,18}\d")
_DOTTED_QUAD = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DIGIT_GROUP = re.compile(r"\d+")


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def card_span(candidate: str) -> tuple[int, int] | None:
    """Span of a Luhn-valid card number inside a digit run, or None.

    A separated run may hold a card plus extra groups (``4111 1111 1111 1111 000``), so
    windows of whole digit groups are tried too. Windows never split a group, which keeps
    random slices of long id numbers from matching by chance.
    """
    groups = [(g.start(), g.end()) for g in _DIGIT_GROUP.finditer(candidate)]
    for i in range(len(groups)):
        for j in range(len(groups) - 1, i - 1, -1):
            start, end = groups[i][0], groups[j][1]
            digits = re.sub(r"\D", "", candidate[start:end])
            if 13 <= len(digits) <= 19 and len(set(digits)) > 1 and luhn_valid(digits):
                return start, end
    return None


class LeakPii(Detector):
    name = "leak_pii"
    layer = 1
    roles = frozenset({Role.ASSISTANT})

    def __init__(self, settings: PiiSettings) -> None:
        self._allowed = tuple(d.lower().lstrip(".") for d in settings.allowed_email_domains)

    def _email_allowed(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d or domain.endswith("." + d) for d in self._allowed)

    def _candidates(self, text: str) -> Iterator[tuple[int, int, str, float, Severity, str]]:
        for m in _EMAIL.finditer(text):
            if not self._email_allowed(m.group(1)):
                yield m.start(), m.end(), "pii-email", 0.75, Severity.MEDIUM, "Email address"
        for m in _CNIC.finditer(text):
            yield m.start(), m.end(), "pii-national-id-pk", 0.85, Severity.HIGH, "CNIC number"
        for m in _CARD.finditer(text):
            if (span := card_span(m.group())) is not None:
                start, end = m.start() + span[0], m.start() + span[1]
                yield start, end, "pii-card-number", 0.9, Severity.HIGH, "Card number"
        for m in _PHONE.finditer(text):
            candidate = m.group()
            digits = re.sub(r"\D", "", candidate)
            if not 10 <= len(digits) <= 15:
                continue
            if _DOTTED_QUAD.fullmatch(candidate) or _ISO_DATE.search(candidate):
                continue
            if not (candidate.startswith("+") or re.search(r"[ ().-]", candidate)):
                continue  # a bare digit run is more likely an id than a phone number
            yield m.start(), m.end(), "pii-phone", 0.7, Severity.MEDIUM, "Phone number"

    def hits(self, views: Views) -> list[Finding]:
        findings: list[Finding] = []
        taken: list[tuple[int, int]] = []
        for view in views.all:
            for start, end, rule_id, score, severity, label in self._candidates(view.text):
                span = view.to_original(start, end)
                if any(span[0] < e and s < span[1] for s, e in taken):
                    continue
                taken.append(span)
                findings.append(
                    Finding(
                        detector=self.name,
                        attack_class=AttackClass.A3,
                        severity=severity,
                        score=score,
                        reason=label + view_note(view),
                        rule_id=rule_id,
                        span=span,
                        layer=self.layer,
                    )
                )
        return findings

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        return self.hits(context.views)
