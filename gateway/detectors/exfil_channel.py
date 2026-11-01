"""Exfiltration channels: markdown images or links to non-allowlisted domains whose URLs carry
data (A3). An image is worse than a link because clients fetch images without a click."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from gateway.core.context import ScanContext
from gateway.core.normalize import Views
from gateway.core.policy import ExfilSettings
from gateway.core.verdict import AttackClass, Finding, Role, Severity
from gateway.detectors.base import Detector, view_note

_URL = r"(https?://[^\s)>\"']{1,4000})"
# The rest of the construct, so a redaction removes all of it: optional title, closing paren.
_MD_TAIL = r">?(?:\s+[\"'][^\"'\n]{0,200}[\"'])?\s{0,20}\)?"
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("image", re.compile(r"!\[[^\[\]\n]{0,500}\]\(\s*<?" + _URL + _MD_TAIL)),
    (
        "image",
        re.compile(r"<img\b[^<>]{0,500}?\bsrc\s*=\s*[\"']?" + _URL + r"[^<>]{0,500}>?", re.I),
    ),
    ("link", re.compile(r"(?<!!)\[[^\[\]\n]{0,500}\]\(\s*<?" + _URL + _MD_TAIL)),
]
_MIN_QUERY_CHARS = 16
_MIN_VALUE_CHARS = 12
_MIN_PATH_SEGMENT_CHARS = 32


def carries_data(url: str) -> bool:
    parts = urlsplit(url)
    if len(parts.query) >= _MIN_QUERY_CHARS:
        return True
    if any(len(v) >= _MIN_VALUE_CHARS for _, v in parse_qsl(parts.query, keep_blank_values=True)):
        return True
    return any(len(seg) >= _MIN_PATH_SEGMENT_CHARS for seg in parts.path.split("/"))


class ExfilChannel(Detector):
    name = "exfil_channel"
    layer = 1
    roles = frozenset({Role.ASSISTANT})

    def __init__(self, settings: ExfilSettings) -> None:
        self._allowed = tuple(d.lower().lstrip(".") for d in settings.allowed_domains)

    def allowed(self, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in self._allowed)

    def hits(self, views: Views) -> list[Finding]:
        findings: dict[tuple[int, int], Finding] = {}
        for view in views.all:
            for kind, pattern in _PATTERNS:
                for m in pattern.finditer(view.text):
                    url = m.group(1)
                    if self.allowed(url):
                        continue
                    span = view.to_original(m.start(), m.end())
                    if span in findings:
                        continue
                    data = carries_data(url)
                    if kind == "image" and data:
                        rule, score, sev = "exfil-markdown-image", 0.9, Severity.HIGH
                        reason = "Image URL to a non-allowlisted domain carries data"
                    elif data:
                        rule, score, sev = "exfil-markdown-link", 0.75, Severity.MEDIUM
                        reason = "Link to a non-allowlisted domain carries data"
                    elif kind == "image":
                        rule, score, sev = "exfil-external-image", 0.4, Severity.LOW
                        reason = "Image loaded from a non-allowlisted domain"
                    else:
                        continue
                    findings[span] = Finding(
                        detector=self.name,
                        attack_class=AttackClass.A3,
                        severity=sev,
                        score=score,
                        reason=reason + view_note(view),
                        rule_id=rule,
                        span=span,
                        layer=self.layer,
                    )
        return list(findings.values())

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        return self.hits(context.views)
