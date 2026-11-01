"""System prompt leakage: canary token echo, and long word overlap with the system prompt (A3)."""

from __future__ import annotations

import re

from gateway.core.context import ScanContext
from gateway.core.normalize import normalize
from gateway.core.policy import CANARY_RULE_ID, SystemPromptLeakSettings
from gateway.core.verdict import AttackClass, Finding, Role, Severity
from gateway.detectors.base import Detector

OVERLAP_RULE_ID = "system-prompt-overlap"
_WORD = re.compile(r"\w+")


def _words(text: str) -> list[re.Match[str]]:
    return list(_WORD.finditer(text))


class LeakSystemPrompt(Detector):
    name = "leak_system_prompt"
    layer = 1
    roles = frozenset({Role.ASSISTANT})

    def __init__(self, settings: SystemPromptLeakSettings) -> None:
        self._min_words = settings.min_overlap_words
        self._shingle = min(8, self._min_words)

    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        canary = context.call.canary
        if canary:
            for view in context.views.all:
                index = view.text.find(canary)
                if index != -1:
                    findings.append(
                        Finding(
                            detector=self.name,
                            attack_class=AttackClass.A3,
                            severity=Severity.CRITICAL,
                            score=1.0,
                            reason="Response contains the canary token from the system prompt",
                            rule_id=CANARY_RULE_ID,
                            span=view.to_original(index, index + len(canary)),
                            layer=self.layer,
                        )
                    )
                    break
        if context.call.system_prompt:
            findings.extend(self._overlap(context, context.call.system_prompt))
        return findings

    def _overlap(self, context: ScanContext, system_prompt: str) -> list[Finding]:
        k = self._shingle
        prompt_words = [m.group().lower() for m in _words(normalize(system_prompt).text)]
        if len(prompt_words) < self._min_words:
            return []
        shingles = {tuple(prompt_words[i : i + k]) for i in range(len(prompt_words) - k + 1)}

        view = context.views.all[1] if len(context.views.all) > 1 else context.views.original
        if view.kind != "normalized":
            view = context.views.original
        matches = _words(view.text)
        words = [m.group().lower() for m in matches]
        hit = [tuple(words[i : i + k]) in shingles for i in range(len(words) - k + 1)]

        findings: list[Finding] = []
        i = 0
        while i < len(hit):
            if not hit[i]:
                i += 1
                continue
            j = i
            while j + 1 < len(hit) and hit[j + 1]:
                j += 1
            length = j - i + k
            if length >= self._min_words:
                start, end = matches[i].start(), matches[j + k - 1].end()
                findings.append(
                    Finding(
                        detector=self.name,
                        attack_class=AttackClass.A3,
                        severity=Severity.HIGH,
                        score=0.9 if length >= 2 * self._min_words else 0.75,
                        reason=f"Response repeats {length} consecutive words of the system prompt",
                        rule_id=OVERLAP_RULE_ID,
                        span=view.to_original(start, end),
                        layer=self.layer,
                    )
                )
            i = j + 1
        return findings
