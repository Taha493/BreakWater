"""The interface every detector implements (spec section 3)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from gateway.core.context import ScanContext
from gateway.core.normalize import View
from gateway.core.verdict import Finding, Role


class Detector(ABC):
    """A detector inspects one piece of text and returns findings.

    Detectors should be pure: text in, findings out, no hidden global state. Layer 0 views of
    the text are in ``context.views``; finding spans always point into the original ``text``.
    Detectors in the same layer run concurrently.
    """

    name: ClassVar[str]
    layer: ClassVar[int]
    roles: ClassVar[frozenset[Role]]

    def applies_to(self, role: Role) -> bool:
        return role in self.roles

    @abstractmethod
    async def scan(self, text: str, role: Role, context: ScanContext) -> list[Finding]:
        """Return findings whose spans point into ``text``."""


def view_note(view: View) -> str:
    """Suffix for a finding's reason saying where hidden content was found."""
    if view.kind in ("original", "normalized"):
        return ""
    return f" (found in {view.kind} content)"
