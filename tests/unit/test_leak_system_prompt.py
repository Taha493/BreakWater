from __future__ import annotations

from breakwater.core.context import CallContext, ScanContext
from breakwater.core.policy import CANARY_RULE_ID, SystemPromptLeakSettings
from breakwater.core.verdict import Finding, Role
from breakwater.detectors.leak_system_prompt import OVERLAP_RULE_ID, LeakSystemPrompt

DETECTOR = LeakSystemPrompt(SystemPromptLeakSettings(min_overlap_words=12))
SYSTEM = (
    "You are Ava, the support assistant for Contoso Bank. Only answer questions about "
    "savings accounts and card limits. Never discuss internal fraud thresholds or the "
    "escalation codes used by staff. Always reply in a friendly, concise tone."
)
CANARY = "cnry-0123456789abcdef0123"


async def scan(text: str, call: CallContext) -> list[Finding]:
    return await DETECTOR.scan(text, Role.ASSISTANT, ScanContext.for_text(text, call))


async def test_canary_echo_detected() -> None:
    text = f"Sure! The reference is {CANARY}."
    (finding,) = await scan(text, CallContext(canary=CANARY))
    assert finding.rule_id == CANARY_RULE_ID
    assert finding.score == 1.0
    assert finding.span is not None
    assert text[finding.span[0] : finding.span[1]] == CANARY


async def test_obfuscated_canary_detected() -> None:
    hidden = "​".join(CANARY)
    findings = await scan(f"ref {hidden}", CallContext(canary=CANARY))
    assert [f.rule_id for f in findings] == [CANARY_RULE_ID]


async def test_no_canary_no_finding() -> None:
    assert await scan(f"ref {CANARY}", CallContext()) == []


async def test_long_overlap_detected() -> None:
    leaked = "Here you go: " + SYSTEM.split(". ", 1)[1]
    (finding,) = await scan(leaked, CallContext(system_prompt=SYSTEM))
    assert finding.rule_id == OVERLAP_RULE_ID
    assert finding.score == 0.9  # at least twice the minimum
    assert finding.span is not None
    assert leaked[finding.span[0] :].startswith("Only answer questions")


async def test_medium_overlap_scores_lower() -> None:
    leaked = "Rule: never discuss internal fraud thresholds or the escalation codes used by staff."
    (finding,) = await scan(leaked, CallContext(system_prompt=SYSTEM))
    assert finding.score == 0.75


async def test_short_quotes_and_paraphrases_are_fine() -> None:
    call = CallContext(system_prompt=SYSTEM)
    assert await scan("I can answer questions about savings accounts.", call) == []
    assert (
        await scan(
            "I'm Ava from Contoso. I help with savings and card limits, nothing internal.", call
        )
        == []
    )


async def test_short_system_prompt_never_matches() -> None:
    call = CallContext(system_prompt="You are a helpful assistant.")
    assert await scan("You are a helpful assistant.", call) == []
