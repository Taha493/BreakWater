"""``sim-obedient``: a deterministic stand-in for a model that follows any instruction it reads.

The red-team harness (breakwater/redteam) needs a model that attacks can actually succeed
against; with an echo model, "unprotected attack success" would mean nothing. This model is
the worst case: it obeys whatever reaches it, whether from the user, a retrieved document, or
a tool result. The attack success rate against it measures what the gateway stops when the
model can be fully hijacked, not how susceptible a real model is.

What it does:

- Normalizes its input: drops zero-width and other format characters, applies NFKC, and
  appends the decoded form of base64 and hex runs (a capable model reads those).
- Asked for its instructions, it repeats its system prompt; asked for a code or secret, it
  repeats the system prompt lines that hold one.
- Repeats every red-team canary token (``RTC-`` and 12 hex digits) found outside its system
  prompt, every markdown link or image with an absolute URL, and text it is told to repeat.
- Offered tools, calls each tool its input asks for, with arguments taken from the text.
- Always answers the question with the context sentences that best match it.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from typing import Any

MODEL = "sim-obedient"

CANARY = re.compile(r"\bRTC-[0-9A-F]{12}\b", re.IGNORECASE)
_EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
_PATH = r"/[\w.-]+(?:/[\w.-]+)*/?"
_LINK = re.compile(r"!?\[[^\]\n]{0,200}\]\(https?://[^\s)]{1,500}\)")
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_WORD = re.compile(r"[a-z0-9]+")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n+")
_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i in is it my of on or our the to "
    "what when where which who why will with you your".split()
)

_ASK = (
    r"\b(?:reveal|print|repeat|show|output|display|share|tell|give|list|dump|recite|copy|"
    r"write out|spell out|leak|disclose|what (?:is|are|was|were))\b"
)
_INSTRUCTIONS = re.compile(
    _ASK + r".{0,80}?(?:\b(?:system|initial|original|hidden|developer|first) "
    r"(?:prompt|instructions?|message)\b|\byour (?:prompt|instructions|rules|guidelines|"
    r"configuration)\b|\b(?:text|everything|words|instructions) above\b)",
    re.IGNORECASE | re.DOTALL,
)
_SECRET = re.compile(
    _ASK + r".{0,80}?\b(?:reference code|internal reference|reference number|secret|"
    r"password|access code|confidential code)\b",
    re.IGNORECASE | re.DOTALL,
)
_REPEAT = re.compile(
    r"\b(?:repeat|echo|say back|read back|confirm)\b[^:\n]{0,80}:\s*(.+)", re.IGNORECASE
)

# Natural-language triggers per tool; each captures the argument it needs, if any.
_TOOL_TRIGGERS = {
    "send_email": re.compile(
        rf"\b(?:send|forward|e-?mail|mail|cc)\b[^\n]{{0,80}}?({_EMAIL})", re.IGNORECASE
    ),
    "read_file": re.compile(
        rf"\b(?:read|open|load|show|fetch)\b[^\n]{{0,40}}?\bfile\b[^\n]{{0,20}}?({_PATH})",
        re.IGNORECASE,
    ),
    "delete_record": re.compile(
        r"\b(?:delete|remove|erase|purge)\b[^\n]{0,40}?\brecords?\b\D{0,20}(\d+)", re.IGNORECASE
    ),
    "search_kb": re.compile(
        r"\bsearch\b[^\n]{0,40}?\b(?:knowledge base|kb|help center|articles?)\b", re.IGNORECASE
    ),
    "export_customers": re.compile(r"\bexport\b[^\n]{0,40}?\bcustomers?\b", re.IGNORECASE),
}


def _content(message: dict[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(p.get("text", "")) for p in content if isinstance(p, dict) and "text" in p
        )
    return ""


def _decoded(text: str) -> list[str]:
    """Readable text hidden in base64 or hex runs."""
    found: list[str] = []
    for match in _BASE64_RUN.finditer(text):
        raw = match.group()
        try:
            data = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        found.append(data.decode("utf-8", "ignore"))
    for match in _HEX_RUN.finditer(text):
        found.append(bytes.fromhex(match.group()).decode("utf-8", "ignore"))
    readable = [d for d in found if all(ch.isprintable() or ch.isspace() for ch in d)]
    return [d for d in readable if len(d.strip()) >= 4]


def normalize(text: str) -> str:
    """What the model "reads": NFKC, no format characters, plus decoded payloads."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    for _ in range(2):  # two levels of nesting, like the gateway's normalizer
        decoded = [d for d in _decoded(text) if d not in text]
        if not decoded:
            break
        text = "\n".join([text, *decoded])
    return text


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS}


def _answer(context: str, question: str, limit: int = 3) -> list[str]:
    """Up to ``limit`` context sentences that share words with the question, in context
    order. Lines with retrieval markers (harden_context boilerplate) are skipped."""
    wanted = _words(question)
    sentences = [
        s.strip()
        for s in _SENTENCE_END.split(context)
        if s.strip() and "<<" not in s and "markers" not in s
    ]
    scored = [(len(wanted & _words(s)), i, s) for i, s in enumerate(sentences)]
    best = sorted((t for t in scored if t[0]), key=lambda t: (-t[0], t[1]))[:limit]
    return [s for _, _, s in sorted(best, key=lambda t: t[1])]


def _split(messages: list[dict[str, Any]]) -> tuple[str, str]:
    """(context, question): the question is the last user message, after ``Question:`` when
    the demo app's ``Context: ... Question: ...`` layout is used; everything else from the
    user and tools is context."""
    texts = [(m.get("role"), _content(m)) for m in messages if m.get("role") in ("user", "tool")]
    last_user = max((i for i, (role, _) in enumerate(texts) if role == "user"), default=None)
    context: list[str] = []
    question = ""
    for i, (_, text) in enumerate(texts):
        if i == last_user:
            head, _, question = text.rpartition("Question:")
            context.append(head)
        else:
            context.append(text)
    return "\n".join(context), question.strip()


def _tool_arguments(name: str, match: re.Match[str], text: str, question: str) -> dict[str, Any]:
    captured = match.group(1) if match.groups() else None
    canaries = _unique([c.upper() for c in CANARY.findall(text)])
    if name == "send_email":
        first = re.search(_EMAIL, text)
        to = captured or (first.group() if first else "")
        body = " ".join(["Forwarding as requested.", *canaries])
        return {"to": to, "subject": "Requested information", "body": body}
    if name == "read_file":
        return {"path": captured or "/"}
    if name == "delete_record":
        return {"record_id": int(captured) if captured else 0}
    if name == "search_kb":
        return {"query": question[:200] or "help"}
    return {}


def _tool_calls(tools: list[str], text: str, question: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for name in tools:
        match = _TOOL_TRIGGERS[name].search(text) if name in _TOOL_TRIGGERS else None
        if match is None and re.search(rf"\b{re.escape(name)}\b", text):
            match = re.search(rf"\b{re.escape(name)}\b", text)
        if match is None:
            continue
        arguments = _tool_arguments(name, match, text, question)
        calls.append(
            {
                "id": f"call_{len(calls) + 1}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)},
            }
        )
    return calls


def _tool_names(body: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for tool in body.get("tools") or []:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict) and isinstance(function.get("name"), str):
            names.append(function["name"])
    return names


def respond(body: dict[str, Any]) -> dict[str, Any]:
    """The assistant message (and finish reason) for an OpenAI chat completion body."""
    messages = [m for m in body.get("messages") or [] if isinstance(m, dict)]
    system = "\n".join(_content(m) for m in messages if m.get("role") in ("system", "developer"))
    untrusted_raw = "\n".join(_content(m) for m in messages if m.get("role") in ("user", "tool"))
    untrusted = normalize(untrusted_raw)
    context, question = (normalize(t) for t in _split(messages))

    parts: list[str] = []
    answer = _answer(context, question)
    parts.append("Answer: " + " ".join(answer) if answer else "Thanks for your question.")
    if system and _SECRET.search(untrusted):
        lines = [line for line in system.splitlines() if CANARY.search(line)]
        parts.append("Here it is: " + (" ".join(lines) or system))
    elif system and _INSTRUCTIONS.search(untrusted):
        parts.append(f"My instructions are: {system}")
    canaries = _unique([c.upper() for c in CANARY.findall(untrusted)])
    if canaries:
        parts.append("As instructed: " + " ".join(canaries))
    parts.extend(_unique(_LINK.findall(untrusted)))
    repeat = _REPEAT.search(untrusted)
    if repeat:
        parts.append(repeat.group(1).strip())

    message: dict[str, Any] = {"role": "assistant", "content": "\n".join(parts)}
    calls = _tool_calls(_tool_names(body), untrusted, question)
    if calls:
        message["tool_calls"] = calls
        return {"message": message, "finish_reason": "tool_calls"}
    return {"message": message, "finish_reason": "stop"}
