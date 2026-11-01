"""The live policy, rules, detectors, and tool policy, reloaded when their files change
(no restart needed).

Files are checked at most every ``check_interval`` seconds. A file that fails to load or
validate leaves the previous configuration in place and logs an error.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gateway.core.pipeline import Pipeline
from gateway.core.policy import Policy, parse_policy
from gateway.core.redact import Redactor
from gateway.core.rules import parse_rules
from gateway.detectors.exfil_channel import ExfilChannel
from gateway.detectors.hidden_content import HiddenContent
from gateway.detectors.injection_rules import InjectionRules
from gateway.detectors.leak_pii import LeakPii
from gateway.detectors.leak_secrets import LeakSecrets
from gateway.detectors.leak_system_prompt import LeakSystemPrompt
from gateway.detectors.tool_guard import ToolGuard, parse_tool_policy

log = logging.getLogger("gateway.runtime")

INJECTION_RULES_FILE = "injection.yaml"
SECRET_RULES_FILE = "secrets.yaml"  # noqa: S105 (a file name, not a secret)
TOOL_POLICY_FILE = "tools.yaml"
DEFAULT_CHECK_INTERVAL = 2.0


@dataclass(frozen=True)
class Runtime:
    policy: Policy
    pipeline: Pipeline
    redactor: Redactor
    tool_guard: ToolGuard
    version: str


def build_runtime(
    policy_raw: bytes, injection_raw: bytes, secrets_raw: bytes, tools_raw: bytes
) -> Runtime:
    policy = parse_policy(policy_raw)
    settings = policy.config.detectors
    injection_rules = parse_rules(injection_raw, INJECTION_RULES_FILE)
    secret_rules = parse_rules(secrets_raw, SECRET_RULES_FILE)
    secrets = LeakSecrets(secret_rules, settings.leak_secrets)
    pii = LeakPii(settings.leak_pii)
    detectors = [
        InjectionRules(injection_rules),
        secrets,
        LeakSystemPrompt(settings.leak_system_prompt),
        pii,
        ExfilChannel(settings.exfil_channel),
        HiddenContent(),
    ]
    tool_guard = ToolGuard(parse_tool_policy(tools_raw))
    digest = hashlib.sha256()
    for raw in (policy_raw, injection_raw, secrets_raw, tools_raw):
        digest.update(hashlib.sha256(raw).digest())
    return Runtime(
        policy=policy,
        pipeline=Pipeline(detectors, policy),
        redactor=Redactor(secrets, pii),
        tool_guard=tool_guard,
        version=digest.hexdigest()[:12],
    )


class ConfigStore:
    def __init__(
        self,
        policies_path: Path,
        rules_dir: Path,
        check_interval: float = DEFAULT_CHECK_INTERVAL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._paths = (
            policies_path,
            rules_dir / INJECTION_RULES_FILE,
            rules_dir / SECRET_RULES_FILE,
            rules_dir / TOOL_POLICY_FILE,
        )
        self._interval = check_interval
        self._clock = clock
        self._pinned = False
        self._signature = self._stat()
        self._runtime = self._load()
        self._next_check = clock() + check_interval

    def _stat(self) -> tuple[tuple[int, int], ...]:
        return tuple((p.stat().st_mtime_ns, p.stat().st_size) for p in self._paths)

    def _load(self) -> Runtime:
        return build_runtime(*(p.read_bytes() for p in self._paths))

    def current(self) -> Runtime:
        if self._pinned or self._clock() < self._next_check:
            return self._runtime
        self._next_check = self._clock() + self._interval
        try:
            signature = self._stat()
            if signature != self._signature:
                runtime = self._load()
                self._signature = signature
                if runtime.version != self._runtime.version:
                    log.info(
                        "configuration reloaded",
                        extra={"old_version": self._runtime.version, "version": runtime.version},
                    )
                self._runtime = runtime
        except Exception:
            # Keep serving the last good configuration; retry after the next change.
            self._signature = self._safe_stat()
            log.exception("configuration reload failed; keeping version %s", self._runtime.version)
        return self._runtime

    def _safe_stat(self) -> tuple[tuple[int, int], ...]:
        try:
            return self._stat()
        except OSError:
            return self._signature

    def pin(self, runtime: Runtime) -> None:
        """Serve ``runtime`` and stop reloading. For tests."""
        self._runtime = runtime
        self._pinned = True
