"""The live policy, rules, detectors, and tool policy, applied without a restart.

The rule files are checked at most every ``check_interval`` seconds. The policy comes from
the active database version once the gateway has one (see api/policy_sync.py; the
policies.yaml file only seeds the first version); until then it is read from the file like
the rules. A change that fails to load or validate leaves the previous configuration in
place and logs an error.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from breakwater.config import JUDGE_BASE_URLS, Settings
from breakwater.core.classifier import InjectionScorer, load_scorer
from breakwater.core.judge_clients import (
    AnthropicJudgeClient,
    JudgeClient,
    OpenAICompatibleJudgeClient,
)
from breakwater.core.pipeline import Pipeline
from breakwater.core.policy import Policy, parse_policy
from breakwater.core.redact import Redactor
from breakwater.core.rules import parse_rules
from breakwater.detectors.base import Detector
from breakwater.detectors.exfil_channel import ExfilChannel
from breakwater.detectors.hidden_content import HiddenContent
from breakwater.detectors.injection_classifier import InjectionClassifier
from breakwater.detectors.injection_rules import InjectionRules
from breakwater.detectors.judge import Judge
from breakwater.detectors.leak_pii import LeakPii
from breakwater.detectors.leak_secrets import LeakSecrets
from breakwater.detectors.leak_system_prompt import LeakSystemPrompt
from breakwater.detectors.tool_guard import ToolGuard, parse_tool_policy

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

    @property
    def layers(self) -> tuple[int, ...]:
        return self.pipeline.layers

    def scan_version(self, max_layer: int | None) -> str:
        """The version a scan ran under. Scans capped at a layer get their own, so a cached
        result from a capped scan never stands in for a full one."""
        return self.version if max_layer is None else f"{self.version}/L{max_layer}"


@dataclass(frozen=True)
class Models:
    """Long-lived models shared by every configuration version (loaded once at startup)."""

    classifier: InjectionScorer | None = None
    judge: Judge | None = None

    async def aclose(self) -> None:
        if self.judge is not None:
            await self.judge.aclose()


def build_runtime(
    policy_raw: bytes,
    injection_raw: bytes,
    secrets_raw: bytes,
    tools_raw: bytes,
    models: Models | None = None,
) -> Runtime:
    models = models or Models()
    policy = parse_policy(policy_raw)
    settings = policy.config.detectors
    injection_rules = parse_rules(injection_raw, INJECTION_RULES_FILE)
    secret_rules = parse_rules(secrets_raw, SECRET_RULES_FILE)
    secrets = LeakSecrets(secret_rules, settings.leak_secrets)
    pii = LeakPii(settings.leak_pii)
    detectors: list[Detector] = [
        InjectionRules(injection_rules),
        secrets,
        LeakSystemPrompt(settings.leak_system_prompt),
        pii,
        ExfilChannel(settings.exfil_channel),
        HiddenContent(),
    ]
    if models.classifier is not None:
        detectors.append(InjectionClassifier(models.classifier, settings.injection_classifier))
    tool_guard = ToolGuard(parse_tool_policy(tools_raw))
    digest = hashlib.sha256()
    for raw in (policy_raw, injection_raw, secrets_raw, tools_raw):
        digest.update(hashlib.sha256(raw).digest())
    # Cached scan results are only reused under the same models.
    if models.classifier is not None:
        digest.update(models.classifier.model_id.encode())
    if models.judge is not None:
        digest.update(models.judge.model_id.encode())
    return Runtime(
        policy=policy,
        pipeline=Pipeline(detectors, policy, models.judge),
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
        models: Models | None = None,
    ) -> None:
        self.models = models or Models()
        self._paths = (
            policies_path,
            rules_dir / INJECTION_RULES_FILE,
            rules_dir / SECRET_RULES_FILE,
            rules_dir / TOOL_POLICY_FILE,
        )
        self._interval = check_interval
        self._clock = clock
        self._pinned = False
        # The active database policy (its text and version id), once set.
        self._policy: bytes | None = None
        self.policy_version: int | None = None
        self._signature = self._stat()
        self._runtime = self._load()
        self._next_check = clock() + check_interval

    def _stat(self) -> tuple[tuple[int, int], ...]:
        return tuple((p.stat().st_mtime_ns, p.stat().st_size) for p in self._paths)

    def _load(self, policy_raw: bytes | None = None) -> Runtime:
        policy, injection, secrets, tools = (p.read_bytes() for p in self._paths)
        policy = policy_raw or self._policy or policy
        return build_runtime(policy, injection, secrets, tools, models=self.models)

    @property
    def policy_file(self) -> Path:
        return self._paths[0]

    def check_policy(self, raw: bytes) -> Runtime:
        """The runtime ``raw`` would give with the current rules. Raises if it is invalid."""
        return self._load(raw)

    def set_policy(self, raw: bytes, version_id: int) -> None:
        """Run the policy ``raw`` (database version ``version_id``) from now on. Raises if it
        is invalid, keeping the current one."""
        runtime = self._load(raw)
        self._policy, self.policy_version = raw, version_id
        if not self._pinned:
            if runtime.version != self._runtime.version:
                log.info(
                    "policy applied",
                    extra={"policy_version": version_id, "version": runtime.version},
                )
            self._runtime = runtime

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


def load_models(settings: Settings) -> Models:
    """The models the settings turn on, loaded and warmed up (slow: call off the event loop)."""
    classifier = None
    if settings.classifier_enabled:
        classifier = load_scorer(
            settings.classifier_model,
            settings.classifier_revision,
            settings.classifier_onnx_subfolder,
            settings.classifier_injection_label,
            settings.classifier_threads,
        )
    return Models(classifier=classifier, judge=make_judge(settings))


def make_judge(settings: Settings) -> Judge | None:
    if not settings.judge_enabled or settings.judge_model is None:
        return None
    key = settings.judge_api_key.get_secret_value() if settings.judge_api_key else None
    client: JudgeClient
    if settings.judge_provider == "anthropic" and key is not None:
        client = AnthropicJudgeClient(
            key,
            settings.judge_model,
            settings.judge_max_tokens,
            settings.judge_effort,
            settings.judge_base_url,
        )
    elif settings.judge_provider in ("groq", "gemini", "openai_compatible"):
        base_url = settings.judge_base_url or JUDGE_BASE_URLS.get(settings.judge_provider)
        if base_url is None:
            raise ValueError("the openai_compatible judge needs JUDGE_BASE_URL")
        client = OpenAICompatibleJudgeClient(
            base_url,
            key,
            settings.judge_model,
            settings.judge_max_tokens,
            settings.judge_json_mode,
        )
    else:
        raise ValueError("judge settings are incomplete")
    return Judge(client, settings.judge_provider)


def configured_layers(settings: Settings) -> tuple[int, ...]:
    """The detection layers a gateway with these settings runs, without loading models (for
    tools such as the red-team CLI that run beside the gateway)."""
    layers = (1, 2) if settings.classifier_enabled else (1,)
    return (*layers, 3) if settings.judge_enabled else layers
