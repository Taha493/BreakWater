"""Per-key request rate limits (spec section 11, keys).

A token bucket per API key, in this process: a key may burst up to its per-minute limit,
then gets one request per 60/limit seconds. With several gateway replicas each counts on
its own, so the limit a key sees is the per-process limit times the replica count.
"""

from __future__ import annotations

import time
from collections.abc import Callable

MAX_TRACKED_KEYS = 10_000


class KeyRateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        # key -> (tokens left, time of the last update)
        self._buckets: dict[str, tuple[float, float]] = {}

    def take(self, key: str, per_minute: int) -> float | None:
        """Spend one token. Returns None when allowed, else seconds until the next token.
        A limit of 0 means unlimited."""
        if per_minute <= 0:
            return None
        now = self._clock()
        rate = per_minute / 60.0
        tokens, last = self._buckets.get(key, (float(per_minute), now))
        tokens = min(float(per_minute), tokens + (now - last) * rate)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return (1.0 - tokens) / rate
        if key not in self._buckets and len(self._buckets) >= MAX_TRACKED_KEYS:
            self._prune(now, rate)
        self._buckets[key] = (tokens - 1.0, now)
        return None

    def _prune(self, now: float, rate: float) -> None:
        """Forget keys idle long enough to have refilled (their next request starts full)."""
        idle = 60.0 / max(rate, 1e-9) if rate else 60.0
        for key, (_, last) in list(self._buckets.items()):
            if now - last >= max(idle, 60.0):
                del self._buckets[key]
