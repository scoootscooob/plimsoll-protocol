"""
Engine 1: State-Space Trajectory Hashing — The Markov Trap Breaker.

Detects when an LLM agent is stuck in an absorbing state (infinite retry loop)
by hashing the *semantic execution parameters* of each action, not its natural
language description. Standard rate-limiters fail because LLMs rephrase their
intent; this engine hashes the deterministic payload signature.

Algorithm:
    1. For each outgoing payload P_t, compute H = SHA-256(target, amount, fn_sig).
    2. Maintain a temporal sliding window of width Δt seconds.
    3. If frequency(H) within the window exceeds threshold θ, the agent is
       mathematically trapped. Verdict: BLOCK.

Time complexity: O(1) amortized per check (hash table lookup + deque pruning).
Space complexity: O(W) where W = max window entries.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from aegis.verdict import Verdict, VerdictCode

_ENGINE_NAME = "TrajectoryHash"


@dataclass
class TrajectoryHashConfig:
    """Tunable parameters for the trajectory hash engine."""

    window_seconds: float = 60.0
    max_duplicates: int = 3
    hash_fields: tuple[str, ...] = ("target", "amount", "function")


@dataclass
class TrajectoryHashEngine:
    """Detects LLM retry loops via deterministic payload hashing."""

    config: TrajectoryHashConfig = field(default_factory=TrajectoryHashConfig)
    _windows: dict[str, deque[float]] = field(
        default_factory=lambda: defaultdict(deque), init=False, repr=False
    )

    def _compute_hash(self, payload: dict[str, Any]) -> str:
        """SHA-256 of the canonical execution parameters."""
        parts: list[str] = []
        for key in self.config.hash_fields:
            val = payload.get(key, "")
            parts.append(f"{key}={val}")
        canonical = "|".join(parts)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _prune_window(self, window: deque[float], now: float) -> None:
        """Evict timestamps older than the sliding window — O(k) amortised."""
        cutoff = now - self.config.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

    def evaluate(self, payload: dict[str, Any]) -> Verdict:
        """Run the trajectory hash check. Returns a Verdict."""
        h = self._compute_hash(payload)
        now = time.monotonic()
        window = self._windows[h]

        self._prune_window(window, now)
        window.append(now)

        count = len(window)
        if count > self.config.max_duplicates:
            return Verdict(
                code=VerdictCode.BLOCK_LOOP_DETECTED,
                reason=(
                    f"LOOP DETECTED: Identical intent hash {h[:12]}… seen "
                    f"{count}x in {self.config.window_seconds}s window "
                    f"(threshold: {self.config.max_duplicates})"
                ),
                engine=_ENGINE_NAME,
                metadata={"hash": h, "count": count, "window_s": self.config.window_seconds},
            )

        return Verdict(
            code=VerdictCode.ALLOW,
            reason="Trajectory hash within normal bounds",
            engine=_ENGINE_NAME,
            metadata={"hash": h, "count": count},
        )

    def reset(self) -> None:
        """Clear all tracked state."""
        self._windows.clear()
