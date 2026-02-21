"""
Engine 2: Capital Velocity Bound — First-Derivative Physics with PID Control.

Static spend limits ("max $50/day") are too rigid for autonomous agents that
must react in real-time to market conditions. Instead, Aegis caps the *first
derivative* of capital expenditure: d(Capital)/dt ≤ V_max.

A PID (Proportional-Integral-Derivative) controller monitors the agent's
spend velocity against its historically established baseline variance σ².
If the velocity spikes exponentially beyond the baseline — the mathematical
signature of a prompt-injection attack or flash-crash hallucination — the
breaker trips and hard-locks the wallet.

PID Terms:
    P  — Proportional to *current* velocity overshoot.
    I  — Integral of accumulated spend over the observation window
         (catches slow-bleed attacks).
    D  — Derivative of velocity change (catches sudden ramps).

Time complexity: O(1) per check.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import struct
import time
from collections import deque
from dataclasses import dataclass, field
from typing import NamedTuple

from aegis.verdict import Verdict, VerdictCode

_ENGINE_NAME = "CapitalVelocity"


class SpendRecord(NamedTuple):
    timestamp: float
    amount: float


@dataclass
class CapitalVelocityConfig:
    """Tunable parameters for the PID velocity controller."""

    v_max: float = 100.0          # Max allowed spend velocity (units/sec)
    window_seconds: float = 300.0  # Observation window for baseline
    k_p: float = 1.0              # Proportional gain
    k_i: float = 0.3              # Integral gain
    k_d: float = 0.5              # Derivative gain
    pid_threshold: float = 2.0    # PID output above which we block
    min_samples: int = 2          # Min records before PID activates
    max_single_amount: float = float("inf")  # Hard cap on any single tx

    # ── Algorithmic Jitter (V2) ──────────────────────────────────
    jitter_enabled: bool = False           # Enable HMAC-based threshold jitter
    jitter_pct: float = 0.12              # ±12% jitter range
    jitter_rotation_seconds: float = 3600.0  # Nonce rotation interval
    dead_man_switch: bool = False          # Lock engine after jitter catch


@dataclass
class CapitalVelocityEngine:
    """PID-controlled spend velocity governor with optional algorithmic jitter."""

    config: CapitalVelocityConfig = field(default_factory=CapitalVelocityConfig)
    _records: deque[SpendRecord] = field(
        default_factory=deque, init=False, repr=False
    )
    _total_spent: float = field(default=0.0, init=False, repr=False)
    _last_velocity: float = field(default=0.0, init=False, repr=False)
    _integral: float = field(default=0.0, init=False, repr=False)
    # Jitter state
    _jitter_nonce: bytes = field(default=b"", init=False, repr=False)
    _dead_man_locked: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._jitter_nonce = os.urandom(32)

    # ── Window management ────────────────────────────────────────

    def _prune(self, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while self._records and self._records[0].timestamp < cutoff:
            old = self._records.popleft()
            self._total_spent -= old.amount

    def _current_velocity(self, now: float) -> float:
        """Compute instantaneous spend velocity (units/sec) over the window."""
        if len(self._records) < 2:
            return 0.0
        elapsed = now - self._records[0].timestamp
        if elapsed <= 0:
            return 0.0
        return self._total_spent / elapsed

    # ── Jitter computation ───────────────────────────────────────

    def _compute_jitter_factor(self, now: float) -> float:
        """Compute a deterministic jitter factor in [-pct, +pct] using HMAC.

        The factor is deterministic within a time slot (rotation window) but
        unpredictable to an external observer who doesn't know the nonce.
        """
        if not self.config.jitter_enabled:
            return 0.0

        # Compute the time slot index
        slot = int(now / self.config.jitter_rotation_seconds)
        slot_bytes = struct.pack(">Q", slot)

        # HMAC-SHA256(nonce, time_slot) → deterministic but unpredictable
        digest = hmac.new(
            self._jitter_nonce, slot_bytes, hashlib.sha256
        ).digest()

        # Map first 8 bytes to a float in [0, 1)
        raw = struct.unpack(">Q", digest[:8])[0]
        unit = raw / (2**64)  # [0, 1)

        # Map to [-pct, +pct]
        pct = self.config.jitter_pct
        return (unit * 2.0 - 1.0) * pct

    # ── PID computation ──────────────────────────────────────────

    def _compute_pid(self, velocity: float, effective_v_max: float | None = None) -> tuple[float, dict]:
        """Compute PID controller output. Mutates internal state (_integral, _last_velocity)."""
        v_max = effective_v_max if effective_v_max is not None else self.config.v_max
        error = velocity - v_max

        # P term
        p_term = self.config.k_p * error

        # I term — accumulated overshoot
        if error > 0:
            self._integral += error
        else:
            # Decay integral when velocity is under limit (anti-windup)
            self._integral = max(0.0, self._integral * 0.9)
        i_term = self.config.k_i * self._integral

        # D term — rate of velocity change
        d_error = velocity - self._last_velocity
        d_term = self.config.k_d * d_error

        self._last_velocity = velocity

        output = p_term + i_term + d_term
        details = {
            "p_term": round(p_term, 4),
            "i_term": round(i_term, 4),
            "d_term": round(d_term, 4),
            "pid_output": round(output, 4),
            "velocity": round(velocity, 4),
            "v_max": v_max,
        }
        return output, details

    def _compute_pid_readonly(self, velocity: float, v_max: float) -> float:
        """Compute PID output WITHOUT mutating state (for nominal comparison)."""
        error = velocity - v_max
        p_term = self.config.k_p * error
        # Use current integral snapshot
        integral = self._integral + error if error > 0 else max(0.0, self._integral * 0.9)
        i_term = self.config.k_i * integral
        d_error = velocity - self._last_velocity
        d_term = self.config.k_d * d_error
        return p_term + i_term + d_term

    # ── Main evaluation ──────────────────────────────────────────

    def evaluate(self, amount: float) -> Verdict:
        """Evaluate a proposed spend of `amount` units."""
        now = time.monotonic()
        self._prune(now)

        # Dead man's switch — engine is permanently locked
        if self._dead_man_locked:
            return Verdict(
                code=VerdictCode.BLOCK_VELOCITY_JITTER,
                reason="DEAD MAN SWITCH: Engine locked after jitter anomaly",
                engine=_ENGINE_NAME,
                metadata={"dead_man_locked": True},
            )

        # Hard cap check
        if amount > self.config.max_single_amount:
            return Verdict(
                code=VerdictCode.BLOCK_VELOCITY_BREACH,
                reason=(
                    f"SINGLE TRANSACTION CAP: {amount} exceeds hard limit "
                    f"{self.config.max_single_amount}"
                ),
                engine=_ENGINE_NAME,
                metadata={"amount": amount, "cap": self.config.max_single_amount},
            )

        # Record the spend
        self._records.append(SpendRecord(timestamp=now, amount=amount))
        self._total_spent += amount

        # Need minimum samples for meaningful PID
        if len(self._records) < self.config.min_samples:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="Insufficient samples for PID — allowing",
                engine=_ENGINE_NAME,
                metadata={"samples": len(self._records)},
            )

        velocity = self._current_velocity(now)

        # Compute jittered effective v_max
        jitter_factor = self._compute_jitter_factor(now)
        effective_v_max = self.config.v_max * (1.0 + jitter_factor)

        # Run PID with the (possibly jittered) v_max
        pid_output, pid_details = self._compute_pid(velocity, effective_v_max)
        pid_details["jitter_factor"] = round(jitter_factor, 6)
        pid_details["effective_v_max"] = round(effective_v_max, 4)

        if pid_output > self.config.pid_threshold:
            # Rollback the spend record since we're blocking
            self._records.pop()
            self._total_spent -= amount

            # Check if this is a jitter-specific catch:
            # Would this have passed under nominal (non-jittered) v_max?
            nominal_pid = self._compute_pid_readonly(velocity, self.config.v_max)
            is_jitter_catch = (
                self.config.jitter_enabled
                and nominal_pid <= self.config.pid_threshold
            )

            if is_jitter_catch:
                # Trigger dead man's switch if enabled
                if self.config.dead_man_switch:
                    self._dead_man_locked = True
                    pid_details["dead_man_triggered"] = True

                return Verdict(
                    code=VerdictCode.BLOCK_VELOCITY_JITTER,
                    reason=(
                        f"JITTER CATCH: PID output {pid_output:.2f} > "
                        f"threshold {self.config.pid_threshold} "
                        f"(effective v_max {effective_v_max:.2f}, "
                        f"jitter {jitter_factor:+.4f}). "
                        f"Attacker probing near threshold boundary"
                    ),
                    engine=_ENGINE_NAME,
                    metadata=pid_details,
                )

            return Verdict(
                code=VerdictCode.BLOCK_VELOCITY_BREACH,
                reason=(
                    f"VELOCITY BREACH: PID output {pid_output:.2f} > "
                    f"threshold {self.config.pid_threshold}. "
                    f"Spend velocity {velocity:.2f} units/s exceeds "
                    f"v_max {self.config.v_max} units/s"
                ),
                engine=_ENGINE_NAME,
                metadata=pid_details,
            )

        return Verdict(
            code=VerdictCode.ALLOW,
            reason=f"Velocity {velocity:.2f} units/s within PID bounds",
            engine=_ENGINE_NAME,
            metadata=pid_details,
        )

    def reset(self) -> None:
        """Clear all tracked state and regenerate jitter nonce."""
        self._records.clear()
        self._total_spent = 0.0
        self._last_velocity = 0.0
        self._integral = 0.0
        self._dead_man_locked = False
        self._jitter_nonce = os.urandom(32)
