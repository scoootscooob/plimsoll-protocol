"""
PlimsollFirewall — The orchestrator that chains all deterministic engines.

Sits between the Reason and Act phases of the agent's OODA loop.
For every outgoing action, the payload passes through:

    0. ThreatFeed         → Global Bloom Filter blacklist (O(1), sub-ms)
    1. TrajectoryHash     → Loop detection                (O(1))
    2. CapitalVelocity    → PID velocity governor          (O(1))
    3. EntropyGuard       → Secret exfil detection         (O(n))
    4. AssetGuard         → Oracle-backed swap guard       (O(1) + oracle)
    5. PayloadQuantizer   → Steganography destruction      (O(n))
    6. EVMSimulator       → Pre-execution simulation       (O(1) + sim)

If ANY engine returns BLOCK, the payload is either:
    - Dropped with synthetic cognitive feedback (default), or
    - Escrowed for human review if spend >= ``auto_escalate_above``.

TEE enclave integration (V3) provides hardware-isolated signing when
a TEEBackend is configured.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from plimsoll.engines.threat_feed import ThreatFeedEngine, ThreatFeedConfig
from plimsoll.engines.trajectory_hash import TrajectoryHashEngine, TrajectoryHashConfig
from plimsoll.engines.capital_velocity import CapitalVelocityEngine, CapitalVelocityConfig
from plimsoll.engines.entropy_guard import EntropyGuardEngine, EntropyGuardConfig
from plimsoll.engines.asset_guard import AssetGuardEngine, AssetGuardConfig
from plimsoll.engines.payload_quantizer import PayloadQuantizerEngine, PayloadQuantizerConfig
from plimsoll.engines.evm_simulator import EVMSimulatorEngine, EVMSimulatorConfig
from plimsoll.enclave.vault import KeyVault
from plimsoll.enclave.tee import TEEEnclave, TEEConfig
from plimsoll.escrow import EscrowQueue, EscrowConfig, EscrowedTransaction
from plimsoll.verdict import Verdict, VerdictCode

logger = logging.getLogger("plimsoll")


@dataclass
class PlimsollConfig:
    """Top-level configuration for the Plimsoll firewall."""

    threat_feed: ThreatFeedConfig = field(default_factory=ThreatFeedConfig)
    trajectory: TrajectoryHashConfig = field(default_factory=TrajectoryHashConfig)
    velocity: CapitalVelocityConfig = field(default_factory=CapitalVelocityConfig)
    entropy: EntropyGuardConfig = field(default_factory=EntropyGuardConfig)
    asset_guard: AssetGuardConfig = field(default_factory=AssetGuardConfig)
    quantizer: PayloadQuantizerConfig = field(default_factory=PayloadQuantizerConfig)
    simulator: EVMSimulatorConfig = field(default_factory=EVMSimulatorConfig)
    escrow: EscrowConfig = field(default_factory=EscrowConfig)
    tee: TEEConfig = field(default_factory=TEEConfig)
    enable_vault: bool = True
    on_block: Callable[[Verdict], None] | None = None

    # ── ZERO-DAY 4: Cognitive Starvation Defense ──────────────────
    # If an agent hits the firewall `strike_max` times within
    # `strike_window_secs`, trigger a "Cognitive Sever" — the agent's
    # LLM API key is revoked for `sever_duration_secs`.
    strike_max: int = 5                  # Max blocks before sever
    strike_window_secs: float = 60.0     # Rolling window for strikes
    sever_duration_secs: float = 900.0   # 15 min lockout
    cognitive_sever_enabled: bool = False  # Disabled by default
    on_cognitive_sever: Callable[[], None] | None = None  # Webhook callback

    # ── ZERO-DAY 4 (v1.0.2): Paymaster Slashing Defense ────────
    # Track post-simulation reverts per agent. If N transactions pass
    # simulation but revert on-chain within a window, sever the agent's
    # Paymaster connection to stop gas griefing.
    revert_strike_max: int = 0               # 0 = disabled
    revert_strike_window_secs: float = 300.0  # 5-minute rolling window
    on_paymaster_sever: Callable[[], None] | None = None  # Webhook callback

    # ── v1.0.3 Bounty 3: L1 Blob-Fee Asymmetry ──────────────────
    # Chain ID for L2-aware TVAR computation. On L2 rollups, TVAR
    # includes L1 data posting cost to prevent calldata-padding attacks.
    # 0 = unknown/skip L1 fee, 1 = L1 mainnet (no L1 fee).
    chain_id: int = 0

    # ── v1.0.3 Bounty 4: Gas Black Hole Defense ─────────────────
    # Gas anomaly ratio threshold. If actual gas / simulated gas > ratio,
    # record a gas anomaly strike (reuses Paymaster sever mechanism).
    # 0.0 = disabled.
    gas_anomaly_ratio: float = 0.0

    # ── v1.0.4 Kill-Shot 2: PVG Heist Defense ────────────────────
    # Maximum preVerificationGas allowed in ERC-4337 UserOperations.
    # PVG is a flat Bundler fee invisible to the EVM simulator.
    # 0 = disabled (backward compat).
    max_pre_verification_gas: int = 0

    # ── v1.0.4 Kill-Shot 4: Permit2 Time-Bomb Defense ────────────
    # Maximum duration (seconds) for EIP-712 permit/deadline fields.
    # If expiration/deadline exceeds current_time + this value, refuse.
    # 0 = disabled (backward compat).
    max_permit_duration_secs: int = 0


@dataclass
class PlimsollFirewall:
    """The Agentic Circuit Breaker.

    Usage::

        firewall = PlimsollFirewall()
        verdict = firewall.evaluate(
            payload={"target": "0xDEAD...", "amount": 500, "function": "transfer"},
            spend_amount=500.0,
        )
        if verdict.blocked:
            # Inject feedback into LLM context
            print(verdict.feedback_prompt())
    """

    config: PlimsollConfig = field(default_factory=PlimsollConfig)
    _threat_feed: ThreatFeedEngine = field(init=False, repr=False)
    _trajectory: TrajectoryHashEngine = field(init=False, repr=False)
    _velocity: CapitalVelocityEngine = field(init=False, repr=False)
    _entropy: EntropyGuardEngine = field(init=False, repr=False)
    _asset_guard: AssetGuardEngine = field(init=False, repr=False)
    _quantizer: PayloadQuantizerEngine = field(init=False, repr=False)
    _simulator: EVMSimulatorEngine = field(init=False, repr=False)
    _escrow: EscrowQueue = field(init=False, repr=False)
    _tee: TEEEnclave = field(init=False, repr=False)
    vault: KeyVault = field(init=False, repr=False)
    _blocked_count: int = field(default=0, init=False, repr=False)
    _allowed_count: int = field(default=0, init=False, repr=False)
    _escrowed_count: int = field(default=0, init=False, repr=False)
    _history: list[tuple[float, Verdict]] = field(
        default_factory=list, init=False, repr=False
    )
    # ZERO-DAY 4: Cognitive Starvation — strike counter
    _strike_timestamps: deque = field(
        default_factory=deque, init=False, repr=False
    )
    _cognitive_severed: bool = field(default=False, init=False, repr=False)
    _sever_until: float = field(default=0.0, init=False, repr=False)
    # ZERO-DAY 4 (v1.0.2): Paymaster Slashing — revert tracking
    _revert_timestamps: deque = field(
        default_factory=deque, init=False, repr=False
    )
    _paymaster_severed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self._threat_feed = ThreatFeedEngine(config=self.config.threat_feed)
        self._trajectory = TrajectoryHashEngine(config=self.config.trajectory)
        self._velocity = CapitalVelocityEngine(config=self.config.velocity)
        self._entropy = EntropyGuardEngine(config=self.config.entropy)
        self._asset_guard = AssetGuardEngine(config=self.config.asset_guard)
        self._quantizer = PayloadQuantizerEngine(config=self.config.quantizer)
        self._simulator = EVMSimulatorEngine(config=self.config.simulator)
        self._escrow = EscrowQueue(config=self.config.escrow)
        self._tee = TEEEnclave(config=self.config.tee)
        self.vault = KeyVault() if self.config.enable_vault else None  # type: ignore[assignment]
        # PATCH (Flaw 1): Inversion of Control — vault owns the firewall.
        # The vault independently evaluates every tx BEFORE decrypting the key.
        if self.vault is not None:
            self.vault.bind_firewall(self)

    def evaluate(
        self,
        payload: dict[str, Any],
        spend_amount: float = 0.0,
    ) -> Verdict:
        """Run a payload through all six engines. First BLOCK wins.

        If escrow is enabled and the blocked spend exceeds
        ``auto_escalate_above``, the transaction is held for human review.
        """

        # ── ZERO-DAY 4: Cognitive Starvation — check sever state ──
        # If the agent has been cognitively severed, block ALL actions
        # until the sever expires. This prevents infinite retry loops
        # from burning cloud compute / API credits.
        if self._cognitive_severed:
            now = time.time()
            if now < self._sever_until:
                remaining = int(self._sever_until - now)
                return self._record(Verdict(
                    code=VerdictCode.BLOCK_COGNITIVE_STARVATION,
                    reason=(
                        f"ZERO-DAY 4 (COGNITIVE STARVATION): Agent is "
                        f"cognitively severed. {remaining}s remaining in "
                        f"cooldown. Too many blocked attempts detected — "
                        f"LLM API access revoked to prevent compute drain."
                    ),
                    engine="CognitiveSever",
                    metadata={
                        "sever_until": self._sever_until,
                        "remaining_secs": remaining,
                    },
                ))
            else:
                # Sever has expired — resume normal operation
                self._cognitive_severed = False
                self._strike_timestamps.clear()
                logger.info("ZERO-DAY 4: Cognitive sever expired — resuming")

        # ── ZERO-DAY 4 (v1.0.2): Paymaster Slashing — check sever state ──
        # If too many post-simulation reverts detected, block ALL actions
        # to stop gas griefing against the Enterprise Paymaster.
        if self._paymaster_severed:
            return self._record(Verdict(
                code=VerdictCode.BLOCK_PAYMASTER_SEVERED,
                reason=(
                    "ZERO-DAY 4 (PAYMASTER SLASHING): Paymaster connection "
                    "severed. Too many post-simulation reverts detected — "
                    "agent is blocked to prevent gas drain."
                ),
                engine="PaymasterSever",
                metadata={
                    "revert_count": len(self._revert_timestamps),
                    "threshold": self.config.revert_strike_max,
                },
            ))

        # Engine 0: Threat Feed — is target globally blacklisted?
        v = self._threat_feed.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # Engine 1: Trajectory Hash — are we in a retry loop?
        v = self._trajectory.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # Engine 2: Capital Velocity — is spend velocity spiking?
        if spend_amount > 0:
            v = self._velocity.evaluate(spend_amount)
            if v.blocked:
                return self._maybe_escrow(v, payload, spend_amount)

        # Engine 3: Entropy Guard — is the payload leaking secrets?
        v = self._entropy.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # Engine 4: Asset Guard — is this a bad swap?
        v = self._asset_guard.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # Engine 5: Payload Quantizer — steganography in amounts?
        v = self._quantizer.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # Engine 6: EVM Simulator — does the tx outcome look safe?
        v = self._simulator.evaluate(payload)
        if v.blocked:
            return self._maybe_escrow(v, payload, spend_amount)

        # All clear
        return self._record(
            Verdict(
                code=VerdictCode.ALLOW,
                reason="All engines passed",
                engine="PlimsollFirewall",
            )
        )

    def _maybe_escrow(
        self,
        verdict: Verdict,
        payload: dict[str, Any],
        spend_amount: float,
    ) -> Verdict:
        """Route a blocked verdict through escrow if applicable."""
        cfg = self.config.escrow
        if (
            cfg.enable_escrow
            and spend_amount >= cfg.auto_escalate_above
        ):
            # Escalate to escrow for human review
            tx = self._escrow.enqueue(
                payload=payload,
                spend_amount=spend_amount,
                block_reason=verdict.reason,
                block_engine=verdict.engine,
            )
            escrowed_verdict = Verdict(
                code=VerdictCode.PENDING_HUMAN_APPROVAL,
                reason=(
                    f"Escrowed for human review (original: {verdict.reason})"
                ),
                engine="PlimsollFirewall",
                metadata={
                    "tx_id": tx.tx_id,
                    "original_code": verdict.code.value,
                    "original_engine": verdict.engine,
                    "spend_amount": spend_amount,
                },
            )
            self._escrowed_count += 1
            return self._record(escrowed_verdict)

        # Hard block
        return self._record(verdict)

    def evaluate_intent(self, intent: object) -> Verdict:
        """Evaluate a :class:`~plimsoll.intent.NormalizedIntent` through all engines.

        This is the **universal entry point** for multi-chain payloads.
        The intent is translated to the standard payload dict format
        that the existing engines understand.

        .. code-block:: python

            from plimsoll.intent import intent_from_evm_tx
            intent = intent_from_evm_tx(tx_dict, price_usd=3000.0)
            verdict = firewall.evaluate_intent(intent)
        """
        from plimsoll.intent import NormalizedIntent  # deferred to avoid circular

        if not isinstance(intent, NormalizedIntent):
            raise TypeError(
                f"evaluate_intent() expects a NormalizedIntent, got {type(intent).__name__}"
            )
        payload = intent.to_plimsoll_payload()
        return self.evaluate(payload, spend_amount=intent.capital_at_risk_usd)

    def sign_and_send(
        self,
        key_id: str,
        payload: dict[str, Any],
        spend_amount: float = 0.0,
        executor: Callable[[dict[str, Any], str], Any] | None = None,
    ) -> tuple[Verdict, Any]:
        """Evaluate, sign via vault if allowed, and optionally execute.

        This is the full Reason → Check → Sign → Act pipeline.
        """
        verdict = self.evaluate(payload, spend_amount)
        if verdict.blocked:
            return verdict, None

        result = None
        if self.vault and self.vault.has_key(key_id):
            signature = self.vault.sign_transaction(key_id, payload)
            if executor:
                result = executor(payload, signature)
        elif executor:
            result = executor(payload, "")

        return verdict, result

    # ── Escrow management ────────────────────────────────────────

    def approve(self, tx_id: str) -> Optional[EscrowedTransaction]:
        """Approve an escrowed transaction."""
        return self._escrow.approve(tx_id)

    def reject(self, tx_id: str) -> Optional[EscrowedTransaction]:
        """Reject an escrowed transaction."""
        return self._escrow.reject(tx_id)

    def list_escrowed(self) -> list[EscrowedTransaction]:
        """List all pending escrowed transactions."""
        return self._escrow.list_pending()

    # ── Paymaster revert tracking (ZERO-DAY 4, v1.0.2) ────────

    def record_revert(self) -> None:
        """Record a post-simulation on-chain revert.

        Call this when a transaction that passed Plimsoll simulation reverts
        on-chain. If the revert count exceeds ``revert_strike_max`` within
        ``revert_strike_window_secs``, the agent's Paymaster connection
        is severed (permanent until manual reset).
        """
        if self.config.revert_strike_max <= 0:
            return  # Feature disabled

        now = time.time()
        self._revert_timestamps.append(now)

        # Prune timestamps outside the rolling window
        cutoff = now - self.config.revert_strike_window_secs
        while (
            self._revert_timestamps
            and self._revert_timestamps[0] < cutoff
        ):
            self._revert_timestamps.popleft()

        # Check if revert count exceeds threshold
        if len(self._revert_timestamps) >= self.config.revert_strike_max:
            self._paymaster_severed = True
            logger.critical(
                "ZERO-DAY 4 (v1.0.2): PAYMASTER SEVER TRIGGERED — "
                "%d reverts in %.0fs window. Agent Paymaster connection severed.",
                len(self._revert_timestamps),
                self.config.revert_strike_window_secs,
            )
            # Fire webhook callback (exception-safe)
            if self.config.on_paymaster_sever:
                try:
                    self.config.on_paymaster_sever()
                except Exception:
                    logger.exception(
                        "ZERO-DAY 4 (v1.0.2): on_paymaster_sever callback failed"
                    )

    # ── Gas anomaly tracking (v1.0.3 Bounty 4) ─────────────────

    def record_gas_anomaly(self, actual_gas: int, simulated_gas: int) -> None:
        """Record a gas anomaly — actual gas significantly exceeded simulated gas.

        v1.0.3 Bounty 4 (Gas Black Hole): The 63/64ths EIP-150 rule allows
        a malicious contract to burn gas internally, catch its own OOG, and
        return success. This bypasses the revert strike system because the
        parent call returns ``success=True``.

        This method detects the attack by comparing actual vs simulated gas.
        If the ratio exceeds ``gas_anomaly_ratio``, it records a strike using
        the same paymaster sever mechanism as ``record_revert()``.

        Parameters
        ----------
        actual_gas : int
            Gas consumed on-chain (from receipt.gasUsed).
        simulated_gas : int
            Gas consumed in simulation.
        """
        if self.config.gas_anomaly_ratio <= 0.0:
            return  # Feature disabled

        if simulated_gas <= 0:
            return  # No simulation data to compare

        ratio = actual_gas / simulated_gas
        if ratio > self.config.gas_anomaly_ratio:
            logger.warning(
                "v1.0.3 BOUNTY 4 (GAS BLACK HOLE): Gas anomaly detected — "
                "actual=%d, simulated=%d, ratio=%.1f (threshold=%.1f). "
                "Recording strike.",
                actual_gas, simulated_gas, ratio, self.config.gas_anomaly_ratio,
            )
            # Reuse the paymaster sever mechanism
            self.record_revert()

    # ── TEE enclave ──────────────────────────────────────────────

    @property
    def tee(self) -> TEEEnclave:
        """Access the TEE enclave for key management and signing."""
        return self._tee

    # ── Quantizer helper ─────────────────────────────────────────

    def quantize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a payload with numeric fields snapped to the tick grid.

        Use this in permissive mode to rewrite payloads before sending.
        """
        return self._quantizer.quantize_payload(payload)

    # ── Recording & stats ────────────────────────────────────────

    def _record(self, verdict: Verdict) -> Verdict:
        """Record verdict in history and invoke callbacks."""
        now = time.time()
        self._history.append((now, verdict))

        if verdict.code is VerdictCode.PENDING_HUMAN_APPROVAL:
            # Escrowed — not a hard block, but not allowed either
            logger.info("PLIMSOLL ESCROW: %s", verdict.reason)
            if self.config.on_block:
                self.config.on_block(verdict)
        elif verdict.blocked:
            self._blocked_count += 1
            logger.warning("PLIMSOLL BLOCK: %s", verdict.reason)
            if self.config.on_block:
                self.config.on_block(verdict)

            # ── ZERO-DAY 4: Cognitive Starvation — record strike ──
            if self.config.cognitive_sever_enabled:
                self._strike_timestamps.append(now)
                # Prune timestamps outside the rolling window
                cutoff = now - self.config.strike_window_secs
                while (
                    self._strike_timestamps
                    and self._strike_timestamps[0] < cutoff
                ):
                    self._strike_timestamps.popleft()
                # Check if strike count exceeds threshold
                if len(self._strike_timestamps) >= self.config.strike_max:
                    self._cognitive_severed = True
                    self._sever_until = now + self.config.sever_duration_secs
                    logger.critical(
                        "ZERO-DAY 4: COGNITIVE SEVER TRIGGERED — "
                        "%d blocks in %.0fs window. Agent locked out for %.0fs.",
                        len(self._strike_timestamps),
                        self.config.strike_window_secs,
                        self.config.sever_duration_secs,
                    )
                    # Fire webhook callback (exception-safe)
                    if self.config.on_cognitive_sever:
                        try:
                            self.config.on_cognitive_sever()
                        except Exception:
                            logger.exception(
                                "ZERO-DAY 4: on_cognitive_sever callback failed"
                            )
        else:
            self._allowed_count += 1

        return verdict

    @property
    def stats(self) -> dict[str, int]:
        return {
            "allowed": self._allowed_count,
            "blocked": self._blocked_count,
            "escrowed": self._escrowed_count,
            "total": self._allowed_count + self._blocked_count + self._escrowed_count,
        }

    @property
    def threat_feed(self) -> ThreatFeedEngine:
        """Access Engine 0 for adding/removing threats."""
        return self._threat_feed

    def reset(self) -> None:
        """Reset all engine state."""
        self._threat_feed.reset()
        self._trajectory.reset()
        self._velocity.reset()
        self._asset_guard.reset()
        self._quantizer.reset()
        self._simulator.reset()
        self._escrow.reset()
        self._tee.reset()
        self._blocked_count = 0
        self._allowed_count = 0
        self._escrowed_count = 0
        self._history.clear()
        # ZERO-DAY 4: Reset cognitive sever state
        self._strike_timestamps.clear()
        self._cognitive_severed = False
        self._sever_until = 0.0
        # ZERO-DAY 4 (v1.0.2): Reset paymaster sever state
        self._revert_timestamps.clear()
        self._paymaster_severed = False
