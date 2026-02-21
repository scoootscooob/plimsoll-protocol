"""
AegisFirewall — The orchestrator that chains all deterministic engines.

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
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from aegis.engines.threat_feed import ThreatFeedEngine, ThreatFeedConfig
from aegis.engines.trajectory_hash import TrajectoryHashEngine, TrajectoryHashConfig
from aegis.engines.capital_velocity import CapitalVelocityEngine, CapitalVelocityConfig
from aegis.engines.entropy_guard import EntropyGuardEngine, EntropyGuardConfig
from aegis.engines.asset_guard import AssetGuardEngine, AssetGuardConfig
from aegis.engines.payload_quantizer import PayloadQuantizerEngine, PayloadQuantizerConfig
from aegis.engines.evm_simulator import EVMSimulatorEngine, EVMSimulatorConfig
from aegis.enclave.vault import KeyVault
from aegis.enclave.tee import TEEEnclave, TEEConfig
from aegis.escrow import EscrowQueue, EscrowConfig, EscrowedTransaction
from aegis.verdict import Verdict, VerdictCode

logger = logging.getLogger("aegis")


@dataclass
class AegisConfig:
    """Top-level configuration for the Aegis firewall."""

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


@dataclass
class AegisFirewall:
    """The Agentic Circuit Breaker.

    Usage::

        firewall = AegisFirewall()
        verdict = firewall.evaluate(
            payload={"target": "0xDEAD...", "amount": 500, "function": "transfer"},
            spend_amount=500.0,
        )
        if verdict.blocked:
            # Inject feedback into LLM context
            print(verdict.feedback_prompt())
    """

    config: AegisConfig = field(default_factory=AegisConfig)
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
                engine="AegisFirewall",
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
                engine="AegisFirewall",
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
            logger.info("AEGIS ESCROW: %s", verdict.reason)
            if self.config.on_block:
                self.config.on_block(verdict)
        elif verdict.blocked:
            self._blocked_count += 1
            logger.warning("AEGIS BLOCK: %s", verdict.reason)
            if self.config.on_block:
                self.config.on_block(verdict)
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
