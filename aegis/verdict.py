"""Verdict objects returned by Aegis engines after evaluating a payload."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class VerdictCode(enum.Enum):
    """Outcome codes for an Aegis evaluation."""

    ALLOW = "ALLOW"
    BLOCK_LOOP_DETECTED = "BLOCK_LOOP_DETECTED"
    BLOCK_VELOCITY_BREACH = "BLOCK_VELOCITY_BREACH"
    BLOCK_VELOCITY_JITTER = "BLOCK_VELOCITY_JITTER"
    BLOCK_ENTROPY_ANOMALY = "BLOCK_ENTROPY_ANOMALY"
    BLOCK_ENCLAVE_REJECTED = "BLOCK_ENCLAVE_REJECTED"
    BLOCK_ASSET_REJECTED = "BLOCK_ASSET_REJECTED"
    BLOCK_GLOBAL_BLACKLIST = "BLOCK_GLOBAL_BLACKLIST"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    # V3 verdict codes
    BLOCK_QUANTIZATION_REJECTED = "BLOCK_QUANTIZATION_REJECTED"
    BLOCK_SIMULATION_REJECTED = "BLOCK_SIMULATION_REJECTED"
    BLOCK_TEE_REJECTED = "BLOCK_TEE_REJECTED"


@dataclass(frozen=True)
class Verdict:
    """Immutable result of running a payload through the Aegis engines."""

    code: VerdictCode
    reason: str
    engine: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.code is VerdictCode.ALLOW

    @property
    def blocked(self) -> bool:
        return not self.allowed

    def feedback_prompt(self) -> str:
        """Generate synthetic cognitive feedback for the LLM context window."""
        if self.allowed:
            return ""
        if self.code is VerdictCode.PENDING_HUMAN_APPROVAL:
            tx_id = self.metadata.get("tx_id", "unknown")
            return (
                f"[SYSTEM OVERRIDE: TRANSACTION HELD FOR HUMAN REVIEW. "
                f"TX_ID: {tx_id}. REASON: {self.reason}. "
                f"DO NOT RETRY. AWAIT OPERATOR APPROVAL.]"
            )
        return (
            f"[SYSTEM OVERRIDE: ERROR 403. TRANSACTION BLOCKED BY AEGIS FIREWALL. "
            f"REASON: {self.reason}. "
            f"DO NOT RETRY THIS ACTION. PIVOT STRATEGY.]"
        )
