"""Verdict objects returned by Plimsoll engines after evaluating a payload."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class VerdictCode(enum.Enum):
    """Outcome codes for an Plimsoll evaluation."""

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
    # V4 (God-Tier) verdict codes
    BLOCK_EIP712_PERMIT = "BLOCK_EIP712_PERMIT"
    BLOCK_REALITY_DESYNC = "BLOCK_REALITY_DESYNC"
    BLOCK_GAS_VALUE_RATIO = "BLOCK_GAS_VALUE_RATIO"
    # V5 (Zero-Day v1.0.1) verdict codes
    BLOCK_METAMORPHIC_CODE = "BLOCK_METAMORPHIC_CODE"
    BLOCK_COGNITIVE_STARVATION = "BLOCK_COGNITIVE_STARVATION"
    # V6 (Zero-Day v1.0.2) verdict codes
    BLOCK_TROJAN_RECEIPT = "BLOCK_TROJAN_RECEIPT"
    BLOCK_NON_DETERMINISTIC = "BLOCK_NON_DETERMINISTIC"
    BLOCK_CROSS_CHAIN_REPLAY = "BLOCK_CROSS_CHAIN_REPLAY"
    BLOCK_PAYMASTER_SEVERED = "BLOCK_PAYMASTER_SEVERED"
    # V7 (Zero-Day v1.0.3) verdict codes
    BLOCK_JSON_POLLUTION = "BLOCK_JSON_POLLUTION"
    BLOCK_PROXY_UPGRADE = "BLOCK_PROXY_UPGRADE"
    BLOCK_L1_DATA_FEE_ANOMALY = "BLOCK_L1_DATA_FEE_ANOMALY"
    BLOCK_GAS_ANOMALY = "BLOCK_GAS_ANOMALY"
    # V8 (Kill-Shot v1.0.4) verdict codes
    BLOCK_BUNDLER_ORIGIN_MISMATCH = "BLOCK_BUNDLER_ORIGIN_MISMATCH"
    BLOCK_PVG_CEILING_EXCEEDED = "BLOCK_PVG_CEILING_EXCEEDED"
    BLOCK_PVG_TVAR_ANOMALY = "BLOCK_PVG_TVAR_ANOMALY"
    BLOCK_BRIDGE_REFUND_HIJACK = "BLOCK_BRIDGE_REFUND_HIJACK"
    BLOCK_BRIDGE_RECIPIENT_MISMATCH = "BLOCK_BRIDGE_RECIPIENT_MISMATCH"
    BLOCK_PERMIT_EXPIRY_TOO_LONG = "BLOCK_PERMIT_EXPIRY_TOO_LONG"
    BLOCK_PERMIT_IMMORTAL_SIGNATURE = "BLOCK_PERMIT_IMMORTAL_SIGNATURE"
    # V9 (v2.0 Multi-Chain & Web2) verdict codes
    BLOCK_SVM_UNAUTHORIZED_WRITABLE = "BLOCK_SVM_UNAUTHORIZED_WRITABLE"
    BLOCK_UTXO_FEE_EXCESSIVE = "BLOCK_UTXO_FEE_EXCESSIVE"
    BLOCK_HTTP_BUDGET_EXCEEDED = "BLOCK_HTTP_BUDGET_EXCEEDED"
    BLOCK_INTENT_REJECTED = "BLOCK_INTENT_REJECTED"


@dataclass(frozen=True)
class Verdict:
    """Immutable result of running a payload through the Plimsoll engines."""

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
            f"[SYSTEM OVERRIDE: ERROR 403. TRANSACTION BLOCKED BY PLIMSOLL FIREWALL. "
            f"REASON: {self.reason}. "
            f"DO NOT RETRY THIS ACTION. PIVOT STRATEGY.]"
        )
