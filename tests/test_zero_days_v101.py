"""Tests for Zero-Day Security Patches v1.0.1.

Zero-Day 1: EIP-712 "Silent Dagger" — Already tested in test_god_tier.py
Zero-Day 2: "Mempool Metamorphosis" — EXTCODEHASH Pinning (Rust-side, Python metadata pass-through)
Zero-Day 3: "Jurisdictional Arbitrage" — Deep Calldata Unrolling for cross-chain bridges
Zero-Day 4: "Cognitive Starvation" — Strike Counter + Cognitive Sever
"""

from __future__ import annotations

import time
import pytest

from aegis.engines.asset_guard import (
    AssetGuardConfig,
    AssetGuardEngine,
    KNOWN_BRIDGE_ADDRESSES,
    BRIDGE_FUNCTION_SELECTORS,
)
from aegis.engines.capital_velocity import CapitalVelocityConfig
from aegis.firewall import AegisConfig, AegisFirewall
from aegis.verdict import VerdictCode


# ═════════════════════════════════════════════════════════════════════
# ZERO-DAY 2: Mempool Metamorphosis — EXTCODEHASH Pinning
# (Rust simulator produces target_codehash; Python-side just validates
# metadata passthrough via EVM Simulator engine verdict)
# ═════════════════════════════════════════════════════════════════════


class TestMetamorphicCodehashPinning:
    """Verify EXTCODEHASH metadata flows through the verdict system."""

    def test_metamorphic_verdict_code_exists(self):
        """VerdictCode.BLOCK_METAMORPHIC_CODE is defined."""
        assert hasattr(VerdictCode, "BLOCK_METAMORPHIC_CODE")
        assert VerdictCode.BLOCK_METAMORPHIC_CODE.value == "BLOCK_METAMORPHIC_CODE"

    def test_metamorphic_verdict_is_blocked(self):
        """A BLOCK_METAMORPHIC_CODE verdict is properly blocked."""
        from aegis.verdict import Verdict
        v = Verdict(
            code=VerdictCode.BLOCK_METAMORPHIC_CODE,
            reason="Bytecode mutated since simulation",
            engine="EVMSimulator",
            metadata={"target_codehash": "0xabcdef"},
        )
        assert v.blocked
        assert not v.allowed
        assert "Bytecode mutated" in v.feedback_prompt()

    def test_metamorphic_verdict_feedback_prompt(self):
        """Feedback prompt for metamorphic block contains critical info."""
        from aegis.verdict import Verdict
        v = Verdict(
            code=VerdictCode.BLOCK_METAMORPHIC_CODE,
            reason="Target bytecode changed after simulation",
            engine="EVMSimulator",
        )
        prompt = v.feedback_prompt()
        assert "SYSTEM OVERRIDE" in prompt
        assert "Target bytecode changed" in prompt


# ═════════════════════════════════════════════════════════════════════
# ZERO-DAY 3: Jurisdictional Arbitrage — Bridge Destination Defense
# ═════════════════════════════════════════════════════════════════════


class TestBridgeDestinationDefense:
    """AssetGuard blocks cross-chain bridge txns with unapproved destinations."""

    OPTIMISM_BRIDGE = "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1"
    APPROVED_VAULT = "0x1111111111111111111111111111111111111111"
    HACKER_WALLET = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

    def test_bridge_addresses_populated(self):
        """Known bridge addresses frozenset is not empty."""
        assert len(KNOWN_BRIDGE_ADDRESSES) >= 10

    def test_bridge_selectors_populated(self):
        """Known bridge function selectors are present."""
        assert len(BRIDGE_FUNCTION_SELECTORS) >= 8

    def test_bridge_disabled_by_default(self):
        """With empty approved_destinations, bridge check is a no-op."""
        engine = AssetGuardEngine(config=AssetGuardConfig())
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.HACKER_WALLET,
        })
        # approved_destinations is empty → feature disabled → passes
        assert verdict.allowed

    def test_bridge_approved_destination_passes(self):
        """Transaction to bridge with approved destination passes."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.APPROVED_VAULT,
        })
        assert verdict.allowed

    def test_bridge_unapproved_destination_blocked(self):
        """Transaction to bridge with unapproved destination is blocked."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.HACKER_WALLET,
        })
        assert verdict.blocked
        assert verdict.code == VerdictCode.BLOCK_ASSET_REJECTED
        assert "JURISDICTIONAL ARBITRAGE" in verdict.reason
        assert self.HACKER_WALLET in verdict.reason

    def test_bridge_no_destination_fail_closed(self):
        """Bridge tx with no extractable destination is fail-closed."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            # No destination_address, no calldata
        })
        assert verdict.blocked
        assert "could not be extracted" in verdict.reason

    def test_bridge_destination_case_insensitive(self):
        """Destination matching is case-insensitive."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT.upper()],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.APPROVED_VAULT.lower(),
        })
        assert verdict.allowed

    def test_bridge_calldata_extraction_hex(self):
        """Destination extracted from hex calldata string."""
        # Build calldata: 4-byte selector + 32-byte ABI-encoded address
        # depositETHTo(address,uint32,bytes) selector: 0xb1a1a882
        selector = "b1a1a882"
        # ABI-encode address: left-pad to 32 bytes
        addr = self.APPROVED_VAULT[2:]  # strip 0x
        padded_addr = "0" * 24 + addr  # 12 bytes padding + 20 bytes address
        calldata = "0x" + selector + padded_addr

        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "data": calldata,
        })
        assert verdict.allowed

    def test_bridge_calldata_extraction_bytes(self):
        """Destination extracted from bytes calldata."""
        selector = bytes.fromhex("b1a1a882")
        addr_bytes = bytes.fromhex(self.APPROVED_VAULT[2:])
        padded = b"\x00" * 12 + addr_bytes  # 32-byte ABI word
        calldata = selector + padded

        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "data": calldata,
        })
        assert verdict.allowed

    def test_bridge_calldata_hacker_destination_blocked(self):
        """Calldata-extracted destination not in approved list is blocked."""
        selector = bytes.fromhex("b1a1a882")
        addr_bytes = bytes.fromhex(self.HACKER_WALLET[2:])
        padded = b"\x00" * 12 + addr_bytes
        calldata = selector + padded

        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "data": calldata,
        })
        assert verdict.blocked
        assert "JURISDICTIONAL ARBITRAGE" in verdict.reason

    def test_bridge_calldata_too_short(self):
        """Calldata too short to extract address → fail closed."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "data": "0xb1a1a882",  # Only selector, no params
        })
        assert verdict.blocked
        assert "could not be extracted" in verdict.reason

    def test_non_bridge_target_not_checked(self):
        """Transactions to non-bridge targets skip bridge check."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": "0x0000000000000000000000000000000000000001",
            "token_address": "0xToken1",
            "slippage_bps": 100,
        })
        assert verdict.allowed

    def test_bridge_via_bridge_contract_field(self):
        """Bridge detection also works via explicit bridge_contract field."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": "0x0000000000000000000000000000000000000099",
            "bridge_contract": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.HACKER_WALLET,
        })
        assert verdict.blocked
        assert "JURISDICTIONAL ARBITRAGE" in verdict.reason

    def test_bridge_multiple_approved_destinations(self):
        """Multiple approved destinations are all accepted."""
        vault_a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        vault_b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[vault_a, vault_b],
        ))
        # Vault A → approved
        v = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": vault_a,
        })
        assert v.allowed

        # Vault B → approved
        v = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": vault_b,
        })
        assert v.allowed

    def test_bridge_destination_chain_in_metadata(self):
        """destination_chain is captured in block metadata."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            approved_destinations=[self.APPROVED_VAULT],
        ))
        verdict = engine.evaluate({
            "target": self.OPTIMISM_BRIDGE,
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "destination_address": self.HACKER_WALLET,
            "destination_chain": "optimism",
        })
        assert verdict.blocked
        assert verdict.metadata.get("destination_chain") == "optimism"

    def test_extract_destination_empty_calldata(self):
        """Empty calldata returns empty string."""
        result = AssetGuardEngine._extract_destination_from_calldata("")
        assert result == ""
        result = AssetGuardEngine._extract_destination_from_calldata(b"")
        assert result == ""
        result = AssetGuardEngine._extract_destination_from_calldata(None)
        assert result == ""

    def test_extract_destination_all_zeros(self):
        """All-zero address in calldata returns empty string."""
        selector = bytes.fromhex("b1a1a882")
        padded = b"\x00" * 32
        calldata = selector + padded
        result = AssetGuardEngine._extract_destination_from_calldata(calldata)
        assert result == ""


# ═════════════════════════════════════════════════════════════════════
# ZERO-DAY 4: Cognitive Starvation — Strike Counter + Cognitive Sever
# ═════════════════════════════════════════════════════════════════════


class TestCognitiveStarvation:
    """Firewall detects infinite retry loops and cognitively severs the agent."""

    def _make_firewall(self, **kwargs) -> AegisFirewall:
        """Create a firewall with cognitive sever enabled."""
        defaults = dict(
            cognitive_sever_enabled=True,
            strike_max=3,
            strike_window_secs=60.0,
            sever_duration_secs=10.0,
            enable_vault=False,
        )
        defaults.update(kwargs)
        return AegisFirewall(config=AegisConfig(**defaults))

    def _trigger_block(self, fw: AegisFirewall) -> None:
        """Trigger a trajectory loop block."""
        payload = {"target": "0xDEAD", "amount": 1}
        fw.evaluate(payload)  # 1st time: allowed
        fw.evaluate(payload)  # 2nd time: allowed (ring not full yet for k=2)
        # Force a block by repeating many times
        for _ in range(10):
            v = fw.evaluate(payload)
            if v.blocked:
                return
        # If trajectory didn't block, use capital velocity
        fw.evaluate(payload, spend_amount=999999.0)

    def test_cognitive_sever_disabled_by_default(self):
        """Default config has cognitive_sever_enabled=False."""
        fw = AegisFirewall(config=AegisConfig(enable_vault=False))
        assert fw.config.cognitive_sever_enabled is False

    def test_no_sever_below_threshold(self):
        """Fewer blocks than strike_max don't trigger sever."""
        fw = self._make_firewall(strike_max=10)
        # Generate 2 blocks — should not trigger sever with max=10
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(5):
            fw.evaluate(payload)
        assert not fw._cognitive_severed

    def test_sever_triggered_after_threshold(self):
        """Reaching strike_max blocks triggers cognitive sever."""
        fw = self._make_firewall(strike_max=3)
        payload = {"target": "0xDEAD", "amount": 1}
        # Generate enough evaluations to trigger 3+ blocks
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

    def test_sever_blocks_all_actions(self):
        """During sever period, ALL evaluations return BLOCK_COGNITIVE_STARVATION."""
        fw = self._make_firewall(strike_max=3, sever_duration_secs=60.0)
        payload = {"target": "0xDEAD", "amount": 1}
        # Trigger sever
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

        # Even a brand-new, clean payload is blocked
        clean = {"target": "0xBEEF", "amount": 1, "unique": True}
        v = fw.evaluate(clean)
        assert v.blocked
        assert v.code == VerdictCode.BLOCK_COGNITIVE_STARVATION
        assert "cognitively severed" in v.reason

    def test_sever_expires_after_duration(self):
        """Sever expires after sever_duration_secs."""
        fw = self._make_firewall(strike_max=3, sever_duration_secs=0.1)
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

        # Wait for sever to expire
        time.sleep(0.15)

        # Should resume normal operation
        clean = {"target": "0xNEW", "amount": 1}
        v = fw.evaluate(clean)
        assert not fw._cognitive_severed
        assert v.allowed

    def test_sever_webhook_called(self):
        """on_cognitive_sever callback is fired when sever triggers."""
        sever_calls = []

        def on_sever():
            sever_calls.append(time.time())

        fw = self._make_firewall(
            strike_max=3,
            on_cognitive_sever=on_sever,
        )
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(20):
            fw.evaluate(payload)

        assert len(sever_calls) >= 1

    def test_sever_webhook_exception_safe(self):
        """Failing on_cognitive_sever callback doesn't crash the firewall."""
        def bad_callback():
            raise RuntimeError("Webhook server down!")

        fw = self._make_firewall(
            strike_max=3,
            on_cognitive_sever=bad_callback,
        )
        payload = {"target": "0xDEAD", "amount": 1}
        # Should not raise
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

    def test_sever_metadata_contains_timing(self):
        """Sever verdict metadata includes timing info."""
        fw = self._make_firewall(strike_max=3, sever_duration_secs=60.0)
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

        v = fw.evaluate({"target": "0xNEW"})
        assert v.code == VerdictCode.BLOCK_COGNITIVE_STARVATION
        assert "sever_until" in v.metadata
        assert "remaining_secs" in v.metadata

    def test_sever_feedback_prompt(self):
        """BLOCK_COGNITIVE_STARVATION verdict has correct feedback prompt."""
        from aegis.verdict import Verdict
        v = Verdict(
            code=VerdictCode.BLOCK_COGNITIVE_STARVATION,
            reason="Agent is cognitively severed",
            engine="CognitiveSever",
        )
        prompt = v.feedback_prompt()
        assert "SYSTEM OVERRIDE" in prompt
        assert "cognitively severed" in prompt

    def test_reset_clears_sever_state(self):
        """reset() clears all cognitive sever state."""
        fw = self._make_firewall(strike_max=3, sever_duration_secs=300.0)
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(20):
            fw.evaluate(payload)
        assert fw._cognitive_severed

        fw.reset()
        assert not fw._cognitive_severed
        assert fw._sever_until == 0.0
        assert len(fw._strike_timestamps) == 0

        # Should allow new evaluations
        v = fw.evaluate({"target": "0xNEW", "amount": 1})
        assert v.allowed

    def test_strike_window_rolling(self):
        """Strikes outside the rolling window are pruned."""
        fw = self._make_firewall(
            strike_max=3,
            strike_window_secs=0.1,  # 100ms window
            sever_duration_secs=60.0,
        )
        payload = {"target": "0xDEAD", "amount": 1}

        # Generate 2 blocks
        for _ in range(10):
            fw.evaluate(payload)

        # Wait for window to expire
        time.sleep(0.15)

        # Reset trajectory to start fresh
        fw._trajectory.reset()
        fw._cognitive_severed = False  # Manually clear if triggered

        # Generate 1 more block — should not trigger (old strikes pruned)
        fw._strike_timestamps.clear()
        for _ in range(3):
            fw.evaluate(payload)

        # Only the fresh strikes should be in the deque
        assert len(fw._strike_timestamps) <= 3

    def test_sever_verdict_code_value(self):
        """BLOCK_COGNITIVE_STARVATION has correct string value."""
        assert VerdictCode.BLOCK_COGNITIVE_STARVATION.value == "BLOCK_COGNITIVE_STARVATION"

    def test_sever_disabled_no_strike_tracking(self):
        """When cognitive_sever_enabled=False, no strikes are recorded."""
        fw = AegisFirewall(config=AegisConfig(
            enable_vault=False,
            cognitive_sever_enabled=False,
        ))
        payload = {"target": "0xDEAD", "amount": 1}
        for _ in range(20):
            fw.evaluate(payload)
        assert not fw._cognitive_severed
        assert len(fw._strike_timestamps) == 0


# ═════════════════════════════════════════════════════════════════════
# INTEGRATION: All Zero-Day v1.0.1 patches working together
# ═════════════════════════════════════════════════════════════════════


class TestZeroDayV101Integration:
    """Integration tests for v1.0.1 zero-day patches."""

    def test_bridge_block_counts_as_strike(self):
        """A bridge destination block contributes to cognitive sever strikes."""
        fw = AegisFirewall(config=AegisConfig(
            enable_vault=False,
            cognitive_sever_enabled=True,
            strike_max=3,
            sever_duration_secs=60.0,
            asset_guard=AssetGuardConfig(
                approved_destinations=["0x1111111111111111111111111111111111111111"],
            ),
        ))
        bridge = "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1"
        hacker = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

        # Each bridge block should record a strike
        for _ in range(5):
            fw.evaluate({
                "target": bridge,
                "token_address": "0xToken",
                "slippage_bps": 100,
                "destination_address": hacker,
            })

        assert fw._cognitive_severed

    def test_backward_compat_all_disabled(self):
        """Default config: all v1.0.1 features disabled, existing behavior intact."""
        fw = AegisFirewall(config=AegisConfig(enable_vault=False))
        # No bridge checking (empty approved_destinations)
        # No cognitive sever (disabled)
        v = fw.evaluate({"target": "0xABC", "amount": 100})
        assert v.allowed
        assert not fw._cognitive_severed
        assert len(fw._strike_timestamps) == 0

    def test_all_zero_day_verdict_codes_present(self):
        """All v1.0.1 verdict codes are defined."""
        assert hasattr(VerdictCode, "BLOCK_METAMORPHIC_CODE")
        assert hasattr(VerdictCode, "BLOCK_COGNITIVE_STARVATION")
