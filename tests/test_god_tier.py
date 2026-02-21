"""Tests for God-Tier Security Patches (v1.0.0).

God-Tier 1: EIP-712 Silent Dagger — Permit Decoder + Synthetic State Translation
God-Tier 2: Flashloan Sybil (TWAB) — 72-hour Time-Weighted Average Balance
God-Tier 3: Block Reorg Reality Desync — State-Root Pinning (Solidity tests)
God-Tier 4: Paymaster Parasite — Gas-to-Value Ratio Caps
"""

from __future__ import annotations

import time
import pytest

from plimsoll.enclave.vault import KeyVault, PlimsollEnforcementError
from plimsoll.engines.capital_velocity import (
    CapitalVelocityConfig,
    CapitalVelocityEngine,
)
from plimsoll.engines.threat_feed import ThreatFeedConfig, ThreatFeedEngine
from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.verdict import VerdictCode


# ═══════════════════════════════════════════════════════════════════════
# GOD-TIER 1: EIP-712 Silent Dagger — Permit Decoder Tests
# ═══════════════════════════════════════════════════════════════════════


class TestEIP712SilentDagger:
    """The vault's sign_typed_data() must detect and block dangerous EIP-712 types."""

    def _make_vault_with_firewall(self) -> KeyVault:
        """Create a vault with a firewall bound for testing."""
        vault = KeyVault()
        vault.store("test_key", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        firewall = PlimsollFirewall(config=PlimsollConfig(
            velocity=CapitalVelocityConfig(
                v_max=1000.0,
                max_single_amount=float("inf"),
            ),
        ))
        vault.bind_firewall(firewall)
        return vault

    def test_safe_typed_data_passes(self):
        """Non-dangerous EIP-712 types are signed without issue."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        typed_data = {
            "primaryType": "Mail",
            "domain": {"name": "Test"},
            "message": {"from": "Alice", "to": "Bob", "content": "Hello"},
        }
        sig = vault.sign_typed_data("test_key", typed_data)
        assert sig  # Got a valid signature

    def test_permit_detected_and_blocked_max_uint(self):
        """Permit with MAX_UINT value is categorically blocked."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "Permit",
            "domain": {"name": "USDC", "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
            "message": {
                "owner": "0xVictim",
                "spender": "0xHacker",
                "value": max_uint,
                "nonce": 0,
                "deadline": 99999999999,
            },
        }
        with pytest.raises(PlimsollEnforcementError) as exc_info:
            vault.sign_typed_data("test_key", typed_data)
        assert "MAX_UINT" in str(exc_info.value)
        assert "Silent Dagger" in str(exc_info.value) or "GOD-TIER 1" in str(exc_info.value)

    def test_permit_max_uint_hex_blocked(self):
        """MAX_UINT as hex is also blocked."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        typed_data = {
            "primaryType": "Permit",
            "domain": {"verifyingContract": "0xToken"},
            "message": {
                "spender": "0xHacker",
                "value": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            },
        }
        with pytest.raises(PlimsollEnforcementError) as exc_info:
            vault.sign_typed_data("test_key", typed_data)
        assert "MAX_UINT" in str(exc_info.value)

    def test_permit_single_detected(self):
        """PermitSingle (Permit2) is detected as dangerous."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "PermitSingle",
            "domain": {"verifyingContract": "0xPermit2"},
            "message": {
                "spender": "0xDrainer",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", typed_data)

    def test_permit_batch_detected(self):
        """PermitBatch is detected as dangerous."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "PermitBatch",
            "domain": {"verifyingContract": "0xPermit2"},
            "message": {
                "spender": "0xDrainer",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", typed_data)

    def test_permit_transfer_from_detected(self):
        """PermitTransferFrom (UniswapX) is detected as dangerous."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "PermitTransferFrom",
            "domain": {"verifyingContract": "0xPermit2"},
            "message": {
                "spender": "0xDrainer",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", typed_data)

    def test_order_components_detected(self):
        """OrderComponents (Seaport) is detected as dangerous."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "OrderComponents",
            "domain": {"verifyingContract": "0xSeaport"},
            "message": {
                "taker": "0xDrainer",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", typed_data)

    def test_meta_transaction_detected(self):
        """MetaTransaction is detected as dangerous."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "MetaTransaction",
            "domain": {"verifyingContract": "0xTarget"},
            "message": {
                "spender": "0xDrainer",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", typed_data)

    def test_permit_with_firewall_evaluates_synthetic(self):
        """When firewall is bound, Permit with finite amount runs through firewall."""
        vault = self._make_vault_with_firewall()
        # Use a finite amount that the firewall allows
        typed_data = {
            "primaryType": "Permit",
            "domain": {"verifyingContract": "0xToken"},
            "message": {
                "spender": "0xSpender",
                "value": "100",
            },
        }
        # Should pass — amount is small
        sig = vault.sign_typed_data("test_key", typed_data)
        assert sig

    def test_dangerous_primary_types_coverage(self):
        """All 10 dangerous primary types are recognized."""
        dangerous_types = {
            "Permit", "PermitSingle", "PermitBatch",
            "PermitTransferFrom", "PermitWitnessTransferFrom",
            "Order", "OrderComponents",
            "MetaTransaction", "ForwardRequest", "Delegation",
        }
        assert dangerous_types == KeyVault._DANGEROUS_PRIMARY_TYPES

    def test_unknown_primary_type_not_blocked(self):
        """Unknown primary types pass through without analysis."""
        vault = KeyVault()
        vault.store("test_key", "deadbeef" * 8)
        typed_data = {
            "primaryType": "CustomStruct",
            "domain": {"name": "MyDApp"},
            "message": {"foo": "bar"},
        }
        sig = vault.sign_typed_data("test_key", typed_data)
        assert sig

    def test_permit_without_firewall_still_blocks_max_uint(self):
        """Even without a firewall, MAX_UINT approvals are blocked."""
        vault = KeyVault()  # No firewall bound
        vault.store("test_key", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        typed_data = {
            "primaryType": "Permit",
            "domain": {"verifyingContract": "0xToken"},
            "message": {
                "spender": "0xHacker",
                "value": max_uint,
            },
        }
        with pytest.raises(PlimsollEnforcementError) as exc_info:
            vault.sign_typed_data("test_key", typed_data)
        assert "PermitDecoder" in str(exc_info.value)

    def test_enforcement_error_attributes(self):
        """PlimsollEnforcementError has correct attributes."""
        err = PlimsollEnforcementError(
            reason="test reason",
            engine="PermitDecoder",
            code="BLOCK_EIP712_PERMIT",
        )
        assert err.reason == "test reason"
        assert err.engine == "PermitDecoder"
        assert err.code == "BLOCK_EIP712_PERMIT"
        assert "PLIMSOLL VAULT ENFORCEMENT" in str(err)


# ═══════════════════════════════════════════════════════════════════════
# GOD-TIER 2: Flashloan Sybil — TWAB (Time-Weighted Average Balance)
# ═══════════════════════════════════════════════════════════════════════


class TestFlashloanSybilTWAB:
    """ThreatFeedEngine.validate_ioc_with_twab() blocks flash-loan governance."""

    def test_twab_window_constant(self):
        """TWAB window is 20,000 blocks (~72 hours)."""
        engine = ThreatFeedEngine()
        assert engine.TWAB_WINDOW_BLOCKS == 20_000

    def test_vault_too_young_rejected(self):
        """Vault younger than 20,000 blocks cannot submit IOCs."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=50_000.0,
            vault_age_blocks=1_000,  # Way too young
        )
        assert not accepted
        assert "GOD-TIER 2" in reason
        assert "vault age" in reason

    def test_vault_exactly_at_window_accepted(self):
        """Vault exactly 20,000 blocks old with sufficient TWAB passes."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=10_000.0,
            vault_age_blocks=20_000,
        )
        assert accepted
        assert "TWAB validation" in reason

    def test_vault_old_but_low_twab_rejected(self):
        """Old vault with TWAB below $5K minimum is rejected."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=1_000.0,  # Below $5K
            vault_age_blocks=50_000,
        )
        assert not accepted
        assert "GOD-TIER 2" in reason
        assert "TWAB" in reason

    def test_flashloan_attack_math(self):
        """Flash loan attack produces negligible TWAB.

        Attack: $50M flash loan split into 10,000 vaults.
        Each vault: $5K for 1 block.
        TWAB per vault: $5K / 20,000 blocks = $0.25
        Result: $0.25 TWAB → rejected (< $5K minimum).
        """
        engine = ThreatFeedEngine()
        flashloan_twab = 5_000.0 / 20_000  # $0.25
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=flashloan_twab,
            vault_age_blocks=1,  # Flash loan exists for 1 block
        )
        assert not accepted

    def test_legitimate_vault_accepted(self):
        """Legitimate vault with 72+ hours and sufficient TWAB passes."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=25_000.0,
            vault_age_blocks=30_000,  # ~108 hours
        )
        assert accepted
        assert "stake weight" in reason

    def test_vault_one_block_below_window_rejected(self):
        """Vault at 19,999 blocks (just below 20,000) is rejected."""
        engine = ThreatFeedEngine()
        accepted, _ = engine.validate_ioc_with_twab(
            twab_usd=100_000.0,
            vault_age_blocks=19_999,
        )
        assert not accepted

    def test_custom_min_tvl_with_twab(self):
        """Custom min_tvl_for_submission applies to TWAB validation."""
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            min_tvl_for_submission=50_000.0,
        ))
        # $10K TWAB below custom $50K threshold
        accepted, _ = engine.validate_ioc_with_twab(
            twab_usd=10_000.0,
            vault_age_blocks=25_000,
        )
        assert not accepted
        # $50K TWAB meets threshold
        accepted, _ = engine.validate_ioc_with_twab(
            twab_usd=50_000.0,
            vault_age_blocks=25_000,
        )
        assert accepted

    def test_twab_stake_weight_in_response(self):
        """Accepted TWAB includes stake weight in reason."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_with_twab(
            twab_usd=50_000.0,
            vault_age_blocks=20_000,
        )
        assert accepted
        assert "0.5000" in reason  # $50K / $100K cap = 0.5

    def test_zero_twab_rejected(self):
        """$0 TWAB is rejected even with old vault."""
        engine = ThreatFeedEngine()
        accepted, _ = engine.validate_ioc_with_twab(
            twab_usd=0.0,
            vault_age_blocks=100_000,
        )
        assert not accepted


# ═══════════════════════════════════════════════════════════════════════
# GOD-TIER 4: Paymaster Parasite — Gas-to-Value Ratio Caps
# ═══════════════════════════════════════════════════════════════════════


class TestPaymasterParasiteGTV:
    """CapitalVelocityEngine.check_gtv() blocks irrational gas spending."""

    def test_gtv_disabled_by_default(self):
        """GTV is disabled by default — no behavioral change."""
        engine = CapitalVelocityEngine()
        result = engine.check_gtv(gas_cost=100.0, value_moved=1.0)
        assert result is None  # Not checked

    def test_gtv_enabled_normal_ratio_passes(self):
        """Normal GTV ratio passes."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        result = engine.check_gtv(gas_cost=5.0, value_moved=100.0)
        assert result is None  # 0.05x < 5.0x → OK

    def test_gtv_per_tx_excessive_blocked(self):
        """Per-tx GTV ratio exceeding threshold is blocked."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        # $15 gas for $1 value = 15x ratio > 5.0x
        result = engine.check_gtv(gas_cost=15.0, value_moved=1.0)
        assert result is not None
        assert result.code == VerdictCode.BLOCK_GAS_VALUE_RATIO
        assert "PAYMASTER PARASITE" in result.reason
        assert "Irrational Economic Sabotage" in result.reason

    def test_gtv_exact_threshold_passes(self):
        """GTV ratio exactly at threshold passes."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        result = engine.check_gtv(gas_cost=5.0, value_moved=1.0)
        assert result is None  # 5.0x == 5.0x → OK (not exceeded)

    def test_gtv_zero_value_blocked(self):
        """Zero value with any gas cost is blocked (infinite ratio)."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        result = engine.check_gtv(gas_cost=1.0, value_moved=0.0)
        assert result is not None
        assert result.code == VerdictCode.BLOCK_GAS_VALUE_RATIO

    def test_gtv_cumulative_drain_blocked(self):
        """Cumulative GTV over window catches systematic drain."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=100.0,  # Per-tx is generous
            gtv_cumulative_max=3.0,  # But cumulative is tight
        ))
        # 10 transactions: $2 gas for $1 value each = 2x per-tx (OK)
        # But cumulative: $20 gas / $10 value = 2.0x (OK)
        for _ in range(10):
            result = engine.check_gtv(gas_cost=2.0, value_moved=1.0)
            assert result is None

        # Now one more at 4x pushes cumulative to $24/$11 = 2.18x (still OK)
        # Let's push it over: high gas, low value
        result = engine.check_gtv(gas_cost=20.0, value_moved=1.0)
        # Cumulative: ($20+$20) / ($10+$1) = $40/$11 = 3.6x > 3.0x
        assert result is not None
        assert result.code == VerdictCode.BLOCK_GAS_VALUE_RATIO
        assert "Cumulative" in result.reason
        assert "Systematic gas drain" in result.reason.lower() or "gas drain" in result.reason

    def test_gtv_reset_clears_state(self):
        """Reset clears GTV tracking state."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        # Record some transactions
        engine.check_gtv(gas_cost=1.0, value_moved=10.0)
        engine.check_gtv(gas_cost=1.0, value_moved=10.0)
        engine.reset()
        # After reset, cumulative should be clean
        assert engine._gtv_total_gas == 0.0
        assert engine._gtv_total_value == 0.0
        assert len(engine._gtv_records) == 0

    def test_gtv_metadata_includes_details(self):
        """Blocked verdict includes GTV details in metadata."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        result = engine.check_gtv(gas_cost=50.0, value_moved=1.0)
        assert result is not None
        assert "per_tx_gtv" in result.metadata
        assert result.metadata["per_tx_gtv"] == 50.0
        assert result.metadata["gas_cost"] == 50.0
        assert result.metadata["value_moved"] == 1.0

    def test_gtv_config_defaults(self):
        """GTV config has sensible defaults."""
        config = CapitalVelocityConfig()
        assert config.gtv_enabled is False
        assert config.gtv_max_ratio == 5.0
        assert config.gtv_cumulative_max == 10.0
        assert config.gtv_window_seconds == 300.0

    def test_gtv_per_tx_rollback_not_recorded(self):
        """Per-tx blocked transactions are NOT recorded in cumulative state."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=5.0,
        ))
        # This gets blocked at per-tx level (50x > 5x)
        result = engine.check_gtv(gas_cost=50.0, value_moved=1.0)
        assert result is not None
        # Cumulative state should be empty — blocked tx not recorded
        assert engine._gtv_total_gas == 0.0
        assert engine._gtv_total_value == 0.0

    def test_gtv_cumulative_rollback_on_block(self):
        """Cumulative-blocked transactions are rolled back."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True,
            gtv_max_ratio=100.0,  # Generous per-tx
            gtv_cumulative_max=2.0,
        ))
        # Record: $10 gas / $10 value = 1.0x cumulative (OK)
        engine.check_gtv(gas_cost=10.0, value_moved=10.0)
        assert engine._gtv_total_gas == 10.0
        assert engine._gtv_total_value == 10.0

        # Try: $30 gas / $5 value → cumulative would be $40/$15 = 2.67x > 2.0x
        result = engine.check_gtv(gas_cost=30.0, value_moved=5.0)
        assert result is not None
        # State should be rolled back to before this tx
        assert engine._gtv_total_gas == 10.0
        assert engine._gtv_total_value == 10.0


# ═══════════════════════════════════════════════════════════════════════
# GOD-TIER INTEGRATION: Cross-cutting tests
# ═══════════════════════════════════════════════════════════════════════


class TestGodTierIntegration:
    """Integration tests for all God-Tier patches working together."""

    def test_verdict_codes_exist(self):
        """All God-Tier verdict codes exist."""
        assert VerdictCode.BLOCK_EIP712_PERMIT.value == "BLOCK_EIP712_PERMIT"
        assert VerdictCode.BLOCK_REALITY_DESYNC.value == "BLOCK_REALITY_DESYNC"
        assert VerdictCode.BLOCK_GAS_VALUE_RATIO.value == "BLOCK_GAS_VALUE_RATIO"

    def test_vault_firewall_binding_once(self):
        """Firewall can only be bound once."""
        vault = KeyVault()
        fw = PlimsollFirewall()
        vault.bind_firewall(fw)
        with pytest.raises(RuntimeError, match="already bound"):
            vault.bind_firewall(fw)

    def test_eip712_plus_gtv_defense(self):
        """Both EIP-712 and GTV defenses work independently."""
        # EIP-712 defense
        vault = KeyVault()
        vault.store("k", "deadbeef" * 8)
        max_uint = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("k", {
                "primaryType": "Permit",
                "domain": {"verifyingContract": "0xT"},
                "message": {"spender": "0xH", "value": max_uint},
            })

        # GTV defense
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            gtv_enabled=True, gtv_max_ratio=5.0,
        ))
        result = engine.check_gtv(gas_cost=50.0, value_moved=1.0)
        assert result is not None
        assert result.code == VerdictCode.BLOCK_GAS_VALUE_RATIO

    def test_twab_plus_ioc_validation(self):
        """TWAB supersedes point-in-time TVL for IOC validation."""
        engine = ThreatFeedEngine()
        # Point-in-time: $50K TVL → would pass old validation
        accepted_old, _ = engine.validate_ioc_submission(50_000.0)
        assert accepted_old

        # TWAB: same $50K but vault only 100 blocks old → rejected
        accepted_twab, reason = engine.validate_ioc_with_twab(
            twab_usd=50_000.0,
            vault_age_blocks=100,
        )
        assert not accepted_twab
        assert "GOD-TIER 2" in reason

    def test_backward_compatibility_defaults(self):
        """All God-Tier features are disabled by default — zero behavioral change."""
        # GTV disabled by default
        config = CapitalVelocityConfig()
        assert config.gtv_enabled is False

        # Engine with defaults still works normally
        engine = CapitalVelocityEngine()
        verdict = engine.evaluate(10.0)
        assert verdict.allowed

        # Vault without firewall signs typed data for non-dangerous types
        vault = KeyVault()
        vault.store("k", "deadbeef" * 8)
        sig = vault.sign_typed_data("k", {
            "primaryType": "SafeType",
            "message": {"data": "test"},
        })
        assert sig

    def test_capital_velocity_evaluate_unchanged(self):
        """The main evaluate() method is unaffected by GTV additions."""
        engine = CapitalVelocityEngine(config=CapitalVelocityConfig(
            v_max=100.0,
            gtv_enabled=True,  # Even when GTV is on
        ))
        # evaluate() doesn't check GTV — it's a separate method
        verdict = engine.evaluate(10.0)
        assert verdict.allowed

    def test_threat_feed_twab_and_old_api_coexist(self):
        """Both old validate_ioc_submission() and new validate_ioc_with_twab() coexist."""
        engine = ThreatFeedEngine()
        # Old API still works
        accepted, _ = engine.validate_ioc_submission(10_000.0)
        assert accepted
        # New API also works
        accepted, _ = engine.validate_ioc_with_twab(10_000.0, 25_000)
        assert accepted
