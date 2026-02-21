"""
Tests for v1.0.4 Kill-Shot ERC-4337 Security Patches.

Kill-Shot 1: tx.origin Bundler Illusion — Environment Reality Pinning
Kill-Shot 2: PVG Heist — Absolute PVG Ceilings
Kill-Shot 3: Cross-Chain Refund Hijacking — Bridge Parameter Validation
Kill-Shot 4: Permit2 Time-Bomb — Signature Temporal Bounds

Total: ~40 tests
"""

from __future__ import annotations

import time
import unittest

from plimsoll.verdict import VerdictCode
from plimsoll.firewall import PlimsollConfig, PlimsollFirewall
from plimsoll.enclave.vault import (
    KeyVault,
    PlimsollEnforcementError,
    _compute_tvar,
    _TEMPORAL_BOUND_FIELDS,
    _UINT256_MAX,
)


# ─────────────────────────────────────────────────────────────────────
# Phase 0: V8 VerdictCode Existence Tests
# ─────────────────────────────────────────────────────────────────────


class TestVerdictCodesV104(unittest.TestCase):
    """All v1.0.4 VerdictCodes must exist and be unique."""

    def test_block_bundler_origin_mismatch_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_BUNDLER_ORIGIN_MISMATCH.value,
            "BLOCK_BUNDLER_ORIGIN_MISMATCH",
        )

    def test_block_pvg_ceiling_exceeded_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_PVG_CEILING_EXCEEDED.value,
            "BLOCK_PVG_CEILING_EXCEEDED",
        )

    def test_block_pvg_tvar_anomaly_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_PVG_TVAR_ANOMALY.value,
            "BLOCK_PVG_TVAR_ANOMALY",
        )

    def test_block_bridge_refund_hijack_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_BRIDGE_REFUND_HIJACK.value,
            "BLOCK_BRIDGE_REFUND_HIJACK",
        )

    def test_block_bridge_recipient_mismatch_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_BRIDGE_RECIPIENT_MISMATCH.value,
            "BLOCK_BRIDGE_RECIPIENT_MISMATCH",
        )

    def test_block_permit_expiry_too_long_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_PERMIT_EXPIRY_TOO_LONG.value,
            "BLOCK_PERMIT_EXPIRY_TOO_LONG",
        )

    def test_block_permit_immortal_signature_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_PERMIT_IMMORTAL_SIGNATURE.value,
            "BLOCK_PERMIT_IMMORTAL_SIGNATURE",
        )

    def test_all_v104_codes_unique(self) -> None:
        v104_codes = [
            VerdictCode.BLOCK_BUNDLER_ORIGIN_MISMATCH,
            VerdictCode.BLOCK_PVG_CEILING_EXCEEDED,
            VerdictCode.BLOCK_PVG_TVAR_ANOMALY,
            VerdictCode.BLOCK_BRIDGE_REFUND_HIJACK,
            VerdictCode.BLOCK_BRIDGE_RECIPIENT_MISMATCH,
            VerdictCode.BLOCK_PERMIT_EXPIRY_TOO_LONG,
            VerdictCode.BLOCK_PERMIT_IMMORTAL_SIGNATURE,
        ]
        values = [c.value for c in v104_codes]
        self.assertEqual(len(values), len(set(values)))

    def test_v104_codes_coexist_with_all_previous(self) -> None:
        """v1.0.4 codes don't collide with any previous version's codes."""
        all_codes = [c.value for c in VerdictCode]
        self.assertEqual(len(all_codes), len(set(all_codes)))


# ─────────────────────────────────────────────────────────────────────
# Kill-Shot 1: tx.origin Bundler Illusion Tests
# ─────────────────────────────────────────────────────────────────────


class TestBundlerIllusionConfig(unittest.TestCase):
    """Kill-Shot 1: Bundler address configuration tests."""

    def test_bundler_address_not_in_python_config(self) -> None:
        """bundler_address is Rust-only — no Python PlimsollConfig field needed."""
        config = PlimsollConfig()
        self.assertFalse(hasattr(config, "bundler_address"))

    def test_firewall_works_without_bundler_config(self) -> None:
        """Firewall operates normally without any bundler configuration."""
        fw = PlimsollFirewall()
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)


# ─────────────────────────────────────────────────────────────────────
# Kill-Shot 2: PVG Heist — TVAR with PVG Tests
# ─────────────────────────────────────────────────────────────────────


class TestPVGInTVAR(unittest.TestCase):
    """Kill-Shot 2: preVerificationGas must be included in TVAR."""

    def test_tvar_without_pvg(self) -> None:
        """TVAR without PVG field is unchanged (backward compat)."""
        tx = {
            "value": 1_000_000_000_000_000_000,  # 1 ETH
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
        }
        tvar = _compute_tvar(tx)
        expected = 1_000_000_000_000_000_000 + 21_000 * 20_000_000_000
        self.assertEqual(tvar, float(expected))

    def test_tvar_includes_pvg(self) -> None:
        """PVG cost should be added to TVAR."""
        tx = {
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "preVerificationGas": 100_000,
        }
        tvar = _compute_tvar(tx)
        gas_cost = 21_000 * 20_000_000_000
        pvg_cost = 100_000 * 20_000_000_000
        expected = gas_cost + pvg_cost
        self.assertEqual(tvar, float(expected))

    def test_tvar_pvg_heist_attack_30k(self) -> None:
        """Attacker sets PVG=15M + maxFeePerGas=2000gwei → massive TVAR."""
        tx = {
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 2_000_000_000_000,  # 2000 gwei
            "preVerificationGas": 15_000_000,    # 15M PVG
        }
        tvar = _compute_tvar(tx)
        gas_cost = 21_000 * 2_000_000_000_000
        pvg_cost = 15_000_000 * 2_000_000_000_000
        expected = gas_cost + pvg_cost
        self.assertEqual(tvar, float(expected))
        # PVG alone: 15M * 2000 gwei = 30e18 wei = 30 ETH
        # Total TVAR is ~30.042 ETH — attacker drains Paymaster
        self.assertGreater(tvar, 30_000_000_000_000_000_000)  # > 30 ETH in wei

    def test_tvar_pvg_zero_is_noop(self) -> None:
        """PVG=0 should not change TVAR."""
        tx = {
            "value": 1_000_000,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "preVerificationGas": 0,
        }
        tvar_with = _compute_tvar(tx)
        del tx["preVerificationGas"]
        tvar_without = _compute_tvar(tx)
        self.assertEqual(tvar_with, tvar_without)

    def test_tvar_pvg_with_l2_chain(self) -> None:
        """PVG + L1 data fee should both be included on L2 chains."""
        tx = {
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "preVerificationGas": 50_000,
            "data": "0x" + "ff" * 100,
        }
        tvar = _compute_tvar(tx, chain_id=10)  # Optimism
        gas_cost = 21_000 * 20_000_000_000
        pvg_cost = 50_000 * 20_000_000_000
        l1_fee = 100 * 16 * 30_000_000_000
        expected = gas_cost + pvg_cost + l1_fee
        self.assertEqual(tvar, float(expected))


class TestPVGFirewallConfig(unittest.TestCase):
    """Kill-Shot 2: PVG configuration in Python PlimsollConfig."""

    def test_max_pvg_default_zero(self) -> None:
        """max_pre_verification_gas defaults to 0 (disabled)."""
        config = PlimsollConfig()
        self.assertEqual(config.max_pre_verification_gas, 0)

    def test_max_pvg_can_be_set(self) -> None:
        """max_pre_verification_gas can be configured."""
        config = PlimsollConfig(max_pre_verification_gas=500_000)
        self.assertEqual(config.max_pre_verification_gas, 500_000)


# ─────────────────────────────────────────────────────────────────────
# Kill-Shot 3: Bridge Refund Hijacking Tests
# ─────────────────────────────────────────────────────────────────────


class TestBridgeRefundHijack(unittest.TestCase):
    """Kill-Shot 3: Bridge parameter validation tests.

    Note: Bridge validation happens in the Rust RPC proxy, so Python-side
    tests focus on config defaults and VerdictCode existence.
    """

    def test_bridge_config_not_in_python(self) -> None:
        """Bridge refund check is Rust-only — no Python config needed."""
        config = PlimsollConfig()
        self.assertFalse(hasattr(config, "bridge_refund_check"))

    def test_arbitrum_selector_constant(self) -> None:
        """Arbitrum createRetryableTicket selector is well-known."""
        # 0x679b6ded — keccak256 of the function signature
        selector = bytes.fromhex("679b6ded")
        self.assertEqual(len(selector), 4)
        self.assertEqual(selector[0], 0x67)
        self.assertEqual(selector[1], 0x9b)

    def test_optimism_selector_constant(self) -> None:
        """Optimism depositTransaction selector is well-known."""
        # 0xe9e05c42 — keccak256 of the function signature
        selector = bytes.fromhex("e9e05c42")
        self.assertEqual(len(selector), 4)
        self.assertEqual(selector[0], 0xE9)
        self.assertEqual(selector[1], 0xE0)

    def test_arbitrum_calldata_layout(self) -> None:
        """Verify ABI layout of createRetryableTicket calldata.

        Arg layout (each word = 32 bytes):
          Word 0: to (address)
          Word 1: l2CallValue (uint256)
          Word 2: maxSubmissionCost (uint256)
          Word 3: excessFeeRefundAddress (address) ← must match sender
          Word 4: callValueRefundAddress (address) ← must match sender
        """
        sender = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
        # Build minimal calldata: selector + 5 words
        selector = bytes.fromhex("679b6ded")
        word0 = bytes(12) + bytes.fromhex(sender[2:])  # to
        word1 = (0).to_bytes(32, "big")                 # l2CallValue
        word2 = (0).to_bytes(32, "big")                 # maxSubmissionCost
        word3 = bytes(12) + bytes.fromhex(sender[2:])   # excessFeeRefundAddress
        word4 = bytes(12) + bytes.fromhex(sender[2:])   # callValueRefundAddress
        calldata = selector + word0 + word1 + word2 + word3 + word4
        # excessFeeRefundAddress is at bytes [112..132]
        # (4 selector + 3*32 words + 12 padding = 112; + 20 address = 132)
        excess = calldata[112:132]
        self.assertEqual(excess.hex().lower(), sender[2:].lower())
        # callValueRefundAddress is at bytes [144..164]
        # (4 selector + 4*32 words + 12 padding = 144; + 20 address = 164)
        value_refund = calldata[144:164]
        self.assertEqual(value_refund.hex().lower(), sender[2:].lower())

    def test_bridge_refund_hijack_calldata(self) -> None:
        """Attacker sets excessFeeRefundAddress to their address."""
        sender = "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
        attacker = "0xBAD0000000000000000000000000000000000BAD"
        selector = bytes.fromhex("679b6ded")
        word0 = bytes(12) + bytes.fromhex(sender[2:])    # to
        word1 = (0).to_bytes(32, "big")
        word2 = (0).to_bytes(32, "big")
        word3 = bytes(12) + bytes.fromhex(attacker[2:])   # HIJACKED refund
        word4 = bytes(12) + bytes.fromhex(sender[2:])
        calldata = selector + word0 + word1 + word2 + word3 + word4
        # The excess refund address should NOT match sender
        excess = "0x" + calldata[108:128].hex()
        self.assertNotEqual(excess.lower(), sender.lower())


# ─────────────────────────────────────────────────────────────────────
# Kill-Shot 4: Permit2 Time-Bomb — Temporal Bounds Tests
# ─────────────────────────────────────────────────────────────────────


class TestTemporalBoundConstants(unittest.TestCase):
    """Kill-Shot 4: Temporal field constants and sentinel values."""

    def test_temporal_bound_fields_complete(self) -> None:
        """All known temporal fields are present."""
        self.assertIn("deadline", _TEMPORAL_BOUND_FIELDS)
        self.assertIn("expiration", _TEMPORAL_BOUND_FIELDS)
        self.assertIn("sigDeadline", _TEMPORAL_BOUND_FIELDS)
        self.assertIn("expiry", _TEMPORAL_BOUND_FIELDS)
        self.assertIn("validBefore", _TEMPORAL_BOUND_FIELDS)
        self.assertIn("validAfter", _TEMPORAL_BOUND_FIELDS)

    def test_temporal_bound_fields_frozen(self) -> None:
        """Temporal fields set is frozen (immutable)."""
        self.assertIsInstance(_TEMPORAL_BOUND_FIELDS, frozenset)

    def test_uint256_max_correct(self) -> None:
        """_UINT256_MAX is 2^256 - 1."""
        expected = 2**256 - 1
        self.assertEqual(_UINT256_MAX, expected)

    def test_uint256_max_is_115792(self) -> None:
        """Verify the decimal representation matches Solidity's type(uint256).max."""
        s = str(_UINT256_MAX)
        self.assertTrue(s.startswith("115792089237316195423570985008687907853"))


class TestPermitTemporalBoundsValidation(unittest.TestCase):
    """Kill-Shot 4: _validate_permit_temporal_bounds() in KeyVault."""

    def _make_vault_with_firewall(self, max_permit_secs: int = 3600) -> KeyVault:
        """Create a KeyVault with firewall enforcing temporal bounds."""
        config = PlimsollConfig(max_permit_duration_secs=max_permit_secs)
        fw = PlimsollFirewall(config=config)
        vault = KeyVault()
        vault.bind_firewall(fw)
        return vault

    def test_immortal_deadline_rejected(self) -> None:
        """uint256.max deadline → BLOCK_PERMIT_IMMORTAL_SIGNATURE."""
        vault = self._make_vault_with_firewall(3600)
        with self.assertRaises(PlimsollEnforcementError) as ctx:
            vault._validate_permit_temporal_bounds(
                {"deadline": _UINT256_MAX}, 3600,
            )
        self.assertIn("IMMORTAL", ctx.exception.reason)

    def test_immortal_expiration_rejected(self) -> None:
        """uint256.max expiration field also caught."""
        vault = self._make_vault_with_firewall(3600)
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"expiration": _UINT256_MAX}, 3600,
            )

    def test_immortal_hex_string_rejected(self) -> None:
        """uint256.max as hex string is also caught."""
        vault = self._make_vault_with_firewall(3600)
        max_hex = "0x" + "ff" * 32
        with self.assertRaises(PlimsollEnforcementError) as ctx:
            vault._validate_permit_temporal_bounds(
                {"deadline": max_hex}, 3600,
            )
        self.assertIn("IMMORTAL", ctx.exception.reason)

    def test_excessive_deadline_rejected(self) -> None:
        """Deadline 7 days from now exceeds 1-hour max → rejected."""
        vault = self._make_vault_with_firewall(3600)
        future_7d = int(time.time()) + 7 * 86400
        with self.assertRaises(PlimsollEnforcementError) as ctx:
            vault._validate_permit_temporal_bounds(
                {"deadline": future_7d}, 3600,
            )
        self.assertIn("PERMIT2 TIME-BOMB", ctx.exception.reason)

    def test_reasonable_deadline_allowed(self) -> None:
        """Deadline 30 minutes from now within 1-hour max → allowed."""
        vault = self._make_vault_with_firewall(3600)
        future_30m = int(time.time()) + 1800
        # Should NOT raise
        vault._validate_permit_temporal_bounds(
            {"deadline": future_30m}, 3600,
        )

    def test_no_temporal_fields_allowed(self) -> None:
        """Message with no temporal fields passes validation."""
        vault = self._make_vault_with_firewall(3600)
        vault._validate_permit_temporal_bounds(
            {"spender": "0x123", "value": "1000"}, 3600,
        )

    def test_multiple_temporal_fields_all_checked(self) -> None:
        """If message has both deadline and sigDeadline, both are checked."""
        vault = self._make_vault_with_firewall(3600)
        ok_time = int(time.time()) + 1800
        bad_time = int(time.time()) + 7 * 86400
        # First field OK, second exceeds
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"deadline": ok_time, "sigDeadline": bad_time}, 3600,
            )

    def test_sig_deadline_field_caught(self) -> None:
        """sigDeadline (Permit2-specific) is detected."""
        vault = self._make_vault_with_firewall(3600)
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"sigDeadline": _UINT256_MAX}, 3600,
            )

    def test_expiry_field_caught(self) -> None:
        """DAI-style 'expiry' field is detected."""
        vault = self._make_vault_with_firewall(3600)
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"expiry": _UINT256_MAX}, 3600,
            )

    def test_valid_before_field_caught(self) -> None:
        """ERC-3009 'validBefore' field is detected."""
        vault = self._make_vault_with_firewall(3600)
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"validBefore": _UINT256_MAX}, 3600,
            )

    def test_disabled_at_sign_typed_data_level(self) -> None:
        """When max_permit_duration_secs=0, sign_typed_data skips validation.

        The gating happens in sign_typed_data() before calling
        _validate_permit_temporal_bounds(). The method itself always
        checks immortal signatures when called directly.
        """
        config = PlimsollConfig(max_permit_duration_secs=0)
        fw = PlimsollFirewall(config=config)
        vault = KeyVault()
        vault.bind_firewall(fw)
        # Direct call with max_duration > 0 still catches immortal
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"deadline": _UINT256_MAX}, 1,
            )
        # Immortal detection is always active even with 0 (safety net)
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"deadline": _UINT256_MAX}, 0,
            )

    def test_string_decimal_temporal_value(self) -> None:
        """Temporal values as decimal strings are parsed correctly."""
        vault = self._make_vault_with_firewall(3600)
        future_str = str(int(time.time()) + 1800)
        # Should NOT raise
        vault._validate_permit_temporal_bounds(
            {"deadline": future_str}, 3600,
        )

    def test_string_hex_temporal_value(self) -> None:
        """Temporal values as hex strings are parsed correctly."""
        vault = self._make_vault_with_firewall(3600)
        future_hex = hex(int(time.time()) + 1800)
        # Should NOT raise
        vault._validate_permit_temporal_bounds(
            {"deadline": future_hex}, 3600,
        )

    def test_invalid_temporal_value_skipped(self) -> None:
        """Non-parseable temporal values are silently skipped."""
        vault = self._make_vault_with_firewall(3600)
        vault._validate_permit_temporal_bounds(
            {"deadline": "not_a_number"}, 3600,
        )

    def test_past_deadline_allowed(self) -> None:
        """A deadline in the past is within the duration limit (negative duration)."""
        vault = self._make_vault_with_firewall(3600)
        past = int(time.time()) - 600
        vault._validate_permit_temporal_bounds(
            {"deadline": past}, 3600,
        )


class TestPermitDurationConfig(unittest.TestCase):
    """Kill-Shot 4: Python config for max_permit_duration_secs."""

    def test_max_permit_duration_default_zero(self) -> None:
        """max_permit_duration_secs defaults to 0 (disabled)."""
        config = PlimsollConfig()
        self.assertEqual(config.max_permit_duration_secs, 0)

    def test_max_permit_duration_can_be_set(self) -> None:
        """max_permit_duration_secs can be configured."""
        config = PlimsollConfig(max_permit_duration_secs=7200)
        self.assertEqual(config.max_permit_duration_secs, 7200)


# ─────────────────────────────────────────────────────────────────────
# Backward Compatibility Tests
# ─────────────────────────────────────────────────────────────────────


class TestBackwardCompatV104(unittest.TestCase):
    """All v1.0.4 features are disabled by default."""

    def test_all_v104_configs_default_disabled(self) -> None:
        """All v1.0.4 Python config fields default to disabled."""
        config = PlimsollConfig()
        self.assertEqual(config.max_pre_verification_gas, 0)
        self.assertEqual(config.max_permit_duration_secs, 0)

    def test_firewall_works_without_v104_config(self) -> None:
        """Firewall evaluates normally with no v1.0.4 config."""
        fw = PlimsollFirewall()
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)

    def test_tvar_backward_compat_no_pvg(self) -> None:
        """_compute_tvar without PVG field returns same as before v1.0.4."""
        tx = {
            "value": 1_000_000,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
        }
        tvar = _compute_tvar(tx)
        expected = 1_000_000 + 21_000 * 20_000_000_000
        self.assertEqual(tvar, float(expected))

    def test_keyvault_works_without_v104_config(self) -> None:
        """KeyVault() still works without any v1.0.4 config."""
        vault = KeyVault()
        self.assertIsNotNone(vault)
        # Verify vault can store and sign (basic functionality intact)
        vault.store("test_key", "secret")
        self.assertTrue(vault.has_key("test_key"))


# ─────────────────────────────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────────────────────────────


class TestV104Integration(unittest.TestCase):
    """Integration tests combining multiple v1.0.4 features."""

    def test_pvg_and_permit_config_together(self) -> None:
        """PVG ceiling and permit duration can be configured together."""
        config = PlimsollConfig(
            max_pre_verification_gas=500_000,
            max_permit_duration_secs=3600,
        )
        fw = PlimsollFirewall(config=config)
        self.assertEqual(fw.config.max_pre_verification_gas, 500_000)
        self.assertEqual(fw.config.max_permit_duration_secs, 3600)
        # Should still evaluate normally for regular transactions
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)

    def test_pvg_tvar_with_permit_bounds_combined(self) -> None:
        """TVAR with PVG + temporal bounds validation both work."""
        config = PlimsollConfig(
            max_pre_verification_gas=500_000,
            max_permit_duration_secs=3600,
        )
        fw = PlimsollFirewall(config=config)
        vault = KeyVault()
        vault.bind_firewall(fw)

        # TVAR includes PVG
        tx = {
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "preVerificationGas": 100_000,
        }
        tvar = _compute_tvar(tx)
        self.assertGreater(tvar, 0)

        # Temporal bounds still enforced
        with self.assertRaises(PlimsollEnforcementError):
            vault._validate_permit_temporal_bounds(
                {"deadline": _UINT256_MAX}, 3600,
            )

    def test_v104_with_v103_features(self) -> None:
        """v1.0.4 features coexist with v1.0.3 gas anomaly detection."""
        config = PlimsollConfig(
            chain_id=10,  # Optimism
            gas_anomaly_ratio=3.0,
            revert_strike_max=5,
            max_pre_verification_gas=500_000,
            max_permit_duration_secs=3600,
        )
        fw = PlimsollFirewall(config=config)
        self.assertEqual(fw.config.chain_id, 10)
        self.assertEqual(fw.config.max_pre_verification_gas, 500_000)
        self.assertEqual(fw.config.max_permit_duration_secs, 3600)

        # Should still evaluate normally
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)

    def test_reset_preserves_v104_config(self) -> None:
        """reset() clears state but preserves v1.0.4 config."""
        config = PlimsollConfig(
            max_pre_verification_gas=500_000,
            max_permit_duration_secs=3600,
            revert_strike_max=5,
            gas_anomaly_ratio=2.0,
        )
        fw = PlimsollFirewall(config=config)
        fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        fw.reset()
        # Config should be preserved
        self.assertEqual(fw.config.max_pre_verification_gas, 500_000)
        self.assertEqual(fw.config.max_permit_duration_secs, 3600)
        # State should be cleared
        self.assertEqual(len(fw._revert_timestamps), 0)


if __name__ == "__main__":
    unittest.main()
