"""
Tests for v1.0.3 Security Bounty Patches.

Bounty 1: JSON Parameter Pollution — Canonical re-serialization
Bounty 2: EIP-1967 Proxy Illusion — Implementation slot probing
Bounty 3: L1 Blob-Fee Asymmetry — L1 data fee accounting
Bounty 4: 63/64ths Gas Black Hole — Gas anomaly detection

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
    _compute_l1_data_fee,
    L2_CHAIN_IDS,
)


# ─────────────────────────────────────────────────────────────────────
# Verdict Code Existence Tests
# ─────────────────────────────────────────────────────────────────────


class TestVerdictCodesV103(unittest.TestCase):
    """All v1.0.3 VerdictCodes must exist and be unique."""

    def test_block_json_pollution_exists(self) -> None:
        self.assertEqual(VerdictCode.BLOCK_JSON_POLLUTION.value, "BLOCK_JSON_POLLUTION")

    def test_block_proxy_upgrade_exists(self) -> None:
        self.assertEqual(VerdictCode.BLOCK_PROXY_UPGRADE.value, "BLOCK_PROXY_UPGRADE")

    def test_block_l1_data_fee_anomaly_exists(self) -> None:
        self.assertEqual(
            VerdictCode.BLOCK_L1_DATA_FEE_ANOMALY.value, "BLOCK_L1_DATA_FEE_ANOMALY"
        )

    def test_block_gas_anomaly_exists(self) -> None:
        self.assertEqual(VerdictCode.BLOCK_GAS_ANOMALY.value, "BLOCK_GAS_ANOMALY")

    def test_all_v103_codes_unique(self) -> None:
        v103_codes = [
            VerdictCode.BLOCK_JSON_POLLUTION,
            VerdictCode.BLOCK_PROXY_UPGRADE,
            VerdictCode.BLOCK_L1_DATA_FEE_ANOMALY,
            VerdictCode.BLOCK_GAS_ANOMALY,
        ]
        values = [c.value for c in v103_codes]
        self.assertEqual(len(values), len(set(values)))

    def test_v103_codes_coexist_with_v102(self) -> None:
        """v1.0.3 codes don't collide with any previous version's codes."""
        all_codes = [c.value for c in VerdictCode]
        self.assertEqual(len(all_codes), len(set(all_codes)))


# ─────────────────────────────────────────────────────────────────────
# Bounty 3: L1 Blob-Fee Asymmetry Tests
# ─────────────────────────────────────────────────────────────────────


class TestL1DataFeeComputation(unittest.TestCase):
    """Test L1 data fee calculation for L2 rollups."""

    def test_l1_fee_zero_for_l1_mainnet(self) -> None:
        """L1 mainnet (chain_id=1) should have zero L1 data fee."""
        tx = {"data": "0x" + "ff" * 100}
        fee = _compute_l1_data_fee(tx, chain_id=1)
        self.assertEqual(fee, 0.0)

    def test_l1_fee_zero_for_unknown_chain(self) -> None:
        """Unknown chain_id should have zero L1 data fee."""
        tx = {"data": "0x" + "ff" * 100}
        fee = _compute_l1_data_fee(tx, chain_id=999999)
        self.assertEqual(fee, 0.0)

    def test_l1_fee_for_optimism(self) -> None:
        """Optimism (chain_id=10) should compute L1 data fee."""
        # 10 nonzero bytes → 10 * 16 = 160 L1 gas units
        tx = {"data": "0x" + "ff" * 10}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        expected = 160 * 30_000_000_000  # 160 gas * 30 gwei
        self.assertEqual(fee, float(expected))

    def test_l1_fee_for_base(self) -> None:
        """Base (chain_id=8453) should compute L1 data fee."""
        tx = {"data": "0x" + "ab" * 5}
        fee = _compute_l1_data_fee(tx, chain_id=8453)
        expected = 5 * 16 * 30_000_000_000  # 5 nonzero bytes
        self.assertEqual(fee, float(expected))

    def test_l1_fee_for_arbitrum(self) -> None:
        """Arbitrum (chain_id=42161) should compute L1 data fee."""
        tx = {"data": "0x" + "00" * 10}
        fee = _compute_l1_data_fee(tx, chain_id=42161)
        # 10 zero bytes → 10 * 4 = 40 L1 gas units
        expected = 40 * 30_000_000_000
        self.assertEqual(fee, float(expected))

    def test_l1_fee_mixed_bytes(self) -> None:
        """Mix of zero and nonzero bytes."""
        # 5 nonzero + 5 zero bytes
        tx = {"data": "0x" + "ff" * 5 + "00" * 5}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        expected = (5 * 16 + 5 * 4) * 30_000_000_000
        self.assertEqual(fee, float(expected))

    def test_l1_fee_empty_data(self) -> None:
        """Empty data should have zero L1 fee."""
        tx = {"data": ""}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        self.assertEqual(fee, 0.0)

    def test_l1_fee_no_data_field(self) -> None:
        """Missing data field should have zero L1 fee."""
        tx: dict = {}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        self.assertEqual(fee, 0.0)

    def test_l1_fee_custom_l1_base_fee(self) -> None:
        """Custom _l1BaseFee override."""
        tx = {"data": "0x" + "ff" * 10, "_l1BaseFee": 50_000_000_000}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        expected = 160 * 50_000_000_000
        self.assertEqual(fee, float(expected))

    def test_l1_fee_padded_calldata_attack(self) -> None:
        """Attacker pads calldata with 10KB of junk — massive L1 fee."""
        # 10,240 bytes of nonzero data → 163,840 L1 gas units
        tx = {"data": "0x" + "ab" * 10240}
        fee = _compute_l1_data_fee(tx, chain_id=8453)
        expected = 10240 * 16 * 30_000_000_000
        self.assertEqual(fee, float(expected))
        # At 30 gwei L1 base fee, this is ~0.005 ETH (4.9e15 wei)
        # Significant cost that accumulates across many transactions
        self.assertGreater(fee, 4_000_000_000_000_000)  # > 0.004 ETH

    def test_l2_chain_ids_registry(self) -> None:
        """L2 chain IDs registry has expected entries."""
        self.assertIn(10, L2_CHAIN_IDS)     # Optimism
        self.assertIn(8453, L2_CHAIN_IDS)   # Base
        self.assertIn(42161, L2_CHAIN_IDS)  # Arbitrum One
        self.assertIn(42170, L2_CHAIN_IDS)  # Arbitrum Nova
        self.assertIn(324, L2_CHAIN_IDS)    # zkSync Era
        self.assertIn(534352, L2_CHAIN_IDS) # Scroll
        self.assertIn(59144, L2_CHAIN_IDS)  # Linea
        self.assertNotIn(1, L2_CHAIN_IDS)   # L1 not in L2 registry

    def test_l1_fee_uses_input_field(self) -> None:
        """Should also work with 'input' field instead of 'data'."""
        tx = {"input": "0x" + "ff" * 10}
        fee = _compute_l1_data_fee(tx, chain_id=10)
        expected = 160 * 30_000_000_000
        self.assertEqual(fee, float(expected))


class TestTVARWithL1Fee(unittest.TestCase):
    """Test that TVAR computation includes L1 data fee on L2 chains."""

    def test_tvar_l1_chain_no_l1_fee(self) -> None:
        """TVAR on L1 mainnet should NOT include L1 data fee."""
        tx = {
            "value": 1_000_000_000_000_000_000,  # 1 ETH
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "data": "0x" + "ff" * 1000,
        }
        tvar = _compute_tvar(tx, chain_id=1)
        expected = 1_000_000_000_000_000_000 + 21_000 * 20_000_000_000
        self.assertEqual(tvar, float(expected))

    def test_tvar_l2_includes_l1_fee(self) -> None:
        """TVAR on Optimism should include L1 data fee."""
        tx = {
            "value": 1_000_000_000_000_000_000,  # 1 ETH
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "data": "0x" + "ff" * 100,  # 100 nonzero bytes
        }
        tvar = _compute_tvar(tx, chain_id=10)
        gas_cost = 21_000 * 20_000_000_000
        l1_fee = 100 * 16 * 30_000_000_000
        expected = 1_000_000_000_000_000_000 + gas_cost + l1_fee
        self.assertEqual(tvar, float(expected))

    def test_tvar_default_chain_id_no_l1_fee(self) -> None:
        """TVAR with default chain_id=0 should NOT include L1 data fee."""
        tx = {
            "value": 0,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
            "data": "0x" + "ff" * 100,
        }
        tvar = _compute_tvar(tx, chain_id=0)
        expected = 21_000 * 20_000_000_000
        self.assertEqual(tvar, float(expected))


# ─────────────────────────────────────────────────────────────────────
# Bounty 4: Gas Black Hole — Gas Anomaly Detection Tests
# ─────────────────────────────────────────────────────────────────────


class TestGasAnomalyDetection(unittest.TestCase):
    """Test gas anomaly detection in PlimsollFirewall."""

    def _make_firewall(self, **kwargs) -> PlimsollFirewall:
        config = PlimsollConfig(
            revert_strike_max=kwargs.get("revert_strike_max", 3),
            revert_strike_window_secs=kwargs.get("revert_strike_window_secs", 300.0),
            gas_anomaly_ratio=kwargs.get("gas_anomaly_ratio", 3.0),
        )
        return PlimsollFirewall(config=config)

    def test_gas_anomaly_disabled_by_default(self) -> None:
        """Gas anomaly detection disabled when ratio=0."""
        fw = PlimsollFirewall(config=PlimsollConfig(
            revert_strike_max=3,
            gas_anomaly_ratio=0.0,
        ))
        # Should not trigger even with huge ratio
        fw.record_gas_anomaly(actual_gas=1_000_000, simulated_gas=1)
        self.assertFalse(fw._paymaster_severed)

    def test_gas_anomaly_below_threshold(self) -> None:
        """Gas ratio below threshold should NOT record strike."""
        fw = self._make_firewall(gas_anomaly_ratio=3.0)
        fw.record_gas_anomaly(actual_gas=100_000, simulated_gas=50_000)  # 2x
        self.assertEqual(len(fw._revert_timestamps), 0)

    def test_gas_anomaly_above_threshold(self) -> None:
        """Gas ratio above threshold should record strike."""
        fw = self._make_firewall(gas_anomaly_ratio=3.0)
        fw.record_gas_anomaly(actual_gas=400_000, simulated_gas=100_000)  # 4x
        self.assertEqual(len(fw._revert_timestamps), 1)

    def test_gas_anomaly_triggers_paymaster_sever(self) -> None:
        """Enough gas anomalies should trigger paymaster sever."""
        fw = self._make_firewall(
            revert_strike_max=3,
            gas_anomaly_ratio=2.0,
        )
        for _ in range(3):
            fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        self.assertTrue(fw._paymaster_severed)

    def test_gas_anomaly_zero_simulated_gas(self) -> None:
        """Zero simulated gas should NOT cause divide-by-zero."""
        fw = self._make_firewall(gas_anomaly_ratio=3.0)
        fw.record_gas_anomaly(actual_gas=100_000, simulated_gas=0)
        self.assertEqual(len(fw._revert_timestamps), 0)

    def test_gas_anomaly_exact_threshold(self) -> None:
        """Ratio exactly at threshold should NOT trigger (must exceed)."""
        fw = self._make_firewall(gas_anomaly_ratio=3.0)
        fw.record_gas_anomaly(actual_gas=300_000, simulated_gas=100_000)  # exactly 3x
        self.assertEqual(len(fw._revert_timestamps), 0)

    def test_gas_anomaly_blocks_after_sever(self) -> None:
        """After paymaster sever from gas anomalies, evaluate should block."""
        fw = self._make_firewall(
            revert_strike_max=2,
            gas_anomaly_ratio=2.0,
        )
        # Trigger sever
        for _ in range(2):
            fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        self.assertTrue(fw._paymaster_severed)

        # Evaluate should block
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.blocked)
        self.assertEqual(verdict.code, VerdictCode.BLOCK_PAYMASTER_SEVERED)


# ─────────────────────────────────────────────────────────────────────
# Backward Compatibility Tests
# ─────────────────────────────────────────────────────────────────────


class TestBackwardCompatV103(unittest.TestCase):
    """All v1.0.3 features are disabled by default."""

    def test_chain_id_default_zero(self) -> None:
        """chain_id defaults to 0 (skip L1 fee computation)."""
        config = PlimsollConfig()
        self.assertEqual(config.chain_id, 0)

    def test_gas_anomaly_ratio_default_zero(self) -> None:
        """gas_anomaly_ratio defaults to 0.0 (disabled)."""
        config = PlimsollConfig()
        self.assertEqual(config.gas_anomaly_ratio, 0.0)

    def test_firewall_works_without_v103_config(self) -> None:
        """Firewall works normally with no v1.0.3 config."""
        fw = PlimsollFirewall()
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)

    def test_tvar_backward_compat_no_chain_id(self) -> None:
        """_compute_tvar without chain_id argument should work."""
        tx = {
            "value": 1_000_000,
            "gas": 21_000,
            "maxFeePerGas": 20_000_000_000,
        }
        tvar = _compute_tvar(tx)
        expected = 1_000_000 + 21_000 * 20_000_000_000
        self.assertEqual(tvar, float(expected))


# ─────────────────────────────────────────────────────────────────────
# Integration Tests
# ─────────────────────────────────────────────────────────────────────


class TestV103Integration(unittest.TestCase):
    """Integration tests combining multiple v1.0.3 features."""

    def test_gas_anomaly_and_revert_strikes_combined(self) -> None:
        """Gas anomalies and reverts share the same sever mechanism."""
        fw = PlimsollFirewall(config=PlimsollConfig(
            revert_strike_max=3,
            revert_strike_window_secs=300.0,
            gas_anomaly_ratio=2.0,
        ))
        # 1 revert strike
        fw.record_revert()
        # 2 gas anomaly strikes
        fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        # Total: 3 strikes → sever
        self.assertTrue(fw._paymaster_severed)

    def test_l2_tvar_with_gas_anomaly(self) -> None:
        """L2 chain with gas anomaly detection both enabled."""
        fw = PlimsollFirewall(config=PlimsollConfig(
            chain_id=10,  # Optimism
            gas_anomaly_ratio=3.0,
            revert_strike_max=5,
        ))
        self.assertEqual(fw.config.chain_id, 10)
        self.assertEqual(fw.config.gas_anomaly_ratio, 3.0)
        # Should still evaluate normally
        verdict = fw.evaluate({"target": "0x1234", "amount": 1.0})
        self.assertTrue(verdict.allowed)

    def test_reset_clears_v103_state(self) -> None:
        """reset() clears all v1.0.3 state along with prior state."""
        fw = PlimsollFirewall(config=PlimsollConfig(
            revert_strike_max=5,
            gas_anomaly_ratio=2.0,
        ))
        fw.record_gas_anomaly(actual_gas=500_000, simulated_gas=100_000)
        self.assertEqual(len(fw._revert_timestamps), 1)

        fw.reset()
        self.assertEqual(len(fw._revert_timestamps), 0)
        self.assertFalse(fw._paymaster_severed)


if __name__ == "__main__":
    unittest.main()
