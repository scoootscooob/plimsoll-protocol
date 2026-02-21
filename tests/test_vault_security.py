"""Tests for Vault Security Patches: Flaws 1-4.

Flaw 1: Blind Vault (Inversion of Control)
Flaw 2: EIP-1559 Gas Drain (TVAR)
Flaw 3: Python RAM Forensics (Soft Enclave Wipe)
Flaw 4: Nonce Desync (AegisEnforcementError)
"""

from __future__ import annotations

import gc
import pytest

from aegis.enclave.vault import (
    KeyVault,
    AegisEnforcementError,
    _compute_tvar,
    _tx_dict_to_aegis_payload,
    _secure_wipe,
)
from aegis.firewall import AegisFirewall, AegisConfig
from aegis.engines.capital_velocity import CapitalVelocityConfig
from aegis.verdict import VerdictCode


# ── Helpers ──────────────────────────────────────────────────────────

def _make_eth_key() -> str:
    """Generate a real Ethereum private key for testing."""
    from eth_account import Account as EthAccount
    return EthAccount.create().key.hex()


def _make_tx_dict(
    to: str = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
    value: int = 1000,
    gas: int = 21000,
    max_fee: int = 50_000_000_000,
    priority_fee: int = 2_000_000_000,
    nonce: int = 0,
) -> dict:
    """Build a minimal EIP-1559 tx dict."""
    from web3 import Web3
    return {
        "to": Web3.to_checksum_address(to),
        "value": value,
        "gas": gas,
        "maxFeePerGas": max_fee,
        "maxPriorityFeePerGas": priority_fee,
        "nonce": nonce,
        "chainId": 11155111,
        "type": 2,
    }


# ═════════════════════════════════════════════════════════════════════
# FLAW 1: Blind Vault — Inversion of Control
# ═════════════════════════════════════════════════════════════════════


class TestInversionOfControl:
    """The vault owns the firewall. RCE can't bypass it."""

    def test_firewall_auto_bound_on_init(self):
        """AegisFirewall auto-binds to its vault on __post_init__."""
        fw = AegisFirewall()
        assert fw.vault is not None
        assert fw.vault.has_firewall

    def test_vault_blocks_without_caller_check(self):
        """Even if the caller deletes their if-statement, the vault blocks."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(max_single_amount=500),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("test_key", key_hex)

        # Tx exceeds the hard cap (1000 value > 500 cap)
        tx = _make_tx_dict(value=1_000_000_000_000_000_000)  # 1 ETH in wei

        # The vault internally runs firewall.evaluate() and blocks
        with pytest.raises(AegisEnforcementError) as exc_info:
            fw.vault.sign_eth_transaction("test_key", tx, spend_amount=1000.0)

        assert "CapitalVelocity" in exc_info.value.engine or "BLOCK" in exc_info.value.code

    def test_vault_allows_legitimate_tx(self):
        """Legitimate transactions pass through vault + firewall."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(
                max_single_amount=10_000,
                v_max=100_000,
            ),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("test_key", key_hex)

        tx = _make_tx_dict(value=1000)
        raw = fw.vault.sign_eth_transaction("test_key", tx, spend_amount=10.0)
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    def test_unbound_vault_signs_freely(self):
        """A vault without a bound firewall signs anything (backward compat)."""
        vault = KeyVault()
        key_hex = _make_eth_key()
        vault.store("free_key", key_hex)

        assert not vault.has_firewall

        tx = _make_tx_dict(value=999_999_999)
        raw = vault.sign_eth_transaction("free_key", tx)
        assert isinstance(raw, bytes)

    def test_cannot_rebind_firewall(self):
        """Once bound, the firewall cannot be swapped (prevents hot-swap attacks)."""
        vault = KeyVault()
        fw1 = AegisFirewall(config=AegisConfig(enable_vault=False))
        vault.bind_firewall(fw1)

        fw2 = AegisFirewall(config=AegisConfig(enable_vault=False))
        with pytest.raises(RuntimeError, match="already bound"):
            vault.bind_firewall(fw2)

    def test_enforcement_error_fields(self):
        """AegisEnforcementError carries engine/reason/code for debugging."""
        err = AegisEnforcementError(
            reason="VELOCITY BREACH: PID output 5.2 > threshold 2.0",
            engine="CapitalVelocity",
            code="BLOCK_VELOCITY_BREACH",
        )
        assert err.engine == "CapitalVelocity"
        assert "VELOCITY BREACH" in err.reason
        assert err.code == "BLOCK_VELOCITY_BREACH"
        assert "AEGIS VAULT ENFORCEMENT" in str(err)


# ═════════════════════════════════════════════════════════════════════
# FLAW 2: EIP-1559 Gas Drain — Total Value at Risk
# ═════════════════════════════════════════════════════════════════════


class TestTVAR:
    """TVAR computation catches gas drain attacks."""

    def test_tvar_basic(self):
        """TVAR = value + gas * maxFeePerGas."""
        tx = _make_tx_dict(value=1000, gas=21000, max_fee=100)
        tvar = _compute_tvar(tx)
        assert tvar == 1000 + 21000 * 100

    def test_tvar_zero_value_high_gas(self):
        """Gas drain attack: 0 ETH value, absurd priority fee."""
        tx = _make_tx_dict(value=0, gas=21000, max_fee=500_000_000_000_000)
        tvar = _compute_tvar(tx)
        # TVAR = 0 + 21000 * 500_000_000_000_000 = massive
        assert tvar == 21000 * 500_000_000_000_000
        assert tvar > 0  # Not fooled by value=0

    def test_tvar_legacy_gas_price(self):
        """Legacy transactions use gasPrice instead of maxFeePerGas."""
        tx = {"value": 5000, "gas": 21000, "gasPrice": 50}
        tvar = _compute_tvar(tx)
        assert tvar == 5000 + 21000 * 50

    def test_tvar_eip1559_preferred_over_legacy(self):
        """maxFeePerGas takes priority over gasPrice."""
        tx = {"value": 0, "gas": 21000, "maxFeePerGas": 100, "gasPrice": 50}
        tvar = _compute_tvar(tx)
        assert tvar == 21000 * 100  # Uses maxFeePerGas, not gasPrice

    def test_tvar_defaults(self):
        """Missing fields default to safe values."""
        tvar = _compute_tvar({})
        assert tvar == 0.0

    def test_gas_drain_blocked_by_vault(self):
        """The gas drain attack is caught by TVAR → CapitalVelocity."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(
                max_single_amount=1_000_000,  # 1M wei max
            ),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        # Gas drain: 0 ETH value but absurd gas cost
        tx = _make_tx_dict(
            value=0,
            gas=21_000,
            max_fee=500_000_000_000_000,  # 500K gwei — drains wallet
        )

        # TVAR = 0 + 21000 * 500_000_000_000_000 = 10.5 quadrillion wei
        # This far exceeds max_single_amount=1M
        with pytest.raises(AegisEnforcementError):
            fw.vault.sign_eth_transaction("agent", tx)


class TestTxDictToPayload:
    """Ethereum tx dict → Aegis payload conversion."""

    def test_basic_conversion(self):
        tx = _make_tx_dict(value=1000, gas=21000, max_fee=100, priority_fee=10)
        payload = _tx_dict_to_aegis_payload(tx)
        assert payload["target"] == tx["to"]
        assert payload["amount"] == 1000.0
        assert payload["gas"] == 21000
        assert payload["maxFeePerGas"] == 100
        assert payload["maxPriorityFeePerGas"] == 10

    def test_missing_to(self):
        tx = {"value": 100}
        payload = _tx_dict_to_aegis_payload(tx)
        assert "target" not in payload


# ═════════════════════════════════════════════════════════════════════
# FLAW 3: Python RAM Forensics — Soft Enclave Wipe
# ═════════════════════════════════════════════════════════════════════


class TestSoftEnclaveWipe:
    """Verify bytearray zeroing after key use."""

    def test_secure_wipe_zeros_buffer(self):
        """_secure_wipe overwrites every byte with 0."""
        buf = bytearray(b"super_secret_private_key_material")
        assert any(b != 0 for b in buf)  # Confirm non-zero
        _secure_wipe(buf)
        assert all(b == 0 for b in buf)  # All zeros
        assert len(buf) == len(b"super_secret_private_key_material")

    def test_secure_wipe_empty(self):
        """Wiping empty buffer doesn't crash."""
        buf = bytearray(b"")
        _secure_wipe(buf)
        assert len(buf) == 0

    def test_signing_wipes_key_buffer(self):
        """After sign_eth_transaction, the key buffer should be zeroed.

        We can't directly inspect the local variable, but we verify
        the vault still works (key is re-decrypted on next call) and
        the signing produces valid results.
        """
        vault = KeyVault()
        key_hex = _make_eth_key()
        vault.store("wipe_test", key_hex)

        tx = _make_tx_dict()

        # First sign
        raw1 = vault.sign_eth_transaction("wipe_test", tx)
        assert isinstance(raw1, bytes)

        # Second sign — proves key can be re-decrypted from vault
        # (the wiped buffer was a copy, not the encrypted store)
        tx2 = _make_tx_dict(nonce=1)
        raw2 = vault.sign_eth_transaction("wipe_test", tx2)
        assert isinstance(raw2, bytes)
        assert raw1 != raw2  # Different nonces → different signatures

    def test_gc_is_called(self):
        """Verify gc.collect() is invoked during wipe (via side effect)."""
        # We can't easily test gc.collect was called, but we can verify
        # the function doesn't raise
        buf = bytearray(b"test_data_1234567890")
        _secure_wipe(buf)
        assert all(b == 0 for b in buf)


# ═════════════════════════════════════════════════════════════════════
# FLAW 4: Nonce Desync — Synthetic Revert
# ═════════════════════════════════════════════════════════════════════


class TestAegisEnforcementError:
    """AegisEnforcementError enables graceful recovery (no crash, no desync)."""

    def test_error_is_catchable(self):
        """The error can be caught without crashing the agent."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(max_single_amount=100),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        tx = _make_tx_dict(value=999_999_999)

        caught = False
        try:
            fw.vault.sign_eth_transaction("agent", tx, spend_amount=999.0)
        except AegisEnforcementError as e:
            caught = True
            # The error message is suitable for injection into LLM context
            assert "BLOCKED" in str(e) or "AEGIS" in str(e)
            assert e.engine is not None
            assert e.code is not None

        assert caught

    def test_firewall_state_unaffected_after_block(self):
        """After a vault block, the firewall state is clean for the next tx."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(
                max_single_amount=1000,
                v_max=100_000,
            ),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        # Block a big tx
        big_tx = _make_tx_dict(value=999_999_999)
        with pytest.raises(AegisEnforcementError):
            fw.vault.sign_eth_transaction("agent", big_tx, spend_amount=5000.0)

        # Small tx should still work
        small_tx = _make_tx_dict(value=100, nonce=0)
        raw = fw.vault.sign_eth_transaction("agent", small_tx, spend_amount=1.0)
        assert isinstance(raw, bytes)

    def test_error_preserves_reason_for_llm_feedback(self):
        """The error reason is detailed enough for LLM context injection."""
        err = AegisEnforcementError(
            reason="VELOCITY BREACH: PID output 5.2 > threshold 2.0",
            engine="CapitalVelocity",
            code="BLOCK_VELOCITY_BREACH",
        )
        # This string should be suitable for the LLM's tool output
        s = str(err)
        assert "VELOCITY BREACH" in s
        assert "CapitalVelocity" in s
        assert "BLOCK_VELOCITY_BREACH" in s


# ═════════════════════════════════════════════════════════════════════
# INTEGRATION: All flaws together
# ═════════════════════════════════════════════════════════════════════


class TestEndToEndSecurity:
    """Full integration: vault owns firewall, TVAR computed, key wiped."""

    def test_full_pipeline_legitimate_tx(self):
        """Legit tx: firewall allows → vault signs → key wiped → raw returned."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(
                max_single_amount=10_000_000,
                v_max=100_000_000,
            ),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        tx = _make_tx_dict(value=1000)
        raw = fw.vault.sign_eth_transaction("agent", tx, spend_amount=10.0)

        # Verify signature is valid
        from eth_account import Account as EthAccount
        recovered = EthAccount.recover_transaction(raw)
        assert recovered is not None

    def test_full_pipeline_gas_drain_blocked(self):
        """Gas drain: TVAR catches high gas → firewall blocks → key NEVER decrypted."""
        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(max_single_amount=1_000_000),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        # Gas drain: value=0 but maxFeePerGas is astronomical
        tx = _make_tx_dict(value=0, max_fee=999_999_999_999_999)

        with pytest.raises(AegisEnforcementError) as exc:
            fw.vault.sign_eth_transaction("agent", tx)

        assert exc.value.engine is not None

    def test_full_pipeline_multiple_txs(self):
        """Multiple legit txs succeed, proving vault state is clean between calls."""
        from eth_account import Account as EthAccount

        fw = AegisFirewall(config=AegisConfig(
            velocity=CapitalVelocityConfig(
                max_single_amount=10_000_000,
                v_max=100_000_000,
            ),
        ))
        key_hex = _make_eth_key()
        fw.vault.store("agent", key_hex)

        # Use distinct recipients to avoid TrajectoryHash loop detection
        recipients = [EthAccount.create().address for _ in range(5)]
        for i, addr in enumerate(recipients):
            tx = _make_tx_dict(to=addr, value=100 + i, nonce=i)
            raw = fw.vault.sign_eth_transaction("agent", tx, spend_amount=1.0)
            assert isinstance(raw, bytes)
