"""Tests for Zero-Day Security Patches v1.0.2.

Patch 1: "Trojan Receipt" — LLM Context Poisoning Sanitizer (Rust-side)
Patch 2: "Schrödinger's State" — Opcode-Level Non-Determinism Detector (Rust-side)
Patch 3: Cross-Chain Permit Replay — Domain Separator Pinning (Python + Rust)
Patch 4: Paymaster Slashing Attack — Revert Strike System (Python + Rust + Solidity)
"""

from __future__ import annotations

import time
import pytest

from plimsoll.enclave.vault import PlimsollEnforcementError, KeyVault
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.firewall import PlimsollConfig, PlimsollFirewall
from plimsoll.verdict import Verdict, VerdictCode


# ═════════════════════════════════════════════════════════════════════
# VERDICT CODE EXISTENCE
# ═════════════════════════════════════════════════════════════════════


class TestVerdictCodesV102:
    """Verify all v1.0.2 VerdictCodes are defined."""

    def test_trojan_receipt_code_exists(self):
        assert hasattr(VerdictCode, "BLOCK_TROJAN_RECEIPT")
        assert VerdictCode.BLOCK_TROJAN_RECEIPT.value == "BLOCK_TROJAN_RECEIPT"

    def test_non_deterministic_code_exists(self):
        assert hasattr(VerdictCode, "BLOCK_NON_DETERMINISTIC")
        assert VerdictCode.BLOCK_NON_DETERMINISTIC.value == "BLOCK_NON_DETERMINISTIC"

    def test_cross_chain_replay_code_exists(self):
        assert hasattr(VerdictCode, "BLOCK_CROSS_CHAIN_REPLAY")
        assert VerdictCode.BLOCK_CROSS_CHAIN_REPLAY.value == "BLOCK_CROSS_CHAIN_REPLAY"

    def test_paymaster_severed_code_exists(self):
        assert hasattr(VerdictCode, "BLOCK_PAYMASTER_SEVERED")
        assert VerdictCode.BLOCK_PAYMASTER_SEVERED.value == "BLOCK_PAYMASTER_SEVERED"

    def test_trojan_receipt_verdict_is_blocked(self):
        v = Verdict(
            code=VerdictCode.BLOCK_TROJAN_RECEIPT,
            reason="LLM control token in read-path",
            engine="Sanitizer",
        )
        assert v.blocked
        assert not v.allowed

    def test_non_deterministic_verdict_is_blocked(self):
        v = Verdict(
            code=VerdictCode.BLOCK_NON_DETERMINISTIC,
            reason="Environmental opcode in JUMPI",
            engine="Inspector",
        )
        assert v.blocked

    def test_cross_chain_replay_verdict_is_blocked(self):
        v = Verdict(
            code=VerdictCode.BLOCK_CROSS_CHAIN_REPLAY,
            reason="Missing chainId",
            engine="ChainIdValidator",
        )
        assert v.blocked
        assert "Missing chainId" in v.feedback_prompt()

    def test_paymaster_severed_verdict_is_blocked(self):
        v = Verdict(
            code=VerdictCode.BLOCK_PAYMASTER_SEVERED,
            reason="Too many reverts",
            engine="PaymasterSever",
        )
        assert v.blocked
        assert "PIVOT STRATEGY" in v.feedback_prompt()


# ═════════════════════════════════════════════════════════════════════
# PATCH 3: Cross-Chain Permit Replay — Domain Separator Pinning
# ═════════════════════════════════════════════════════════════════════


class TestCrossChainReplayDefense:
    """Verify chainId validation in KeyVault.sign_typed_data()."""

    def _make_vault(self, chain_id: int | None = None) -> KeyVault:
        vault = KeyVault()
        vault.store("test_key", "secret_key_material")
        if chain_id is not None:
            vault.set_expected_chain_id(chain_id)
        return vault

    def _make_typed_data(self, chain_id=1, include_chain_id=True):
        domain = {"name": "TestProtocol", "version": "1"}
        if include_chain_id:
            domain["chainId"] = chain_id
        return {
            "primaryType": "Transfer",  # Not dangerous — won't trigger GOD-TIER 1
            "domain": domain,
            "types": {"Transfer": [{"name": "to", "type": "address"}]},
            "message": {"to": "0x1234"},
        }

    def test_chain_id_disabled_by_default(self):
        """When _expected_chain_id is None, no chainId validation occurs."""
        vault = self._make_vault(chain_id=None)
        data = self._make_typed_data(chain_id=999, include_chain_id=True)
        # Should NOT raise — validation is disabled
        sig = vault.sign_typed_data("test_key", data)
        assert sig  # Got a signature back

    def test_chain_id_correct_passes(self):
        """Correct chainId passes validation."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id=1)
        sig = vault.sign_typed_data("test_key", data)
        assert sig

    def test_chain_id_mismatch_blocked(self):
        """Mismatched chainId raises PlimsollEnforcementError."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id=42)  # Wrong chain!
        with pytest.raises(PlimsollEnforcementError) as exc:
            vault.sign_typed_data("test_key", data)
        assert "BLOCK_CROSS_CHAIN_REPLAY" in str(exc.value.code)
        assert "42" in exc.value.reason
        assert "1" in exc.value.reason

    def test_chain_id_missing_blocked(self):
        """Missing chainId in domain raises PlimsollEnforcementError."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(include_chain_id=False)
        with pytest.raises(PlimsollEnforcementError) as exc:
            vault.sign_typed_data("test_key", data)
        assert "BLOCK_CROSS_CHAIN_REPLAY" in str(exc.value.code)
        assert "MISSING" in exc.value.reason

    def test_chain_id_zero_blocked(self):
        """chainId=0 (wildcard) is rejected."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id=0)
        with pytest.raises(PlimsollEnforcementError) as exc:
            vault.sign_typed_data("test_key", data)
        assert "BLOCK_CROSS_CHAIN_REPLAY" in str(exc.value.code)
        assert "wildcard" in exc.value.reason.lower() or "0" in exc.value.reason

    def test_chain_id_hex_string_parsed(self):
        """chainId as hex string '0x1' is parsed correctly."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id="0x1")
        sig = vault.sign_typed_data("test_key", data)
        assert sig

    def test_chain_id_decimal_string_parsed(self):
        """chainId as decimal string '1' is parsed correctly."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id="1")
        sig = vault.sign_typed_data("test_key", data)
        assert sig

    def test_chain_id_hex_string_mismatch(self):
        """chainId='0xa' (10) doesn't match expected=1."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id="0xa")
        with pytest.raises(PlimsollEnforcementError):
            vault.sign_typed_data("test_key", data)

    def test_set_expected_chain_id_rejects_zero(self):
        """set_expected_chain_id rejects zero."""
        vault = KeyVault()
        with pytest.raises(ValueError):
            vault.set_expected_chain_id(0)

    def test_set_expected_chain_id_rejects_negative(self):
        """set_expected_chain_id rejects negative values."""
        vault = KeyVault()
        with pytest.raises(ValueError):
            vault.set_expected_chain_id(-1)

    def test_chain_id_unparseable_blocked(self):
        """Unparseable chainId is rejected."""
        vault = self._make_vault(chain_id=1)
        data = self._make_typed_data(chain_id="not_a_number")
        with pytest.raises(PlimsollEnforcementError) as exc:
            vault.sign_typed_data("test_key", data)
        assert "BLOCK_CROSS_CHAIN_REPLAY" in str(exc.value.code)

    def test_chain_id_validation_before_dangerous_type_check(self):
        """chainId validation runs BEFORE dangerous primary type check.

        Even a dangerous type like Permit should first fail on chainId.
        """
        vault = self._make_vault(chain_id=1)
        data = {
            "primaryType": "Permit",  # Dangerous type
            "domain": {"name": "Token", "version": "1", "chainId": 42},  # Wrong chain
            "types": {"Permit": [{"name": "spender", "type": "address"}]},
            "message": {"spender": "0xDEAD", "value": "100"},
        }
        with pytest.raises(PlimsollEnforcementError) as exc:
            vault.sign_typed_data("test_key", data)
        # Should be CROSS_CHAIN_REPLAY, not EIP712_PERMIT
        assert "BLOCK_CROSS_CHAIN_REPLAY" in str(exc.value.code)


# ═════════════════════════════════════════════════════════════════════
# PATCH 4: Paymaster Slashing Attack — Revert Strike System
# ═════════════════════════════════════════════════════════════════════


class TestPaymasterSlashingDefense:
    """Verify revert tracking and Paymaster sever in PlimsollFirewall."""

    def _make_firewall(
        self,
        revert_max: int = 3,
        revert_window: float = 60.0,
    ) -> PlimsollFirewall:
        return PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=revert_max,
                revert_strike_window_secs=revert_window,
                enable_vault=False,
            )
        )

    def _safe_payload(self) -> dict:
        return {"target": "0x1234", "amount": 1.0}

    def test_revert_disabled_by_default(self):
        """Default revert_strike_max=0 means feature is disabled."""
        fw = PlimsollFirewall(config=PlimsollConfig(enable_vault=False))
        assert fw.config.revert_strike_max == 0
        # record_revert should be a no-op
        fw.record_revert()
        fw.record_revert()
        fw.record_revert()
        assert not fw._paymaster_severed

    def test_revert_below_threshold_allows(self):
        """Reverts below threshold don't trigger sever."""
        fw = self._make_firewall(revert_max=3)
        fw.record_revert()
        fw.record_revert()
        assert not fw._paymaster_severed
        # Transactions still allowed
        v = fw.evaluate(self._safe_payload())
        assert v.allowed

    def test_revert_at_threshold_triggers_sever(self):
        """Reaching revert threshold triggers Paymaster sever."""
        fw = self._make_firewall(revert_max=3)
        fw.record_revert()
        fw.record_revert()
        fw.record_revert()
        assert fw._paymaster_severed

    def test_sever_blocks_all_transactions(self):
        """Once severed, ALL transactions are blocked."""
        fw = self._make_firewall(revert_max=2)
        fw.record_revert()
        fw.record_revert()
        assert fw._paymaster_severed

        v = fw.evaluate(self._safe_payload())
        assert v.blocked
        assert v.code is VerdictCode.BLOCK_PAYMASTER_SEVERED
        assert "PaymasterSever" in v.engine

    def test_sever_verdict_has_metadata(self):
        """Sever verdict includes revert count and threshold metadata."""
        fw = self._make_firewall(revert_max=2)
        fw.record_revert()
        fw.record_revert()

        v = fw.evaluate(self._safe_payload())
        assert v.blocked
        assert "revert_count" in v.metadata
        assert "threshold" in v.metadata

    def test_sever_feedback_prompt(self):
        """Sever verdict generates useful feedback for LLM context."""
        fw = self._make_firewall(revert_max=2)
        fw.record_revert()
        fw.record_revert()

        v = fw.evaluate(self._safe_payload())
        prompt = v.feedback_prompt()
        assert "SYSTEM OVERRIDE" in prompt
        assert "PIVOT STRATEGY" in prompt

    def test_rolling_window_prunes_old_reverts(self):
        """Reverts outside the rolling window are pruned."""
        fw = self._make_firewall(revert_max=3, revert_window=1.0)

        fw.record_revert()
        fw.record_revert()
        assert not fw._paymaster_severed

        # Wait for window to expire
        time.sleep(1.1)

        # This revert is in a new window — total in-window = 1
        fw.record_revert()
        assert not fw._paymaster_severed

    def test_webhook_fires_on_sever(self):
        """on_paymaster_sever callback is invoked when sever triggers."""
        callback_fired = []

        def on_sever():
            callback_fired.append(True)

        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=2,
                revert_strike_window_secs=60.0,
                on_paymaster_sever=on_sever,
                enable_vault=False,
            )
        )

        fw.record_revert()
        assert len(callback_fired) == 0
        fw.record_revert()
        assert len(callback_fired) == 1

    def test_webhook_exception_safe(self):
        """Exception in on_paymaster_sever callback doesn't crash."""

        def bad_callback():
            raise RuntimeError("Webhook error!")

        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=1,
                on_paymaster_sever=bad_callback,
                enable_vault=False,
            )
        )

        # Should not raise
        fw.record_revert()
        assert fw._paymaster_severed

    def test_reset_clears_paymaster_state(self):
        """reset() clears the paymaster sever state."""
        fw = self._make_firewall(revert_max=2)
        fw.record_revert()
        fw.record_revert()
        assert fw._paymaster_severed

        fw.reset()
        assert not fw._paymaster_severed
        assert len(fw._revert_timestamps) == 0

        # Should be able to transact again
        v = fw.evaluate(self._safe_payload())
        assert v.allowed

    def test_sever_permanent_until_reset(self):
        """Once severed, stays severed until explicit reset()."""
        fw = self._make_firewall(revert_max=1)
        fw.record_revert()
        assert fw._paymaster_severed

        # Multiple evaluations still blocked
        v1 = fw.evaluate(self._safe_payload())
        v2 = fw.evaluate(self._safe_payload())
        assert v1.blocked
        assert v2.blocked

    def test_paymaster_sever_before_cognitive_sever(self):
        """Paymaster sever check runs in evaluate() and catches before engines."""
        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=1,
                cognitive_sever_enabled=True,
                strike_max=100,  # High so cognitive sever doesn't trigger
                enable_vault=False,
            )
        )
        fw.record_revert()
        assert fw._paymaster_severed

        v = fw.evaluate(self._safe_payload())
        assert v.code is VerdictCode.BLOCK_PAYMASTER_SEVERED

    def test_stats_not_affected_by_sever_blocks(self):
        """Sever blocks are still counted in stats."""
        fw = self._make_firewall(revert_max=1)
        fw.record_revert()
        fw.evaluate(self._safe_payload())
        fw.evaluate(self._safe_payload())

        stats = fw.stats
        assert stats["blocked"] == 2
        assert stats["allowed"] == 0


# ═════════════════════════════════════════════════════════════════════
# BACKWARD COMPATIBILITY
# ═════════════════════════════════════════════════════════════════════


class TestBackwardCompatibility:
    """Ensure all v1.0.2 features are disabled by default."""

    def test_default_config_has_no_chain_id(self):
        """Default vault has no expected_chain_id."""
        vault = KeyVault()
        assert vault._expected_chain_id is None

    def test_default_config_revert_disabled(self):
        """Default config has revert_strike_max=0 (disabled)."""
        cfg = PlimsollConfig()
        assert cfg.revert_strike_max == 0

    def test_default_config_cognitive_sever_disabled(self):
        """Default config has cognitive_sever_enabled=False."""
        cfg = PlimsollConfig()
        assert not cfg.cognitive_sever_enabled

    def test_existing_functionality_unaffected(self):
        """Basic firewall functionality still works with v1.0.2 additions."""
        fw = PlimsollFirewall(config=PlimsollConfig(enable_vault=False))
        payload = {"target": "0x1234", "amount": 10.0}

        v = fw.evaluate(payload, spend_amount=10.0)
        assert v.allowed

        stats = fw.stats
        assert stats["allowed"] == 1
        assert stats["blocked"] == 0

    def test_sign_typed_data_backward_compat(self):
        """sign_typed_data works without chainId validation when disabled."""
        vault = KeyVault()
        vault.store("key1", "my_secret")

        # No chainId in domain — should succeed when validation is disabled
        data = {
            "primaryType": "Transfer",
            "domain": {"name": "Test"},
            "types": {"Transfer": [{"name": "to", "type": "address"}]},
            "message": {"to": "0xABCD"},
        }
        sig = vault.sign_typed_data("key1", data)
        assert sig


# ═════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═════════════════════════════════════════════════════════════════════


class TestV102Integration:
    """Integration tests combining multiple v1.0.2 patches."""

    def test_all_defense_layers_active(self):
        """All v1.0.2 features can be enabled simultaneously."""
        callback_log = []

        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=3,
                revert_strike_window_secs=300.0,
                on_paymaster_sever=lambda: callback_log.append("paymaster"),
                cognitive_sever_enabled=True,
                strike_max=5,
                strike_window_secs=60.0,
                on_cognitive_sever=lambda: callback_log.append("cognitive"),
                enable_vault=False,
            )
        )

        # Normal transaction passes
        v = fw.evaluate({"target": "0x1234", "amount": 1.0})
        assert v.allowed

    def test_paymaster_sever_plus_vault_chain_id(self):
        """Paymaster sever and chainId validation coexist."""
        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=2,
                enable_vault=True,
            )
        )

        # Set chain ID on vault
        fw.vault.set_expected_chain_id(1)

        # Chain ID validation works
        fw.vault.store("key1", "secret_key")
        data = {
            "primaryType": "Transfer",
            "domain": {"name": "Test", "chainId": 42},
            "types": {"Transfer": [{"name": "to", "type": "address"}]},
            "message": {"to": "0x1234"},
        }
        with pytest.raises(PlimsollEnforcementError):
            fw.vault.sign_typed_data("key1", data)

        # Paymaster sever also works
        fw.record_revert()
        fw.record_revert()
        assert fw._paymaster_severed

    def test_sever_counted_in_history(self):
        """Paymaster sever verdicts appear in firewall history."""
        fw = PlimsollFirewall(
            config=PlimsollConfig(
                revert_strike_max=1,
                enable_vault=False,
            )
        )
        fw.record_revert()

        v = fw.evaluate({"target": "0x1234"})
        assert v.blocked

        assert len(fw._history) == 1
        ts, verdict = fw._history[0]
        assert verdict.code is VerdictCode.BLOCK_PAYMASTER_SEVERED
