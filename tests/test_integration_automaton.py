"""Tests for the ``PlimsollAutomatonWallet`` integration."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any
from unittest import mock

import pytest

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.engines.trajectory_hash import TrajectoryHashConfig
from plimsoll.verdict import VerdictCode


# ── Fake Automaton module ─────────────────────────────────────────

@dataclass
class _FakeWallet:
    """Minimal stand-in for ``automaton.wallet.Wallet``."""
    private_key: str = ""
    rpc_url: str = ""
    executed: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.executed = []

    def execute(self, payload: dict[str, Any], **kwargs: Any) -> dict:
        self.executed.append(payload)
        return {"tx_hash": "0xabc"}


def _mock_automaton():
    """Create a mock ``automaton.wallet`` module with our fake Wallet."""
    wallet_mod = mock.MagicMock()
    wallet_mod.Wallet = _FakeWallet
    return {"automaton": mock.MagicMock(), "automaton.wallet": wallet_mod}


# ────────────────────────────────────────────────────────────────────

class TestPlimsollAutomatonWallet:

    def test_allows_clean_tx(self) -> None:
        with mock.patch.dict(sys.modules, _mock_automaton()):
            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            wallet = PlimsollAutomatonWallet(
                private_key="0xdeadbeef",
                rpc_url="https://rpc.example.com",
                max_daily_spend=10_000,
            )
            result = wallet.execute({"target": "0xAAA", "amount": 1.0})
            assert result == {"tx_hash": "0xabc"}

    def test_blocks_velocity_breach(self) -> None:
        with mock.patch.dict(sys.modules, _mock_automaton()):
            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            wallet = PlimsollAutomatonWallet(
                private_key="0xdeadbeef",
                rpc_url="https://rpc.example.com",
                max_daily_spend=10,
                plimsoll_config=PlimsollConfig(
                    velocity=CapitalVelocityConfig(
                        v_max=0.001, max_single_amount=5.0,
                    ),
                ),
            )
            result = wallet.execute({"target": "0xAAA", "amount": 100.0})
            assert result["plimsoll_blocked"] is True
            assert "feedback" in result

    def test_blocks_loop_detection(self) -> None:
        with mock.patch.dict(sys.modules, _mock_automaton()):
            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            wallet = PlimsollAutomatonWallet(
                private_key="0xdeadbeef",
                rpc_url="https://rpc.example.com",
                plimsoll_config=PlimsollConfig(
                    trajectory=TrajectoryHashConfig(max_duplicates=1),
                ),
            )
            payload = {"target": "0xAAA", "amount": 1.0, "function": "transfer"}
            wallet.execute(payload)  # 1st: allowed
            result = wallet.execute(payload)  # 2nd: loop detected
            assert result["plimsoll_blocked"] is True

    def test_exposes_firewall(self) -> None:
        with mock.patch.dict(sys.modules, _mock_automaton()):
            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            wallet = PlimsollAutomatonWallet(
                private_key="0xdeadbeef",
                rpc_url="https://rpc.example.com",
            )
            assert isinstance(wallet.firewall, PlimsollFirewall)

    def test_import_error_without_automaton(self) -> None:
        """Should raise ImportError with helpful message when automaton is missing."""
        # Temporarily remove automaton from sys.modules if it exists
        mods_to_remove = [k for k in sys.modules if k.startswith("automaton")]
        saved = {k: sys.modules.pop(k) for k in mods_to_remove}

        try:
            # Force re-import
            if "plimsoll.integrations.automaton" in sys.modules:
                del sys.modules["plimsoll.integrations.automaton"]

            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            with pytest.raises(ImportError, match="automaton"):
                PlimsollAutomatonWallet(
                    private_key="0xdeadbeef",
                    rpc_url="https://rpc.example.com",
                )
        finally:
            sys.modules.update(saved)

    def test_custom_plimsoll_config(self) -> None:
        with mock.patch.dict(sys.modules, _mock_automaton()):
            from plimsoll.integrations.automaton import PlimsollAutomatonWallet

            custom = PlimsollConfig(
                velocity=CapitalVelocityConfig(v_max=999.0),
            )
            wallet = PlimsollAutomatonWallet(
                private_key="0xdeadbeef",
                rpc_url="https://rpc.example.com",
                plimsoll_config=custom,
            )
            assert wallet.firewall.config.velocity.v_max == 999.0
