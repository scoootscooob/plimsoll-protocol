"""Tests for the ``PlimsollElizaAction`` wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.integrations.eliza import PlimsollElizaAction
from plimsoll.verdict import VerdictCode


def _make_firewall(**kwargs: object) -> PlimsollFirewall:
    return PlimsollFirewall(config=PlimsollConfig(**kwargs))


@dataclass
class _MockElizaAction:
    """Fake Eliza action for testing."""
    called_with: list = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.called_with = []

    def execute(self, payload: dict[str, Any], **kwargs: Any) -> dict:
        self.called_with.append(payload)
        return {"status": "executed"}


# ────────────────────────────────────────────────────────────────────

class TestPlimsollElizaAction:
    def test_allows_clean_execution(self) -> None:
        fw = _make_firewall()
        inner = _MockElizaAction()
        action = PlimsollElizaAction(firewall=fw, inner_action=inner)

        result = action.execute({"to": "0xAAA", "amount": 1.0})
        assert result == {"status": "executed"}
        assert len(inner.called_with) == 1

    def test_blocks_velocity_breach(self) -> None:
        fw = _make_firewall(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=5.0)
        )
        inner = _MockElizaAction()
        action = PlimsollElizaAction(firewall=fw, inner_action=inner)

        result = action.execute({"to": "0xAAA", "amount": 100.0})
        assert result["plimsoll_blocked"] is True
        assert "feedback" in result
        assert len(inner.called_with) == 0  # Inner action never called

    def test_custom_on_block_callback(self) -> None:
        fw = _make_firewall(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=5.0)
        )

        def my_handler(verdict):
            return f"CUSTOM: {verdict.reason}"

        inner = _MockElizaAction()
        action = PlimsollElizaAction(
            firewall=fw, inner_action=inner, on_block=my_handler,
        )

        result = action.execute({"to": "0xAAA", "amount": 100.0})
        assert isinstance(result, str)
        assert "CUSTOM" in result

    def test_different_spend_key(self) -> None:
        fw = _make_firewall(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=5.0)
        )
        inner = _MockElizaAction()
        action = PlimsollElizaAction(
            firewall=fw, inner_action=inner, spend_key="value",
        )

        # "amount" is ignored; "value" is used and it's 0 → should pass
        result = action.execute({"to": "0xAAA", "amount": 999.0, "value": 0.0})
        assert result == {"status": "executed"}
