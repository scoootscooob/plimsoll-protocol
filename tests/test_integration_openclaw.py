"""Tests for the ``PlimsollDeFiTools`` OpenClaw integration."""

from __future__ import annotations

import pytest

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.integrations.openclaw import PlimsollDeFiTools


def _make_firewall(**kwargs: object) -> PlimsollFirewall:
    return PlimsollFirewall(config=PlimsollConfig(**kwargs))


# ────────────────────────────────────────────────────────────────────

class TestPlimsollDeFiTools:

    def test_allows_clean_call(self) -> None:
        fw = _make_firewall()
        tools = PlimsollDeFiTools(firewall=fw)

        def swap(payload, **kw):
            return {"status": "swapped"}

        tools.register(name="swap", fn=swap, spend_key="amount")
        result = tools.get_tool("swap")({"token": "ETH", "amount": 1.0})
        assert result == {"status": "swapped"}

    def test_block_returns_override_string(self) -> None:
        fw = _make_firewall(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=5.0),
        )
        tools = PlimsollDeFiTools(firewall=fw)

        def swap(payload, **kw):
            return {"status": "swapped"}

        tools.register(name="swap", fn=swap, spend_key="amount")
        result = tools.get_tool("swap")({"token": "ETH", "amount": 100.0})
        assert isinstance(result, str)
        assert "[PLIMSOLL SYSTEM OVERRIDE]" in result
        assert "Do not retry" in result

    def test_preserves_function_metadata(self) -> None:
        fw = _make_firewall()
        tools = PlimsollDeFiTools(firewall=fw)

        def my_swap_function(payload, **kw):
            """Execute a swap."""
            return "ok"

        tools.register(name="swap", fn=my_swap_function)
        wrapped = tools.get_tool("swap")
        assert wrapped.__name__ == "my_swap_function"

    def test_get_tool_definitions_format(self) -> None:
        fw = _make_firewall()
        tools = PlimsollDeFiTools(firewall=fw)

        tools.register(name="swap", fn=lambda p: "ok", description="Swap tokens")
        tools.register(name="transfer", fn=lambda p: "ok", description="Send tokens")

        defs = tools.get_tool_definitions()
        assert len(defs) == 2
        names = {d["name"] for d in defs}
        assert names == {"swap", "transfer"}
        assert all("function" in d for d in defs)
        assert all("description" in d for d in defs)

    def test_multiple_tools_independent(self) -> None:
        """Each tool evaluates spend independently."""
        fw = _make_firewall(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=50.0),
        )
        tools = PlimsollDeFiTools(firewall=fw)

        tools.register(name="cheap", fn=lambda p: "ok", spend_key="amount")
        tools.register(name="expensive", fn=lambda p: "ok", spend_key="value")

        # "cheap" uses amount=1.0 → OK
        r1 = tools.get_tool("cheap")({"amount": 1.0})
        assert r1 == "ok"

        # "expensive" uses value=999.0 → blocked
        r2 = tools.get_tool("expensive")({"value": 999.0})
        assert isinstance(r2, str)
        assert "[PLIMSOLL SYSTEM OVERRIDE]" in r2

    def test_get_tool_returns_none_for_unknown(self) -> None:
        fw = _make_firewall()
        tools = PlimsollDeFiTools(firewall=fw)
        assert tools.get_tool("nonexistent") is None
