"""
plimsoll.integrations.openclaw — Plimsoll-wrapped DeFi tools for OpenClaw's
Tool Registry.

OpenClaw uses a strict Tool Registry for its LLM orchestrator.  Instead
of giving the LLM the raw ``send_transaction`` tool, we give it an
Plimsoll-wrapped version.

**The Secret Sauce**: If Plimsoll blocks the trade, the tool catches the
block and returns it as a *successfully executed string*::

    "[PLIMSOLL SYSTEM OVERRIDE]: Blocked. Unsafe slippage. Do not retry."

This keeps the agent **alive** so it can pivot strategy rather than
crashing on an unhandled exception.

Usage::

    from plimsoll.integrations.openclaw import PlimsollDeFiTools

    tools = PlimsollDeFiTools(firewall=firewall)
    tools.register(name="swap",     fn=my_swap_fn,     spend_key="amount")
    tools.register(name="transfer", fn=my_transfer_fn, spend_key="value")

    # Give wrapped tools to OpenClaw
    openclaw_agent.register_tools(tools.get_tool_definitions())
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from plimsoll.firewall import PlimsollFirewall
from plimsoll.verdict import Verdict

logger = logging.getLogger("plimsoll.integrations.openclaw")


@dataclass
class PlimsollDeFiTools:
    """Registry of DeFi tools wrapped with Plimsoll enforcement."""

    firewall: PlimsollFirewall

    # name → {name, fn, original_fn, description, spend_key}
    _tools: dict[str, dict[str, Any]] = field(
        default_factory=dict, init=False, repr=False,
    )

    # ── Registration ──────────────────────────────────────────────

    def register(
        self,
        name: str,
        fn: Callable[..., Any],
        spend_key: str = "amount",
        description: str = "",
    ) -> None:
        """Register a DeFi tool with Plimsoll enforcement."""

        @functools.wraps(fn)
        def wrapped_tool(payload: dict[str, Any], **kwargs: Any) -> Any:
            spend = float(payload.get(spend_key, 0))
            verdict = self.firewall.evaluate(payload, spend_amount=spend)

            if verdict.blocked:
                logger.warning(
                    "PLIMSOLL BLOCK in OpenClaw tool '%s': %s", name, verdict.reason,
                )
                # Return string override — keeps the agent alive to pivot
                return (
                    f"[PLIMSOLL SYSTEM OVERRIDE]: Blocked. {verdict.reason}. "
                    f"Do not retry. Pivot strategy."
                )

            return fn(payload, **kwargs)

        self._tools[name] = {
            "name": name,
            "fn": wrapped_tool,
            "original_fn": fn,
            "description": description or fn.__doc__ or "",
            "spend_key": spend_key,
        }

    # ── Query ─────────────────────────────────────────────────────

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Return tool definitions compatible with OpenClaw's registry."""
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "function": tool["fn"],
            }
            for tool in self._tools.values()
        ]

    def get_tool(self, name: str) -> Optional[Callable[..., Any]]:
        """Get a wrapped tool by name, or ``None``."""
        tool = self._tools.get(name)
        return tool["fn"] if tool else None
