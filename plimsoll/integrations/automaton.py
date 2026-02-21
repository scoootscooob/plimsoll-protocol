"""
plimsoll.integrations.automaton — Drop-in Plimsoll wallet for the Automaton (Conway)
agent framework.

A developer simply changes::

    wallet = StandardWallet(private_key="0x...", rpc_url="https://...")

to::

    from plimsoll.integrations.automaton import PlimsollAutomatonWallet

    wallet = PlimsollAutomatonWallet(
        private_key="0x...",
        rpc_url="https://...",
        max_daily_spend=1000,          # USD/day budget
    )

Every outgoing transaction is piped through the 7-engine Plimsoll firewall
*before* execution.  If the firewall blocks, the wallet returns a dict
with ``plimsoll_blocked: True`` and a cognitive feedback prompt so the LLM
agent can pivot strategy instead of crashing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.verdict import Verdict

logger = logging.getLogger("plimsoll.integrations.automaton")


@dataclass
class PlimsollAutomatonWallet:
    """Composition-based Plimsoll wrapper around an Automaton ``Wallet``.

    *Why composition, not inheritance?*  Automaton's ``Wallet`` class
    hierarchy may change across versions.  Composition isolates us from
    upstream churn while preserving the full ``execute()`` interface.
    """

    private_key: str
    rpc_url: str
    max_daily_spend: float = 1000.0
    plimsoll_config: Optional[PlimsollConfig] = None

    # ── Internal state (set in __post_init__) ─────────────────────
    _firewall: PlimsollFirewall = field(init=False, repr=False)
    _inner_wallet: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        # Build firewall config — translate daily budget → velocity
        config = self.plimsoll_config or PlimsollConfig(
            velocity=CapitalVelocityConfig(
                v_max=self.max_daily_spend / 86400.0,
                window_seconds=300.0,
            ),
        )
        self._firewall = PlimsollFirewall(config=config)
        self._firewall.vault.store("agent_wallet", self.private_key)

        # Lazy-import Automaton to avoid hard dependency
        try:
            from automaton.wallet import Wallet  # type: ignore[import-untyped]
            self._inner_wallet = Wallet(
                private_key=self.private_key,
                rpc_url=self.rpc_url,
            )
        except ImportError:
            raise ImportError(
                "plimsoll[automaton] requires the 'automaton' package.  "
                "Install with: pip install plimsoll-protocol[automaton]"
            )

    # ── Public API ────────────────────────────────────────────────

    def execute(self, payload: dict[str, Any], **kwargs: Any) -> Any:
        """Execute a transaction through Plimsoll before forwarding to Automaton."""
        spend = float(payload.get("value", payload.get("amount", 0)))
        verdict = self._firewall.evaluate(payload, spend_amount=spend)

        if verdict.blocked:
            logger.warning("PLIMSOLL BLOCK in AutomatonWallet: %s", verdict.reason)
            return {
                "plimsoll_blocked": True,
                "verdict": verdict.code.value,
                "reason": verdict.reason,
                "feedback": verdict.feedback_prompt(),
            }

        return self._inner_wallet.execute(payload, **kwargs)

    @property
    def firewall(self) -> PlimsollFirewall:
        """Expose the underlying firewall for introspection / stats."""
        return self._firewall
