"""
plimsoll.integrations.eliza — Plimsoll wrapper for the Eliza agent framework.

Eliza uses an action-based architecture where ``Action`` classes expose
an ``execute(payload, **kwargs)`` method.  ``PlimsollElizaAction`` wraps an
inner action and gates execution behind the Plimsoll firewall.

Usage::

    from plimsoll.integrations.eliza import PlimsollElizaAction

    safe_transfer = PlimsollElizaAction(
        firewall=firewall,
        inner_action=my_transfer_action,
        spend_key="amount",
    )
    result = safe_transfer.execute({"to": "0x...", "amount": 500})
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from plimsoll.firewall import PlimsollFirewall
from plimsoll.verdict import Verdict

logger = logging.getLogger("plimsoll.integrations.eliza")


@dataclass
class PlimsollElizaAction:
    """Wraps an Eliza ``Action`` with Plimsoll enforcement.

    On block, returns a dict with ``plimsoll_blocked: True`` and the
    cognitive feedback prompt, or delegates to a custom ``on_block``
    callback.
    """

    firewall: PlimsollFirewall
    inner_action: Any           # Eliza Action class instance
    spend_key: str = "amount"
    on_block: Optional[Callable[[Verdict], Any]] = None

    def execute(self, payload: dict[str, Any], **kwargs: Any) -> Any:
        """Execute the action through Plimsoll firewall."""
        spend = float(payload.get(self.spend_key, 0))
        verdict = self.firewall.evaluate(payload, spend_amount=spend)

        if verdict.blocked:
            logger.warning(
                "PLIMSOLL BLOCK in Eliza action: %s", verdict.reason,
            )
            if self.on_block is not None:
                return self.on_block(verdict)
            return {
                "plimsoll_blocked": True,
                "verdict": verdict.code.value,
                "reason": verdict.reason,
                "feedback": verdict.feedback_prompt(),
            }

        return self.inner_action.execute(payload, **kwargs)
