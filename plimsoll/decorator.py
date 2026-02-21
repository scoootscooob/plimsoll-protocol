"""
@with_plimsoll_firewall — Drop-in decorator for agent action functions.

Usage::

    from plimsoll import with_plimsoll_firewall, PlimsollFirewall

    firewall = PlimsollFirewall()

    @with_plimsoll_firewall(firewall)
    def send_transaction(payload: dict) -> dict:
        # This only runs if Plimsoll allows it
        return call_blockchain_api(payload)
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from plimsoll.firewall import PlimsollFirewall
from plimsoll.verdict import Verdict

logger = logging.getLogger("plimsoll")


def with_plimsoll_firewall(
    firewall: PlimsollFirewall,
    *,
    spend_key: str = "amount",
    on_block: Callable[[Verdict], Any] | None = None,
) -> Callable:
    """Decorator factory that wraps an agent action with the Plimsoll firewall.

    Args:
        firewall: The PlimsollFirewall instance to evaluate against.
        spend_key: The key in the payload dict that contains the spend amount.
        on_block: Optional callback invoked when a payload is blocked.
                  Receives the Verdict. Its return value (if any) is returned
                  to the caller in place of the wrapped function's result.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(payload: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            spend = float(payload.get(spend_key, 0))
            verdict = firewall.evaluate(payload, spend_amount=spend)

            if verdict.blocked:
                logger.warning(
                    "[PLIMSOLL] Blocked call to %s: %s", fn.__name__, verdict.reason
                )
                feedback = verdict.feedback_prompt()
                if on_block:
                    return on_block(verdict)
                return {
                    "plimsoll_blocked": True,
                    "verdict": verdict.code.value,
                    "reason": verdict.reason,
                    "feedback": feedback,
                }

            return fn(payload, *args, **kwargs)

        # Expose firewall reference for introspection
        wrapper.plimsoll_firewall = firewall  # type: ignore[attr-defined]
        return wrapper

    return decorator
