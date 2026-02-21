"""
plimsoll.integrations.langchain — ``@plimsoll_tool`` decorator for LangChain.

Slap this decorator on top of any existing LangChain ``@tool`` to
automatically pipe inputs through the 7 Plimsoll math engines.  If Plimsoll
blocks, the tool returns the cognitive feedback prompt as a string (the
LLM reads it and pivots strategy).

Usage::

    from langchain.tools import tool
    from plimsoll.integrations.langchain import plimsoll_tool

    @tool
    @plimsoll_tool(firewall, spend_key="amount")
    def transfer_tokens(payload: dict) -> str:
        \"\"\"Send tokens to an address.\"\"\"
        return execute_transfer(payload)
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional

from plimsoll.firewall import PlimsollFirewall
from plimsoll.verdict import Verdict

logger = logging.getLogger("plimsoll.integrations.langchain")


def plimsoll_tool(
    firewall: PlimsollFirewall,
    *,
    spend_key: str = "amount",
    on_block: Optional[Callable[[Verdict], str]] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that wraps a function with Plimsoll enforcement.

    Parameters
    ----------
    firewall : PlimsollFirewall
        Pre-configured firewall instance.
    spend_key : str
        Key in the payload dict that holds the spend amount.
    on_block : callable, optional
        Custom handler called with the blocking ``Verdict``.
        Must return a string to be sent back to the LLM.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # ── Extract payload ──────────────────────────────────
            if args and isinstance(args[0], dict):
                payload: dict[str, Any] = args[0]
            elif kwargs:
                payload = dict(kwargs)
            else:
                # Cannot evaluate — pass through
                return fn(*args, **kwargs)

            # ── Evaluate ─────────────────────────────────────────
            spend = float(payload.get(spend_key, 0))
            verdict = firewall.evaluate(payload, spend_amount=spend)

            if verdict.blocked:
                logger.warning(
                    "PLIMSOLL BLOCK in LangChain tool '%s': %s",
                    fn.__name__,
                    verdict.reason,
                )
                if on_block is not None:
                    return on_block(verdict)
                return verdict.feedback_prompt()

            return fn(*args, **kwargs)

        # Expose firewall for introspection
        wrapper.plimsoll_firewall = firewall  # type: ignore[attr-defined]
        return wrapper

    return decorator
