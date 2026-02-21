"""
Interceptor Proxy — The Choke Point.

A lightweight ASGI proxy (Starlette) that sits on localhost. The agent's
LLM routes intended JSON-RPC or REST payloads to Aegis, not directly to
the target API/blockchain RPC. Aegis evaluates, optionally signs via the
vault, and either forwards or blocks.

Deploy as::

    uvicorn aegis.proxy.interceptor:app --host 127.0.0.1 --port 8545

Compatible with any agent framework (LangChain, Eliza, AgentKit, etc.)
that can be configured to point at a custom RPC endpoint.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from aegis.firewall import AegisFirewall, AegisConfig

logger = logging.getLogger("aegis.proxy")

# Module-level firewall — configured at startup
_firewall: AegisFirewall | None = None
_upstream_url: str = ""


async def _handle_rpc(request: Request) -> JSONResponse:
    """Intercept all incoming JSON payloads, evaluate, and conditionally forward."""
    assert _firewall is not None

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "Invalid JSON payload"}, status_code=400
        )

    # Extract spend amount (heuristic: look for common fields)
    spend = 0.0
    if "value" in body:
        try:
            spend = float(body["value"])
        except (ValueError, TypeError):
            pass
    elif "params" in body and isinstance(body["params"], list):
        for param in body["params"]:
            if isinstance(param, dict) and "value" in param:
                try:
                    spend = float(param["value"])
                except (ValueError, TypeError):
                    pass
                break

    verdict = _firewall.evaluate(body, spend_amount=spend)

    if verdict.blocked:
        logger.warning("PROXY BLOCK: %s", verdict.reason)
        return JSONResponse(
            {
                "aegis_blocked": True,
                "verdict": verdict.code.value,
                "reason": verdict.reason,
                "feedback": verdict.feedback_prompt(),
            },
            status_code=403,
        )

    # Forward to upstream
    async with httpx.AsyncClient() as client:
        upstream_resp = await client.post(
            _upstream_url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30.0,
        )

    return JSONResponse(upstream_resp.json(), status_code=upstream_resp.status_code)


async def _health(request: Request) -> JSONResponse:
    assert _firewall is not None
    return JSONResponse({
        "status": "ok",
        "stats": _firewall.stats,
        "vault_keys": _firewall.vault.list_key_ids() if _firewall.vault else [],
    })


def create_proxy_app(
    upstream_url: str,
    config: AegisConfig | None = None,
) -> Starlette:
    """Create a configured Starlette ASGI app acting as the Aegis proxy."""
    global _firewall, _upstream_url

    _upstream_url = upstream_url
    _firewall = AegisFirewall(config=config or AegisConfig())

    return Starlette(
        routes=[
            Route("/", _handle_rpc, methods=["POST"]),
            Route("/health", _health, methods=["GET"]),
        ],
    )


# Default app for `uvicorn aegis.proxy.interceptor:app`
app = create_proxy_app(upstream_url="http://localhost:8546")
