"""
Interceptor Proxy — The Choke Point.

A lightweight ASGI proxy (Starlette) that sits between agents and the
blockchain. Agents point their RPC URL at Plimsoll instead of directly
at Alchemy/Infura.

Two modes:

1. **Global** (``POST /``): All traffic filtered through a single firewall
   with default config. Good for single-agent setups.

2. **Vault-aware** (``POST /v1/{vault_address}``): Each vault gets its own
   firewall configured from on-chain parameters. The agent just changes its
   RPC URL and gets protection — zero code changes.

Deploy as::

    uvicorn plimsoll.proxy.interceptor:app --host 0.0.0.0 --port 8545

Compatible with any agent framework (LangChain, Eliza, OpenClaw, AgentKit,
Automaton, etc.) that can be configured to point at a custom RPC endpoint.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.proxy.vault_config import VaultConfigCache

logger = logging.getLogger("plimsoll.proxy")

# ── Module-level state ───────────────────────────────────────

_firewall: PlimsollFirewall | None = None
_upstream_url: str = ""
_vault_cache: VaultConfigCache | None = None

# Per-vault firewall instances (lazy-created, keyed by vault address)
_vault_firewalls: dict[str, PlimsollFirewall] = {}


# ── Helpers ──────────────────────────────────────────────────

def _extract_spend(body: dict[str, Any]) -> float:
    """Extract spend amount from a JSON-RPC payload (heuristic)."""
    spend = 0.0

    # Direct value field
    if "value" in body:
        try:
            val = body["value"]
            # Handle hex-encoded wei (e.g., "0x2386f26fc10000")
            if isinstance(val, str) and val.startswith("0x"):
                spend = int(val, 16) / 1e18
            else:
                spend = float(val)
        except (ValueError, TypeError):
            pass
    # JSON-RPC params array (eth_sendTransaction)
    elif "params" in body and isinstance(body["params"], list):
        for param in body["params"]:
            if isinstance(param, dict) and "value" in param:
                try:
                    val = param["value"]
                    if isinstance(val, str) and val.startswith("0x"):
                        spend = int(val, 16) / 1e18
                    else:
                        spend = float(val)
                except (ValueError, TypeError):
                    pass
                break

    return spend


def _is_read_only(body: dict[str, Any]) -> bool:
    """Check if a JSON-RPC request is read-only (no state change)."""
    method = body.get("method", "")
    write_methods = {
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "eth_sign",
        "personal_sign",
        "eth_signTypedData",
        "eth_signTypedData_v3",
        "eth_signTypedData_v4",
    }
    return method not in write_methods


async def _forward_upstream(body: dict[str, Any]) -> JSONResponse:
    """Forward a request to the upstream RPC."""
    async with httpx.AsyncClient() as client:
        upstream_resp = await client.post(
            _upstream_url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30.0,
        )
    return JSONResponse(upstream_resp.json(), status_code=upstream_resp.status_code)


def _block_response(verdict: Any) -> JSONResponse:
    """Return a JSON 403 block response."""
    return JSONResponse(
        {
            "plimsoll_blocked": True,
            "verdict": verdict.code.value,
            "reason": verdict.reason,
            "feedback": verdict.feedback_prompt(),
        },
        status_code=403,
    )


# ── Route Handlers ───────────────────────────────────────────

async def _handle_rpc(request: Request) -> JSONResponse:
    """Global RPC handler — single firewall for all traffic."""
    assert _firewall is not None

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON payload"}, status_code=400)

    # Read-only calls pass through without evaluation
    if _is_read_only(body):
        return await _forward_upstream(body)

    spend = _extract_spend(body)
    verdict = _firewall.evaluate(body, spend_amount=spend)

    if verdict.blocked:
        logger.warning("PROXY BLOCK: %s", verdict.reason)
        return _block_response(verdict)

    return await _forward_upstream(body)


async def _handle_vault_rpc(request: Request) -> JSONResponse:
    """Vault-aware RPC handler — per-vault firewall from on-chain config.

    URL: POST /v1/{vault_address}

    The agent just points its RPC URL to:
        https://rpc.plimsoll.network/v1/0xYourVaultAddress

    The proxy reads the vault's on-chain parameters and configures a
    firewall instance automatically. Zero code changes on the agent side.
    """
    vault_address = request.path_params.get("vault_address", "")

    if not vault_address or not vault_address.startswith("0x") or len(vault_address) != 42:
        return JSONResponse(
            {"error": "Invalid vault address. Use /v1/0x..."},
            status_code=400,
        )

    try:
        body: dict[str, Any] = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON payload"}, status_code=400)

    # Read-only calls pass through without evaluation
    if _is_read_only(body):
        return await _forward_upstream(body)

    # Get or create per-vault firewall
    firewall = await _get_vault_firewall(vault_address)

    spend = _extract_spend(body)
    verdict = firewall.evaluate(body, spend_amount=spend)

    if verdict.blocked:
        logger.warning("VAULT PROXY BLOCK [%s]: %s", vault_address[:10], verdict.reason)
        return _block_response(verdict)

    return await _forward_upstream(body)


async def _get_vault_firewall(vault_address: str) -> PlimsollFirewall:
    """Get or create a firewall instance for a specific vault."""
    key = vault_address.lower()

    if key in _vault_firewalls:
        # Check if we should refresh config (piggyback on VaultConfigCache TTL)
        return _vault_firewalls[key]

    # Load config from chain
    if _vault_cache:
        config = await _vault_cache.get(vault_address)
    else:
        config = PlimsollConfig()

    firewall = PlimsollFirewall(config=config)
    _vault_firewalls[key] = firewall
    logger.info("Created firewall for vault %s", vault_address[:10])

    return firewall


async def _health(request: Request) -> JSONResponse:
    """Health check endpoint."""
    stats = {}
    if _firewall:
        stats["global"] = _firewall.stats
    stats["vaults_active"] = len(_vault_firewalls)
    stats["cache_entries"] = len(_vault_cache._cache) if _vault_cache else 0

    return JSONResponse({
        "status": "ok",
        "upstream": _upstream_url,
        "stats": stats,
    })


# ── App Factory ──────────────────────────────────────────────

def create_proxy_app(
    upstream_url: str,
    config: PlimsollConfig | None = None,
) -> Starlette:
    """Create a configured Starlette ASGI app acting as the Plimsoll proxy.

    The app serves two route families:

    - ``POST /`` — Global firewall (backward compatible)
    - ``POST /v1/{vault_address}`` — Per-vault firewall from on-chain config
    - ``GET /health`` — Health check
    """
    global _firewall, _upstream_url, _vault_cache

    _upstream_url = upstream_url
    _firewall = PlimsollFirewall(config=config or PlimsollConfig())
    _vault_cache = VaultConfigCache(rpc_url=upstream_url)

    return Starlette(
        routes=[
            Route("/", _handle_rpc, methods=["POST"]),
            Route("/v1/{vault_address}", _handle_vault_rpc, methods=["POST"]),
            Route("/health", _health, methods=["GET"]),
        ],
    )


# Default app for `uvicorn plimsoll.proxy.interceptor:app`
_default_upstream = os.environ.get(
    "PLIMSOLL_UPSTREAM_RPC",
    "https://mainnet.base.org",
)
app = create_proxy_app(upstream_url=_default_upstream)
