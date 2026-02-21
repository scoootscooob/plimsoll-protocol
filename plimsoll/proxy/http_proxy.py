"""
plimsoll.proxy.http_proxy — Web2 Egress Gateway (Python-side).

A Starlette-based HTTP forward proxy that intercepts outgoing API calls
from AI agents and applies Plimsoll CapitalVelocity PID enforcement.

Usage (Python-only deployments)::

    HTTP_PROXY=http://127.0.0.1:8080
    uvicorn plimsoll.proxy.http_proxy:create_http_proxy_app --port 8080

For the full Rust-based TLS proxy, see ``plimsoll-rpc/src/http_proxy.rs``.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.intent import IntentAction, IntentProtocol, NormalizedIntent

logger = logging.getLogger("plimsoll.proxy.http")

# ── Cost extraction rules ─────────────────────────────────────────

API_COST_MAP: dict[str, dict[str, dict[str, Any]]] = {
    "api.stripe.com": {
        "/v1/charges":         {"field": "amount", "divisor": 100.0},
        "/v1/payment_intents": {"field": "amount", "divisor": 100.0},
    },
    "api.openai.com": {
        "/v1/chat/completions": {"fixed_usd": 0.03},
    },
    "api.anthropic.com": {
        "/v1/messages": {"fixed_usd": 0.05},
    },
}


def extract_api_cost(
    domain: str,
    path: str,
    body: Optional[dict[str, Any]] = None,
    cost_map: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
) -> Optional[float]:
    """Extract USD cost from an HTTP request using the cost map.

    Returns ``None`` if the domain/path is not governed.
    """
    cmap = cost_map or API_COST_MAP
    domain_rules = cmap.get(domain)
    if domain_rules is None:
        return None

    for prefix, rule in domain_rules.items():
        if not path.startswith(prefix):
            continue

        # Fixed per-request cost
        if "fixed_usd" in rule:
            return float(rule["fixed_usd"])

        # Extract from body field
        field = rule.get("field")
        if field and body and field in body:
            raw = float(body[field])
            divisor = float(rule.get("divisor", 1.0))
            return raw / divisor

        # Field specified but not in body
        return rule.get("fixed_usd", 0.0)

    return None


def evaluate_http_request(
    firewall: PlimsollFirewall,
    method: str,
    url: str,
    body: Optional[dict[str, Any]] = None,
) -> tuple[bool, str, float]:
    """Evaluate an HTTP API request through the Plimsoll firewall.

    Returns ``(allowed, reason, cost_usd)``.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    path = parsed.path or "/"

    cost_usd = extract_api_cost(domain, path, body) or 0.0

    intent = NormalizedIntent(
        protocol=IntentProtocol.HTTP,
        action=IntentAction.API_CHARGE,
        capital_at_risk_usd=cost_usd,
        target=url,
        amount_usd=cost_usd,
        function=f"{method.upper()} {url}",
    )

    verdict = firewall.evaluate_intent(intent)
    return verdict.allowed, verdict.reason if verdict.blocked else "allowed", cost_usd
