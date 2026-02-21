"""
Python SDK bridge for the Aegis V4 RPC Proxy.

Instead of connecting directly to Alchemy/Infura, the agent points its
web3 provider at the Aegis RPC Proxy. This module makes it seamless:

    proxy = AegisRPCProxy(config=RPCProxyConfig(
        proxy_url="https://rpc.aegis.network",
    ))
    w3 = proxy.get_web3()  # Drop-in replacement for Web3(HTTPProvider(...))

Every eth_sendTransaction is automatically:
    1. Simulated in revm (pre-flight check)
    2. MEV-shielded via Flashbots Protect
    3. Charged a 1-2 bps protocol fee
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("aegis")


@dataclass
class RPCProxyConfig:
    """Configuration for the Aegis RPC Proxy client."""

    proxy_url: str = "http://localhost:8545"
    api_key: str = ""
    timeout_seconds: float = 30.0


@dataclass
class AegisRPCProxy:
    """Python client for the Aegis V4 RPC Proxy.

    Usage::

        from aegis.vault import AegisRPCProxy, RPCProxyConfig

        proxy = AegisRPCProxy(config=RPCProxyConfig(
            proxy_url="https://rpc.aegis.network",
            api_key="your-api-key",
        ))

        # Option A: Get a Web3 instance that routes through Aegis
        w3 = proxy.get_web3()

        # Option B: Manual JSON-RPC call
        result = proxy.send_rpc("eth_blockNumber", [])
    """

    config: RPCProxyConfig = field(default_factory=RPCProxyConfig)
    _request_id: int = field(default=0, init=False, repr=False)

    def get_web3(self) -> Any:
        """Return a Web3 instance connected to the Aegis RPC Proxy.

        Requires: ``pip install web3``
        """
        from web3 import Web3

        url = self.config.proxy_url
        if self.config.api_key:
            url = f"{url}?key={self.config.api_key}"

        w3 = Web3(Web3.HTTPProvider(
            url,
            request_kwargs={"timeout": self.config.timeout_seconds},
        ))
        logger.info("Web3 connected to Aegis RPC Proxy at %s", self.config.proxy_url)
        return w3

    def send_rpc(self, method: str, params: list[Any]) -> Any:
        """Send a raw JSON-RPC request to the Aegis proxy.

        Returns the 'result' field from the response, or raises on error.
        """
        import requests

        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": self._request_id,
        }

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        resp = requests.post(
            self.config.proxy_url,
            json=payload,
            headers=headers,
            timeout=self.config.timeout_seconds,
        )
        resp.raise_for_status()

        data = resp.json()
        if "error" in data and data["error"] is not None:
            error = data["error"]
            msg = error.get("message", "Unknown RPC error")
            raise RuntimeError(f"Aegis RPC error: {msg}")

        return data.get("result")

    def health_check(self) -> bool:
        """Check if the Aegis RPC Proxy is reachable."""
        import requests
        try:
            resp = requests.get(
                f"{self.config.proxy_url}/health",
                timeout=5.0,
            )
            return resp.status_code == 200
        except Exception:
            return False
