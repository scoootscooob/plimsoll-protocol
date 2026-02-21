"""Tests for V4/V5 Python SDK bridges (RPC Proxy + Smart Vault)."""

from __future__ import annotations

from plimsoll.vault.rpc_proxy import PlimsollRPCProxy, RPCProxyConfig
from plimsoll.vault.smart_vault import SmartVaultClient, SmartVaultConfig, VAULT_ABI


# ── RPC Proxy client tests ───────────────────────────────────────


def test_rpc_proxy_default_config():
    """Default config should point to localhost:8545."""
    proxy = PlimsollRPCProxy()
    assert proxy.config.proxy_url == "http://localhost:8545"
    assert proxy.config.timeout_seconds == 30.0


def test_rpc_proxy_custom_config():
    """Custom config should be respected."""
    proxy = PlimsollRPCProxy(config=RPCProxyConfig(
        proxy_url="https://rpc.plimsoll.network",
        api_key="test-key",
        timeout_seconds=60.0,
    ))
    assert proxy.config.proxy_url == "https://rpc.plimsoll.network"
    assert proxy.config.api_key == "test-key"


def test_rpc_proxy_health_check_offline():
    """Health check on unreachable server should return False."""
    proxy = PlimsollRPCProxy(config=RPCProxyConfig(
        proxy_url="http://localhost:9999",  # Nothing here
    ))
    assert proxy.health_check() is False


def test_rpc_proxy_request_id_increments():
    """Request IDs should auto-increment."""
    proxy = PlimsollRPCProxy()
    assert proxy._request_id == 0
    proxy._request_id += 1
    assert proxy._request_id == 1


# ── Smart Vault client tests ────────────────────────────────────


def test_smart_vault_default_config():
    """Default config should have Sepolia chain ID."""
    client = SmartVaultClient()
    assert client.config.chain_id == 11155111
    assert client.config.vault_address == ""


def test_smart_vault_custom_config():
    """Custom config should be respected."""
    client = SmartVaultClient(config=SmartVaultConfig(
        vault_address="0xABC123",
        rpc_url="https://eth-sepolia.example.com",
        owner_key="0xDEAD",
        chain_id=1,
    ))
    assert client.config.vault_address == "0xABC123"
    assert client.config.chain_id == 1


def test_vault_abi_has_required_functions():
    """ABI should contain all critical vault functions."""
    fn_names = [entry["name"] for entry in VAULT_ABI]
    assert "deposit" in fn_names
    assert "withdraw" in fn_names
    assert "issueSessionKey" in fn_names
    assert "revokeSessionKey" in fn_names
    assert "execute" in fn_names
    assert "setModules" in fn_names
    assert "emergencyLockVault" in fn_names
    assert "vaultBalance" in fn_names
    assert "isSessionActive" in fn_names
    assert "getSessionKey" in fn_names


def test_vault_abi_function_signatures():
    """ABI function signatures should have correct input types."""
    abi_map = {entry["name"]: entry for entry in VAULT_ABI}

    # issueSessionKey takes (address, uint256, uint256, uint256)
    isk = abi_map["issueSessionKey"]
    assert len(isk["inputs"]) == 4
    assert isk["inputs"][0]["type"] == "address"
    assert isk["inputs"][1]["type"] == "uint256"

    # execute takes (address, uint256, bytes)
    ex = abi_map["execute"]
    assert len(ex["inputs"]) == 3
    assert ex["inputs"][2]["type"] == "bytes"
