"""
Python SDK bridge for the Plimsoll V5 Smart Vault (ERC-4337).

Manages the on-chain PlimsollVault: deposit, session keys, execution,
physics module configuration, and PoBR attestation queries.

    from plimsoll.vault import SmartVaultClient, SmartVaultConfig

    vault = SmartVaultClient(config=SmartVaultConfig(
        vault_address="0xABC...",
        rpc_url="https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY",
        owner_key="0x...",  # Human treasury private key
    ))

    # Issue a session key to your AI agent
    vault.issue_session_key(
        agent_address="0xAGENT...",
        duration_hours=24,
        daily_budget_eth=1.0,
        max_single_eth=0.5,
    )
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("plimsoll")

# ABI fragments for PlimsollVault interactions
VAULT_ABI = [
    {
        "name": "deposit",
        "type": "function",
        "inputs": [],
        "outputs": [],
        "stateMutability": "payable",
    },
    {
        "name": "withdraw",
        "type": "function",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "issueSessionKey",
        "type": "function",
        "inputs": [
            {"name": "agent", "type": "address"},
            {"name": "durationSeconds", "type": "uint256"},
            {"name": "maxSingleAmount_", "type": "uint256"},
            {"name": "dailyBudget_", "type": "uint256"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "revokeSessionKey",
        "type": "function",
        "inputs": [{"name": "agent", "type": "address"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "execute",
        "type": "function",
        "inputs": [
            {"name": "target", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "data", "type": "bytes"},
        ],
        "outputs": [{"name": "", "type": "bytes"}],
        "stateMutability": "nonpayable",
    },
    {
        "name": "setModules",
        "type": "function",
        "inputs": [
            {"name": "velocity_", "type": "address"},
            {"name": "whitelist_", "type": "address"},
            {"name": "drawdown_", "type": "address"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "emergencyLockVault",
        "type": "function",
        "inputs": [],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "vaultBalance",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
    },
    {
        "name": "isSessionActive",
        "type": "function",
        "inputs": [{"name": "agent", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
    },
    {
        "name": "getSessionKey",
        "type": "function",
        "inputs": [{"name": "agent", "type": "address"}],
        "outputs": [
            {
                "name": "",
                "type": "tuple",
                "components": [
                    {"name": "active", "type": "bool"},
                    {"name": "expiresAt", "type": "uint256"},
                    {"name": "maxSingleAmount", "type": "uint256"},
                    {"name": "dailyBudget", "type": "uint256"},
                    {"name": "spentToday", "type": "uint256"},
                    {"name": "dayStart", "type": "uint256"},
                ],
            }
        ],
        "stateMutability": "view",
    },
]


@dataclass
class SmartVaultConfig:
    """Configuration for the Smart Vault Python client."""

    vault_address: str = ""
    rpc_url: str = ""
    owner_key: str = ""          # Private key for owner operations
    agent_key: str = ""          # Private key for agent (session key) operations
    chain_id: int = 11155111     # Default: Sepolia


@dataclass
class SmartVaultClient:
    """Python SDK for managing an on-chain PlimsollVault.

    Provides high-level methods for vault operations:
        - ``deposit()`` / ``withdraw()``
        - ``issue_session_key()`` / ``revoke_session_key()``
        - ``execute()`` — agent executes a tx through the vault
        - ``set_modules()`` — configure physics modules
        - ``get_balance()`` / ``is_session_active()``
    """

    config: SmartVaultConfig = field(default_factory=SmartVaultConfig)
    _w3: Any = field(default=None, init=False, repr=False)
    _vault: Any = field(default=None, init=False, repr=False)

    def _get_web3(self) -> Any:
        """Lazy-init Web3 connection."""
        if self._w3 is None:
            from web3 import Web3
            self._w3 = Web3(Web3.HTTPProvider(self.config.rpc_url))
        return self._w3

    def _get_contract(self) -> Any:
        """Lazy-init contract instance."""
        if self._vault is None:
            w3 = self._get_web3()
            self._vault = w3.eth.contract(
                address=w3.to_checksum_address(self.config.vault_address),
                abi=VAULT_ABI,
            )
        return self._vault

    def _send_owner_tx(self, fn: Any, value: int = 0) -> str:
        """Build, sign, and send a transaction as the vault owner."""
        from eth_account import Account
        w3 = self._get_web3()
        acct = Account.from_key(self.config.owner_key)
        tx = fn.build_transaction({
            "from": acct.address,
            "value": value,
            "nonce": w3.eth.get_transaction_count(acct.address),
            "gas": 500000,
            "maxFeePerGas": w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": w3.to_wei(1, "gwei"),
            "chainId": self.config.chain_id,
        })
        signed = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        logger.info("TX sent: %s", tx_hash.hex())
        return tx_hash.hex()

    # ── Owner operations ─────────────────────────────────────────

    def deposit(self, amount_eth: float) -> str:
        """Deposit ETH into the vault."""
        w3 = self._get_web3()
        contract = self._get_contract()
        value_wei = w3.to_wei(amount_eth, "ether")
        return self._send_owner_tx(contract.functions.deposit(), value=value_wei)

    def withdraw(self, to: str, amount_eth: float) -> str:
        """Withdraw ETH from the vault to a specified address."""
        w3 = self._get_web3()
        contract = self._get_contract()
        value_wei = w3.to_wei(amount_eth, "ether")
        return self._send_owner_tx(
            contract.functions.withdraw(
                w3.to_checksum_address(to), value_wei
            )
        )

    def issue_session_key(
        self,
        agent_address: str,
        duration_hours: float = 24.0,
        daily_budget_eth: float = 1.0,
        max_single_eth: float = 0.5,
    ) -> str:
        """Issue a scoped session key to an AI agent."""
        w3 = self._get_web3()
        contract = self._get_contract()
        return self._send_owner_tx(
            contract.functions.issueSessionKey(
                w3.to_checksum_address(agent_address),
                int(duration_hours * 3600),
                w3.to_wei(max_single_eth, "ether"),
                w3.to_wei(daily_budget_eth, "ether"),
            )
        )

    def revoke_session_key(self, agent_address: str) -> str:
        """Revoke an agent's session key immediately."""
        w3 = self._get_web3()
        contract = self._get_contract()
        return self._send_owner_tx(
            contract.functions.revokeSessionKey(
                w3.to_checksum_address(agent_address)
            )
        )

    def set_modules(
        self,
        velocity: str = "0x0000000000000000000000000000000000000000",
        whitelist: str = "0x0000000000000000000000000000000000000000",
        drawdown: str = "0x0000000000000000000000000000000000000000",
    ) -> str:
        """Configure physics modules on the vault."""
        w3 = self._get_web3()
        contract = self._get_contract()
        return self._send_owner_tx(
            contract.functions.setModules(
                w3.to_checksum_address(velocity),
                w3.to_checksum_address(whitelist),
                w3.to_checksum_address(drawdown),
            )
        )

    def emergency_lock(self) -> str:
        """Emergency lock — freeze all session keys and execution."""
        contract = self._get_contract()
        return self._send_owner_tx(contract.functions.emergencyLockVault())

    # ── View functions ───────────────────────────────────────────

    def get_balance(self) -> float:
        """Get the vault's ETH balance."""
        w3 = self._get_web3()
        contract = self._get_contract()
        balance_wei = contract.functions.vaultBalance().call()
        return float(w3.from_wei(balance_wei, "ether"))

    def is_session_active(self, agent_address: str) -> bool:
        """Check if an agent's session key is active."""
        w3 = self._get_web3()
        contract = self._get_contract()
        return contract.functions.isSessionActive(
            w3.to_checksum_address(agent_address)
        ).call()

    def get_session_info(self, agent_address: str) -> dict[str, Any]:
        """Get session key details for an agent."""
        w3 = self._get_web3()
        contract = self._get_contract()
        result = contract.functions.getSessionKey(
            w3.to_checksum_address(agent_address)
        ).call()
        return {
            "active": result[0],
            "expires_at": result[1],
            "max_single_wei": result[2],
            "daily_budget_wei": result[3],
            "spent_today_wei": result[4],
            "day_start": result[5],
        }
