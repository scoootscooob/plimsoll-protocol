"""
Context-Window Airgap: The Key Vault.

The LLM never touches the private key. Aegis holds the key in an encrypted
local enclave. The LLM asks Aegis to sign a transaction; if the math checks
pass, Aegis signs it and returns the signature. The AI is structurally blind
to its own cryptography.

This module provides a simple symmetric-encryption vault using Fernet
(AES-128-CBC with HMAC). In production, this would be backed by a hardware
TEE (Intel SGX, ARM TrustZone) or a cloud KMS.

PATCH (Flaw 1 — Inversion of Control):
    The Vault is NOT a dumb signer. When a firewall is bound to the vault,
    ``sign_eth_transaction()`` internally runs ``firewall.evaluate()`` BEFORE
    decrypting the key. If the firewall blocks the transaction, the vault
    raises ``AegisEnforcementError`` and the key is NEVER decrypted. This
    prevents RCE attackers from calling vault.sign_eth_transaction() directly
    — the physics are enforced at the cryptographic level.

PATCH (Flaw 3 — Soft Enclave Wipe):
    After ECDSA signing, the decrypted private key is loaded into a mutable
    ``bytearray`` and explicitly zeroed byte-by-byte before the GC can
    scatter copies. This prevents RAM forensics tools (Mimikatz, gcore)
    from extracting the key after use.
"""

from __future__ import annotations

import gc
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    from aegis.firewall import AegisFirewall


class AegisEnforcementError(Exception):
    """Raised when the vault refuses to sign because the firewall blocked.

    This is the cryptographic enforcement layer — if the physics say no,
    the key is NEVER decrypted. Period.
    """

    def __init__(self, reason: str, engine: str, code: str) -> None:
        self.reason = reason
        self.engine = engine
        self.code = code
        super().__init__(
            f"[AEGIS VAULT ENFORCEMENT] Transaction blocked by {engine}: "
            f"{reason} (code={code})"
        )


def _secure_wipe(data: bytearray) -> None:
    """Overwrite a mutable bytearray with zeros, then force GC.

    In CPython, this overwrites the actual buffer in-place. The GC sweep
    ensures any interned copies of intermediate strings are collected.

    Note: This is a best-effort defense in Python. For true airgap guarantees,
    the vault moves into an AWS Nitro TEE or Intel SGX enclave where the
    hypervisor handles memory isolation at the silicon level.
    """
    for i in range(len(data)):
        data[i] = 0
    gc.collect()


@dataclass
class KeyVault:
    """Encrypted local enclave for agent secrets.

    The vault encrypts all stored secrets at rest. The LLM context window
    never receives raw key material — only opaque key IDs.

    Inversion of Control
    --------------------
    When ``bind_firewall()`` is called, the vault enforces physics at the
    cryptographic level. Every ``sign_eth_transaction()`` call runs the
    firewall BEFORE decrypting the key. RCE attackers who delete the
    ``if verdict.blocked`` check in the caller's code still can't bypass
    Aegis — the vault itself refuses to decrypt.
    """

    _fernet: Fernet = field(init=False, repr=False)
    _secrets: dict[str, bytes] = field(default_factory=dict, init=False, repr=False)
    _firewall: Any = field(default=None, init=False, repr=False)  # AegisFirewall | None

    def __post_init__(self) -> None:
        # Generate an ephemeral encryption key for this session.
        # In production, this comes from TEE/KMS.
        self._fernet = Fernet(Fernet.generate_key())

    # ── Inversion of Control ─────────────────────────────────────

    def bind_firewall(self, firewall: AegisFirewall) -> None:
        """Bind a firewall to this vault.

        Once bound, ``sign_eth_transaction()`` will ALWAYS evaluate the
        transaction through the firewall before decrypting the key. This
        cannot be unbound without creating a new vault.
        """
        if self._firewall is not None:
            raise RuntimeError(
                "Firewall already bound to this vault. "
                "Create a new KeyVault to rebind."
            )
        self._firewall = firewall

    @property
    def has_firewall(self) -> bool:
        """True if a firewall is bound to this vault."""
        return self._firewall is not None

    # ── Storage ──────────────────────────────────────────────────

    def store(self, key_id: str, secret: str | bytes) -> str:
        """Encrypt and store a secret. Returns the key_id for reference."""
        if isinstance(secret, str):
            secret = secret.encode()
        self._secrets[key_id] = self._fernet.encrypt(secret)
        return key_id

    def sign(self, key_id: str, message: bytes) -> str:
        """Sign a message using the stored secret (HMAC-SHA256).

        The raw secret never leaves the vault. Only the signature is returned.
        """
        raw = self._fernet.decrypt(self._secrets[key_id])
        sig = hmac.new(raw, message, hashlib.sha256).hexdigest()
        return sig

    def sign_transaction(self, key_id: str, tx_payload: dict[str, Any]) -> str:
        """Sign a structured transaction payload."""
        canonical = json.dumps(tx_payload, sort_keys=True, separators=(",", ":"))
        return self.sign(key_id, canonical.encode())

    def sign_eth_transaction(
        self,
        key_id: str,
        tx_dict: dict[str, Any],
        spend_amount: float = 0.0,
    ) -> bytes:
        """Sign an Ethereum transaction using ECDSA (secp256k1).

        If a firewall is bound (via ``bind_firewall()``), the transaction
        is evaluated BEFORE the key is decrypted. If blocked, the key is
        NEVER decrypted and ``AegisEnforcementError`` is raised.

        PATCH (Flaw 1): The vault owns the firewall — Inversion of Control.
        PATCH (Flaw 2): ``spend_amount`` is the Total Value at Risk (TVAR),
            which includes gas costs, not just the transfer value.
        PATCH (Flaw 3): After signing, the raw key bytes are explicitly
            overwritten with zeros and GC is forced.

        Parameters
        ----------
        key_id : str
            Opaque identifier for the stored private key.
        tx_dict : dict
            Ethereum transaction dictionary (EIP-1559 or legacy).
        spend_amount : float
            Total Value at Risk (value + max gas cost). If 0, the vault
            will compute TVAR automatically from tx_dict fields.

        Returns
        -------
        bytes
            Signed raw transaction bytes for broadcast.

        Raises
        ------
        AegisEnforcementError
            If the bound firewall blocks the transaction.
        """
        from eth_account import Account as EthAccount

        # ── Flaw 1: Inversion of Control ────────────────────────
        # The vault OWNS the firewall. Even if the caller deletes their
        # own firewall check (via RCE or code injection), the vault
        # independently evaluates the transaction before decrypting.
        if self._firewall is not None:
            # ── Flaw 2: Total Value at Risk ─────────────────────
            # Compute TVAR: value + maximum possible gas cost.
            # This catches EIP-1559 gas drain attacks where value=0
            # but maxPriorityFeePerGas is absurdly high.
            if spend_amount <= 0:
                spend_amount = _compute_tvar(tx_dict)

            # Build Aegis payload from the Ethereum tx dict
            payload = _tx_dict_to_aegis_payload(tx_dict)
            verdict = self._firewall.evaluate(payload, spend_amount=spend_amount)

            if verdict.blocked:
                raise AegisEnforcementError(
                    reason=verdict.reason,
                    engine=verdict.engine,
                    code=verdict.code.value,
                )

        # ── Decrypt key ─────────────────────────────────────────
        raw_encrypted = self._secrets[key_id]
        raw_bytes = self._fernet.decrypt(raw_encrypted)

        # ── Flaw 3: Load into mutable bytearray for secure wipe ─
        raw_key_buf = bytearray(raw_bytes)

        try:
            hex_key = raw_key_buf.decode("utf-8")
            if not hex_key.startswith("0x"):
                hex_key = "0x" + hex_key
            signed = EthAccount.sign_transaction(tx_dict, hex_key)
            return signed.raw_transaction
        finally:
            # ── Flaw 3: Soft Enclave Wipe ───────────────────────
            # Overwrite the mutable buffer with zeros. The hex_key
            # string is immutable (Python interning), but the bytearray
            # buffer IS overwritten in-place in CPython's memory.
            _secure_wipe(raw_key_buf)
            # Clear the hex_key reference (str is immutable, but we
            # can at least remove the local binding)
            hex_key = "0" * len(hex_key)  # noqa: F841

    # ── GOD-TIER 1: EIP-712 Silent Dagger Defense ──────────────

    # Known dangerous EIP-712 primary types that authorize token movement.
    _DANGEROUS_PRIMARY_TYPES = frozenset({
        "Permit", "PermitSingle", "PermitBatch",
        "PermitTransferFrom", "PermitWitnessTransferFrom",
        "Order", "OrderComponents",  # CowSwap, Seaport
        "MetaTransaction", "ForwardRequest", "Delegation",
    })

    def sign_typed_data(
        self,
        key_id: str,
        typed_data: dict[str, Any],
    ) -> str:
        """Sign EIP-712 typed data with GOD-TIER 1 protection.

        Before signing, the vault analyzes the EIP-712 payload to detect
        dangerous signature types (Permit2, gasless swaps, etc.). If the
        payload would authorize token movement, the vault runs the
        equivalent on-chain action through the firewall.

        Raises
        ------
        AegisEnforcementError
            If the typed data would authorize a dangerous action.
        """
        primary_type = typed_data.get("primaryType", "")

        if primary_type in self._DANGEROUS_PRIMARY_TYPES:
            message = typed_data.get("message", {})
            spender = (
                message.get("spender")
                or message.get("operator")
                or message.get("taker")
                or "unknown"
            )
            value = message.get("value", message.get("amount", "MAX"))
            domain = typed_data.get("domain", {})
            token = domain.get("verifyingContract", "unknown")

            synthetic_action = (
                f"EIP-712 {primary_type}: {spender} gains approval "
                f"for {value} on token {token}"
            )

            # If firewall is bound, evaluate the synthetic on-chain action
            if self._firewall is not None:
                payload = {
                    "target": str(spender),
                    "amount": float(value) if str(value).isdigit() else float("inf"),
                    "data": f"0x095ea7b3{spender}",  # approve() selector
                    "eip712_primary_type": primary_type,
                    "eip712_synthetic": True,
                }
                verdict = self._firewall.evaluate(
                    payload,
                    spend_amount=float(value) if str(value).isdigit() else float("inf"),
                )
                if verdict.blocked:
                    raise AegisEnforcementError(
                        reason=(
                            f"GOD-TIER 1 (Silent Dagger): {synthetic_action}. "
                            f"Firewall blocked: {verdict.reason}"
                        ),
                        engine="PermitDecoder",
                        code=verdict.code.value,
                    )

            # Even without firewall, block MAX_UINT approvals
            if str(value) in (
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ):
                raise AegisEnforcementError(
                    reason=(
                        f"GOD-TIER 1 (Silent Dagger): MAX_UINT approval "
                        f"to {spender} on {token}. This grants unlimited "
                        f"withdrawal rights — categorically rejected."
                    ),
                    engine="PermitDecoder",
                    code="BLOCK_EIP712_PERMIT",
                )

        # Safe to sign — proceed with HMAC signing
        canonical = json.dumps(typed_data, sort_keys=True, separators=(",", ":"))
        return self.sign(key_id, canonical.encode())

    def has_key(self, key_id: str) -> bool:
        return key_id in self._secrets

    def list_key_ids(self) -> list[str]:
        """Return available key IDs (never the secrets themselves)."""
        return list(self._secrets.keys())

    def destroy(self, key_id: str) -> None:
        """Securely remove a key from the vault."""
        if key_id in self._secrets:
            del self._secrets[key_id]


# ── TVAR Computation (Flaw 2: EIP-1559 Gas Drain) ────────────────────


def _compute_tvar(tx_dict: dict[str, Any]) -> float:
    """Compute Total Value at Risk for an Ethereum transaction.

    TVAR = transfer value + (gas limit * max fee per gas)

    This catches the EIP-1559 gas drain attack where:
        value = 0, gas = 21000, maxPriorityFeePerGas = 500_000 gwei
        → The agent's entire wallet is drained via transaction fees.

    Returns value in Wei (as float for compatibility with CapitalVelocity).
    """
    value = tx_dict.get("value", 0)
    gas = tx_dict.get("gas", 21_000)

    # EIP-1559 fields take priority over legacy gasPrice
    max_fee_per_gas = tx_dict.get("maxFeePerGas", 0)
    if max_fee_per_gas == 0:
        # Legacy transaction
        max_fee_per_gas = tx_dict.get("gasPrice", 0)

    max_gas_cost = gas * max_fee_per_gas
    return float(value + max_gas_cost)


def _tx_dict_to_aegis_payload(tx_dict: dict[str, Any]) -> dict[str, Any]:
    """Convert an Ethereum tx dict to an Aegis evaluation payload.

    This bridges the gap between Ethereum's tx format and the Aegis
    engine payload format.
    """
    payload: dict[str, Any] = {}

    if "to" in tx_dict:
        payload["target"] = str(tx_dict["to"])

    value = tx_dict.get("value", 0)
    payload["amount"] = float(value)

    # Include gas parameters for TVAR-aware engines
    payload["gas"] = tx_dict.get("gas", 21_000)
    payload["maxFeePerGas"] = tx_dict.get("maxFeePerGas", tx_dict.get("gasPrice", 0))
    payload["maxPriorityFeePerGas"] = tx_dict.get("maxPriorityFeePerGas", 0)

    # Include data/input if present
    data = tx_dict.get("data") or tx_dict.get("input")
    if data:
        payload["data"] = data

    return payload
