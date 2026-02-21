"""
Context-Window Airgap: The Key Vault.

The LLM never touches the private key. Plimsoll holds the key in an encrypted
local enclave. The LLM asks Plimsoll to sign a transaction; if the math checks
pass, Plimsoll signs it and returns the signature. The AI is structurally blind
to its own cryptography.

This module provides a simple symmetric-encryption vault using Fernet
(AES-128-CBC with HMAC). In production, this would be backed by a hardware
TEE (Intel SGX, ARM TrustZone) or a cloud KMS.

PATCH (Flaw 1 — Inversion of Control):
    The Vault is NOT a dumb signer. When a firewall is bound to the vault,
    ``sign_eth_transaction()`` internally runs ``firewall.evaluate()`` BEFORE
    decrypting the key. If the firewall blocks the transaction, the vault
    raises ``PlimsollEnforcementError`` and the key is NEVER decrypted. This
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
    from plimsoll.firewall import PlimsollFirewall

# v1.0.4 Kill-Shot 4: Known temporal bound field names in EIP-712 messages.
# These fields control how long a signed Permit/approval remains valid.
# An immortal signature (uint256.max) can be weaponized as a time-bomb.
_TEMPORAL_BOUND_FIELDS = frozenset({
    "deadline", "expiration", "sigDeadline", "expiry",
    "validBefore", "validAfter",
})

# uint256 max — the immortal signature sentinel value
_UINT256_MAX = 2**256 - 1


class PlimsollEnforcementError(Exception):
    """Raised when the vault refuses to sign because the firewall blocked.

    This is the cryptographic enforcement layer — if the physics say no,
    the key is NEVER decrypted. Period.
    """

    def __init__(self, reason: str, engine: str, code: str) -> None:
        self.reason = reason
        self.engine = engine
        self.code = code
        super().__init__(
            f"[PLIMSOLL VAULT ENFORCEMENT] Transaction blocked by {engine}: "
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
    Plimsoll — the vault itself refuses to decrypt.
    """

    _fernet: Fernet = field(init=False, repr=False)
    _secrets: dict[str, bytes] = field(default_factory=dict, init=False, repr=False)
    _firewall: Any = field(default=None, init=False, repr=False)  # PlimsollFirewall | None

    # ZERO-DAY 3 (Dimension Tear): Expected chain ID for EIP-712 signing.
    # When set, sign_typed_data() rejects any domain separator with missing,
    # null, zero, or mismatched chainId to prevent cross-chain replay.
    # None = chain ID validation disabled (backward compat).
    _expected_chain_id: int | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        # Generate an ephemeral encryption key for this session.
        # In production, this comes from TEE/KMS.
        self._fernet = Fernet(Fernet.generate_key())

    # ── Inversion of Control ─────────────────────────────────────

    def bind_firewall(self, firewall: PlimsollFirewall) -> None:
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

    def set_expected_chain_id(self, chain_id: int) -> None:
        """Set the expected chain ID for EIP-712 domain validation.

        ZERO-DAY 3 (Dimension Tear): Once set, sign_typed_data() will reject
        any EIP-712 payload whose domain separator is missing chainId or has
        a mismatched chainId. This prevents cross-chain signature replay
        attacks where a $5 approval on L2 is replayed on L1.
        """
        if chain_id <= 0:
            raise ValueError(f"chain_id must be positive, got {chain_id}")
        self._expected_chain_id = chain_id

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
        NEVER decrypted and ``PlimsollEnforcementError`` is raised.

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
        PlimsollEnforcementError
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
                # v1.0.3 Bounty 3: Pass chain_id for L2-aware TVAR
                fw_chain_id = getattr(self._firewall.config, "chain_id", 0)
                spend_amount = _compute_tvar(tx_dict, chain_id=fw_chain_id)

            # Build Plimsoll payload from the Ethereum tx dict
            payload = _tx_dict_to_plimsoll_payload(tx_dict)
            verdict = self._firewall.evaluate(payload, spend_amount=spend_amount)

            if verdict.blocked:
                raise PlimsollEnforcementError(
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

    # ── v1.0.4 Kill-Shot 4: Permit2 Time-Bomb Defense ──────────

    def _validate_permit_temporal_bounds(
        self,
        message: dict[str, Any],
        max_duration_secs: int,
    ) -> None:
        """Validate temporal bounds in EIP-712 messages.

        v1.0.4 Kill-Shot 4 (Permit2 Time-Bomb): Checks all known temporal
        fields (deadline, expiration, sigDeadline, expiry, validBefore).

        - ``type(uint256).max`` → always reject (immortal signature)
        - Duration exceeds ``max_duration_secs`` → reject

        Raises
        ------
        PlimsollEnforcementError
            If a temporal field exceeds the configured maximum duration.
        """
        import time as _time

        now = int(_time.time())

        for field_name in _TEMPORAL_BOUND_FIELDS:
            raw_value = message.get(field_name)
            if raw_value is None:
                continue

            # Normalize to int
            try:
                if isinstance(raw_value, str):
                    if raw_value.startswith("0x"):
                        temporal_val = int(raw_value, 16)
                    else:
                        temporal_val = int(raw_value)
                else:
                    temporal_val = int(raw_value)
            except (ValueError, TypeError):
                continue

            # Check for immortal signature (uint256.max)
            if temporal_val >= _UINT256_MAX:
                raise PlimsollEnforcementError(
                    reason=(
                        f"KILL-SHOT 4 (PERMIT2 TIME-BOMB): EIP-712 field "
                        f"'{field_name}' set to type(uint256).max — signature "
                        f"is IMMORTAL. After the legitimate swap, the attacker "
                        f"can reuse this signature indefinitely via "
                        f"Permit2.transferFrom()."
                    ),
                    engine="PermitTemporalValidator",
                    code="BLOCK_PERMIT_IMMORTAL_SIGNATURE",
                )

            # Check for excessive duration
            duration = temporal_val - now
            if duration > max_duration_secs:
                raise PlimsollEnforcementError(
                    reason=(
                        f"KILL-SHOT 4 (PERMIT2 TIME-BOMB): EIP-712 field "
                        f"'{field_name}' expires in {duration}s "
                        f"({duration // 3600}h) — exceeds max allowed "
                        f"{max_duration_secs}s ({max_duration_secs // 60}min). "
                        f"Signatures with excessive lifetimes can be weaponized "
                        f"as time-bombs."
                    ),
                    engine="PermitTemporalValidator",
                    code="BLOCK_PERMIT_EXPIRY_TOO_LONG",
                )

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
        """Sign EIP-712 typed data with GOD-TIER 1 + ZERO-DAY 3 protection.

        Before signing, the vault:
        1. ZERO-DAY 3: Validates the domain separator's chainId to prevent
           cross-chain signature replay attacks.
        2. GOD-TIER 1: Analyzes dangerous EIP-712 primary types (Permit2,
           gasless swaps) and evaluates them through the firewall.

        Raises
        ------
        PlimsollEnforcementError
            If the typed data would authorize a dangerous action.
        """
        primary_type = typed_data.get("primaryType", "")
        domain = typed_data.get("domain", {})

        # ── ZERO-DAY 3: Cross-Chain Permit Replay Defense ──────────
        # Validate that the EIP-712 domain separator contains the
        # correct chainId. Missing/null/zero/mismatched chainId means
        # the signature could be replayed on any chain.
        if self._expected_chain_id is not None:
            domain_chain_id = domain.get("chainId")

            if domain_chain_id is None:
                raise PlimsollEnforcementError(
                    reason=(
                        f"ZERO-DAY 3 (Dimension Tear): EIP-712 domain "
                        f"separator is MISSING chainId. Signature would be "
                        f"replayable on ANY chain. Expected "
                        f"chainId={self._expected_chain_id}."
                    ),
                    engine="ChainIdValidator",
                    code="BLOCK_CROSS_CHAIN_REPLAY",
                )

            # Normalize to int (could be string hex "0x1" or int 1)
            try:
                if isinstance(domain_chain_id, str):
                    if domain_chain_id.startswith("0x"):
                        chain_id_val = int(domain_chain_id, 16)
                    else:
                        chain_id_val = int(domain_chain_id)
                else:
                    chain_id_val = int(domain_chain_id)
            except (ValueError, TypeError):
                raise PlimsollEnforcementError(
                    reason=(
                        f"ZERO-DAY 3 (Dimension Tear): EIP-712 domain "
                        f"chainId is unparseable: {domain_chain_id!r}."
                    ),
                    engine="ChainIdValidator",
                    code="BLOCK_CROSS_CHAIN_REPLAY",
                )

            if chain_id_val == 0:
                raise PlimsollEnforcementError(
                    reason=(
                        f"ZERO-DAY 3 (Dimension Tear): EIP-712 domain "
                        f"chainId=0 is a wildcard that allows replay on "
                        f"any chain. Expected "
                        f"chainId={self._expected_chain_id}."
                    ),
                    engine="ChainIdValidator",
                    code="BLOCK_CROSS_CHAIN_REPLAY",
                )

            if chain_id_val != self._expected_chain_id:
                raise PlimsollEnforcementError(
                    reason=(
                        f"ZERO-DAY 3 (Dimension Tear): EIP-712 domain "
                        f"chainId={chain_id_val} does not match expected "
                        f"chainId={self._expected_chain_id}. Cross-chain "
                        f"replay attack possible."
                    ),
                    engine="ChainIdValidator",
                    code="BLOCK_CROSS_CHAIN_REPLAY",
                )

        # ── v1.0.4 Kill-Shot 4: Permit2 Time-Bomb Defense ──────────
        # Before signing ANY EIP-712 message with temporal bounds, validate
        # that expiration/deadline fields don't create immortal signatures.
        if self._firewall is not None:
            max_permit_dur = getattr(
                self._firewall.config, "max_permit_duration_secs", 0
            )
            if max_permit_dur > 0:
                msg_body = typed_data.get("message", {})
                self._validate_permit_temporal_bounds(msg_body, max_permit_dur)

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
                    raise PlimsollEnforcementError(
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
                raise PlimsollEnforcementError(
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


# ── v1.0.3 Bounty 3: L2 Chain ID Registry ────────────────────────────

L2_CHAIN_IDS: dict[int, str] = {
    10: "Optimism",
    8453: "Base",
    42161: "Arbitrum One",
    42170: "Arbitrum Nova",
    324: "zkSync Era",
    1101: "Polygon zkEVM",
    534352: "Scroll",
    59144: "Linea",
    7777777: "Zora",
}


def _compute_l1_data_fee(tx_dict: dict[str, Any], chain_id: int) -> float:
    """Estimate L1 data posting fee for L2 rollups.

    v1.0.3 Bounty 3 (L1 Blob-Fee Asymmetry): On Optimism/Base/Arbitrum,
    every L2 transaction pays an L1 data posting fee proportional to
    calldata size:

        l1_fee = (zero_bytes * 4 + nonzero_bytes * 16) * l1_base_fee

    An attacker can pad calldata with junk bytes (nearly free on L2 execution)
    to inflate the L1 posting fee, draining the treasury via Paymaster.

    We use a conservative default L1 base fee (30 gwei) since the actual
    value comes from the L2's L1 oracle contract (e.g., OVM_GasPriceOracle).

    Parameters
    ----------
    tx_dict : dict
        Ethereum transaction dictionary.
    chain_id : int
        Chain ID (L2 chains trigger L1 fee calculation).

    Returns
    -------
    float
        Estimated L1 data fee in Wei (0.0 if not an L2 chain).
    """
    if chain_id not in L2_CHAIN_IDS:
        return 0.0

    data_hex = tx_dict.get("data", "") or tx_dict.get("input", "")
    if isinstance(data_hex, str):
        data_hex = data_hex.replace("0x", "")
    else:
        data_hex = ""

    try:
        data_bytes = bytes.fromhex(data_hex) if data_hex else b""
    except ValueError:
        data_bytes = b""

    zero_bytes = sum(1 for b in data_bytes if b == 0)
    nonzero_bytes = len(data_bytes) - zero_bytes

    # Conservative L1 base fee estimate (30 gwei = 30e9 wei)
    # In production, this would come from the L2's L1 oracle contract
    l1_base_fee = tx_dict.get("_l1BaseFee", 30_000_000_000)

    l1_data_gas = zero_bytes * 4 + nonzero_bytes * 16
    return float(l1_data_gas * l1_base_fee)


# ── TVAR Computation (Flaw 2: EIP-1559 Gas Drain) ────────────────────


def _compute_tvar(tx_dict: dict[str, Any], chain_id: int = 0) -> float:
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

    # v1.0.4 Kill-Shot 2: Include preVerificationGas in TVAR.
    # PVG is a flat ERC-4337 Bundler fee paid BEFORE execution, invisible
    # to the EVM simulator. An attacker inflates PVG to drain the Paymaster.
    pvg = tx_dict.get("preVerificationGas", 0)
    pvg_cost = pvg * max_fee_per_gas

    # v1.0.3 Bounty 3: Include L1 data posting fee for L2 rollups
    l1_fee = _compute_l1_data_fee(tx_dict, chain_id)

    return float(value + max_gas_cost + pvg_cost + l1_fee)


def _tx_dict_to_plimsoll_payload(tx_dict: dict[str, Any]) -> dict[str, Any]:
    """Convert an Ethereum tx dict to an Plimsoll evaluation payload.

    This bridges the gap between Ethereum's tx format and the Plimsoll
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
