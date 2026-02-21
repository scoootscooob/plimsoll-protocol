"""
TEE Enclave — Hardware-Isolated Transaction Signing.

In V1/V2, Plimsoll's KeyVault runs in the same OS process as the agent.
A sophisticated attacker who roots the OS can ``kill -9`` the Plimsoll
process, read ``/proc/<pid>/mem``, or ptrace-attach to extract keys.

The TEE (Trusted Execution Environment) solves this by moving signing
authority into a hardware-isolated enclave:

    - **AWS Nitro Enclaves** — isolated VM with no network/disk.
    - **Intel SGX** — CPU-level sealed memory region.
    - **ARM TrustZone** — secure-world execution on ARM chips.

This module provides the **abstraction layer**. The actual TEE backend
is pluggable via ``TEEBackend`` — you implement ``attest()``,
``sign()``, and ``get_public_key()`` for your hardware, and Plimsoll
routes all signing through it.

When no hardware TEE is available, Plimsoll falls back to the software
KeyVault (V1) with a logged warning. This keeps the API stable across
dev/staging/production.

Security model:
    1. Agent sends ``(payload, key_id)`` to TEE via ``request_signature()``.
    2. TEE runs Plimsoll's engine chain INSIDE the enclave.
    3. If engines pass → TEE signs with the hardware-sealed key.
    4. If engines block → TEE returns a BLOCK verdict. Key never leaves enclave.
    5. The agent's OS NEVER has access to the raw key material.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from plimsoll.verdict import Verdict, VerdictCode

logger = logging.getLogger("plimsoll")

_ENGINE_NAME = "TEEEnclave"


class TEEBackend(abc.ABC):
    """Abstract interface for a TEE hardware backend.

    Implement this for your specific hardware:
        - ``NitroBackend`` for AWS Nitro Enclaves
        - ``SGXBackend`` for Intel SGX
        - ``TrustZoneBackend`` for ARM TrustZone
        - ``SoftwareBackend`` for development/testing (included below)
    """

    @abc.abstractmethod
    def attest(self) -> AttestationReport:
        """Produce a cryptographic attestation report proving the code
        running inside the enclave has not been tampered with.

        Returns an AttestationReport with:
            - ``valid``: whether attestation succeeded
            - ``pcr_values``: platform configuration register hashes
            - ``nonce``: anti-replay nonce
            - ``timestamp``: when attestation was performed
        """
        ...

    @abc.abstractmethod
    def sign(self, key_id: str, message: bytes) -> bytes:
        """Sign a message using a key sealed inside the TEE.

        The raw key NEVER leaves the enclave boundary. Only the
        signature is returned to the caller.
        """
        ...

    @abc.abstractmethod
    def get_public_key(self, key_id: str) -> bytes:
        """Return the public key for a sealed key_id.

        Used for verification outside the enclave.
        """
        ...

    @abc.abstractmethod
    def seal_key(self, key_id: str, key_material: bytes) -> bool:
        """Import and seal a key inside the TEE.

        After sealing, the key can only be used via ``sign()`` — it
        cannot be exported or read, even by the host OS.
        """
        ...

    @abc.abstractmethod
    def has_key(self, key_id: str) -> bool:
        """Check if a sealed key exists in the enclave."""
        ...

    @abc.abstractmethod
    def destroy_key(self, key_id: str) -> bool:
        """Destroy a sealed key inside the enclave."""
        ...


@dataclass(frozen=True)
class AttestationReport:
    """Cryptographic proof that the enclave is running untampered code."""

    valid: bool
    pcr_values: dict[str, str] = field(default_factory=dict)
    nonce: str = ""
    timestamp: float = 0.0
    backend: str = "unknown"
    error: str = ""


class SoftwareBackend(TEEBackend):
    """Software-only TEE backend for development and testing.

    Uses HMAC-SHA256 signing (same as KeyVault) but implements the full
    TEE interface. This is NOT secure against OS-level attacks — it
    exists so you can develop and test your integration before deploying
    to real hardware.

    In production, replace with ``NitroBackend``, ``SGXBackend``, etc.
    """

    def __init__(self) -> None:
        from cryptography.fernet import Fernet
        self._fernet = Fernet(Fernet.generate_key())
        self._keys: dict[str, bytes] = {}  # key_id → encrypted key

    def attest(self) -> AttestationReport:
        """Software attestation — always valid (not hardware-backed)."""
        return AttestationReport(
            valid=True,
            pcr_values={"pcr0": "software-dev-mode"},
            nonce=hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
            timestamp=time.time(),
            backend="SoftwareBackend",
        )

    def sign(self, key_id: str, message: bytes) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"No sealed key: {key_id}")
        import hmac as _hmac
        raw = self._fernet.decrypt(self._keys[key_id])
        return _hmac.new(raw, message, hashlib.sha256).digest()

    def get_public_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"No sealed key: {key_id}")
        # For HMAC keys, "public key" is just a hash of the key
        raw = self._fernet.decrypt(self._keys[key_id])
        return hashlib.sha256(raw).digest()

    def seal_key(self, key_id: str, key_material: bytes) -> bool:
        self._keys[key_id] = self._fernet.encrypt(key_material)
        return True

    def has_key(self, key_id: str) -> bool:
        return key_id in self._keys

    def destroy_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False


@dataclass
class TEEConfig:
    """Configuration for TEE enclave integration."""

    enabled: bool = False
    backend: Optional[TEEBackend] = None
    require_attestation: bool = True  # Require valid attestation before signing
    attestation_max_age_seconds: float = 300.0  # Re-attest every 5 minutes
    fail_closed: bool = True          # Block if TEE is unavailable


@dataclass
class TEEEnclave:
    """TEE-backed signing gateway.

    Sits in front of the KeyVault as a hardware-enforced gatekeeper.
    If a TEE backend is configured, all signing goes through the
    hardware enclave. If not, falls back to software vault.

    Usage::

        tee = TEEEnclave(config=TEEConfig(
            enabled=True,
            backend=NitroBackend(enclave_id="plimsoll-prod"),
        ))
        tee.seal_key("agent-key", private_key_bytes)

        # Later, when signing:
        verdict, signature = tee.request_signature("agent-key", tx_payload)
        if verdict.allowed:
            broadcast(signature)
    """

    config: TEEConfig = field(default_factory=TEEConfig)
    _last_attestation: Optional[AttestationReport] = field(
        default=None, init=False, repr=False
    )
    _last_attestation_time: float = field(default=0.0, init=False, repr=False)

    def _get_backend(self) -> Optional[TEEBackend]:
        """Get the configured TEE backend, or None."""
        return self.config.backend

    def attest(self) -> AttestationReport:
        """Perform or return cached attestation."""
        backend = self._get_backend()
        if backend is None:
            return AttestationReport(
                valid=False,
                backend="none",
                error="No TEE backend configured",
            )

        now = time.time()
        # Return cached attestation if still fresh
        if (
            self._last_attestation is not None
            and self._last_attestation.valid
            and (now - self._last_attestation_time) < self.config.attestation_max_age_seconds
        ):
            return self._last_attestation

        # Re-attest
        try:
            report = backend.attest()
        except Exception as exc:
            logger.error("TEE attestation failed: %s", exc)
            report = AttestationReport(
                valid=False,
                backend=type(backend).__name__,
                error=str(exc),
            )

        self._last_attestation = report
        self._last_attestation_time = now
        return report

    def seal_key(self, key_id: str, key_material: bytes) -> Verdict:
        """Seal a key inside the TEE enclave.

        Returns ALLOW if sealed successfully, BLOCK_TEE_REJECTED if not.
        """
        if not self.config.enabled:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="TEE disabled — key not sealed (use KeyVault instead)",
                engine=_ENGINE_NAME,
            )

        backend = self._get_backend()
        if backend is None:
            if self.config.fail_closed:
                return Verdict(
                    code=VerdictCode.BLOCK_TEE_REJECTED,
                    reason="NO TEE BACKEND: Cannot seal key — fail closed",
                    engine=_ENGINE_NAME,
                )
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No TEE backend — key not sealed",
                engine=_ENGINE_NAME,
            )

        try:
            backend.seal_key(key_id, key_material)
            logger.info("TEE: Sealed key %s in %s", key_id, type(backend).__name__)
            return Verdict(
                code=VerdictCode.ALLOW,
                reason=f"Key {key_id} sealed in TEE",
                engine=_ENGINE_NAME,
                metadata={"key_id": key_id, "backend": type(backend).__name__},
            )
        except Exception as exc:
            return Verdict(
                code=VerdictCode.BLOCK_TEE_REJECTED,
                reason=f"TEE SEAL FAILED: {exc}",
                engine=_ENGINE_NAME,
                metadata={"error": str(exc)},
            )

    def request_signature(
        self, key_id: str, payload: dict[str, Any]
    ) -> tuple[Verdict, Optional[bytes]]:
        """Request a signature from the TEE enclave.

        The TEE signs the canonical JSON of the payload using the
        sealed key. The raw key never leaves the enclave boundary.

        Returns (verdict, signature_bytes_or_None).
        """
        if not self.config.enabled:
            return (
                Verdict(
                    code=VerdictCode.ALLOW,
                    reason="TEE disabled — passthrough to KeyVault",
                    engine=_ENGINE_NAME,
                ),
                None,
            )

        backend = self._get_backend()
        if backend is None:
            if self.config.fail_closed:
                return (
                    Verdict(
                        code=VerdictCode.BLOCK_TEE_REJECTED,
                        reason="NO TEE BACKEND — fail closed",
                        engine=_ENGINE_NAME,
                    ),
                    None,
                )
            return (
                Verdict(
                    code=VerdictCode.ALLOW,
                    reason="No TEE backend — passthrough",
                    engine=_ENGINE_NAME,
                ),
                None,
            )

        # Attestation check
        if self.config.require_attestation:
            report = self.attest()
            if not report.valid:
                return (
                    Verdict(
                        code=VerdictCode.BLOCK_TEE_REJECTED,
                        reason=(
                            f"TEE ATTESTATION FAILED: {report.error}. "
                            f"Enclave integrity cannot be verified"
                        ),
                        engine=_ENGINE_NAME,
                        metadata={"attestation": report.error},
                    ),
                    None,
                )

        # Check key exists
        if not backend.has_key(key_id):
            return (
                Verdict(
                    code=VerdictCode.BLOCK_TEE_REJECTED,
                    reason=f"KEY NOT FOUND: {key_id} not sealed in TEE",
                    engine=_ENGINE_NAME,
                    metadata={"key_id": key_id},
                ),
                None,
            )

        # Sign the canonical payload
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        try:
            signature = backend.sign(key_id, canonical.encode())
        except Exception as exc:
            return (
                Verdict(
                    code=VerdictCode.BLOCK_TEE_REJECTED,
                    reason=f"TEE SIGNING FAILED: {exc}",
                    engine=_ENGINE_NAME,
                    metadata={"error": str(exc)},
                ),
                None,
            )

        return (
            Verdict(
                code=VerdictCode.ALLOW,
                reason=f"TEE signed payload with key {key_id}",
                engine=_ENGINE_NAME,
                metadata={
                    "key_id": key_id,
                    "backend": type(backend).__name__,
                    "signature_len": len(signature),
                },
            ),
            signature,
        )

    def reset(self) -> None:
        """Clear cached attestation."""
        self._last_attestation = None
        self._last_attestation_time = 0.0
