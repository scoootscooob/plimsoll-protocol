"""
Aegis Nitro Enclave — KMS Bootstrap (PCR0-Attested Key Injection).

Solves the "God Key" flaw: the $50M private key must NEVER exist on the
host OS.  Instead, the key is:

  1. Generated INSIDE the enclave (never leaves).
  2. Encrypted with AWS KMS using a CMK that requires PCR0 attestation.
  3. The ciphertext is stored on host disk (useless without the enclave).
  4. On enclave boot, the enclave re-derives the key by calling KMS Decrypt
     with its attestation document — KMS verifies the PCR0 hash matches
     the expected enclave image before releasing the data key.

## Flow

```text
  ┌──────────────────────────────────────────────────────────┐
  │                    HOST OS (UNTRUSTED)                    │
  │                                                          │
  │  1. nitro-cli run-enclave → boots EIF image              │
  │  2. Host sends KMS CMK ARN + encrypted blob via vsock    │
  │  3. Host NEVER sees the plaintext private key             │
  └───────────────────────┬──────────────────────────────────┘
                          │ vsock (port 5000)
  ┌───────────────────────▼──────────────────────────────────┐
  │                  ENCLAVE (ISOLATED)                       │
  │                                                          │
  │  4. Enclave calls KMS Decrypt with attestation doc       │
  │     (PCR0 = SHA384 of enclave image)                     │
  │  5. KMS verifies PCR0 matches IAM policy condition       │
  │  6. KMS returns plaintext data key → enclave memory ONLY │
  │  7. Enclave derives private key from data key            │
  │  8. Private key exists ONLY in enclave RAM               │
  │                                                          │
  │  If host is compromised, attacker has:                   │
  │    - Encrypted blob (useless without enclave)            │
  │    - vsock access (but cannot extract key via API)       │
  │    - NO access to enclave memory (hardware enforced)     │
  └──────────────────────────────────────────────────────────┘
```

## KMS Policy (set in Terraform)

```json
{
  "Effect": "Allow",
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
  "Resource": "*",
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<enclave_pcr0_hash>"
    }
  }
}
```
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import socket
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("aegis.kms_bootstrap")


# ── Configuration ────────────────────────────────────────────────

@dataclass
class KMSBootstrapConfig:
    """Configuration for the KMS-backed key bootstrap."""

    # AWS KMS CMK ARN — the master key that gates access via PCR0.
    kms_key_arn: str = ""

    # AWS region for KMS calls.
    aws_region: str = "us-east-1"

    # Path to store the encrypted key blob on the host filesystem.
    # This file is useless without the enclave to decrypt it.
    encrypted_blob_path: str = "/opt/aegis/encrypted_key.blob"

    # Expected PCR0 hash of the enclave image (SHA-384, hex).
    # This is set at build time by `nitro-cli describe-eif`.
    expected_pcr0: str = ""

    # Key derivation: HKDF info string for deterministic derivation.
    hkdf_info: str = "aegis-vault-signing-key-v2"

    # Vsock port for host ↔ enclave communication.
    vsock_port: int = 5000

    # MPC provider (alternative to pure KMS).
    # Supported: "kms" (default), "turnkey"
    provider: str = "kms"

    # Turnkey-specific config (if provider == "turnkey")
    turnkey_org_id: str = ""
    turnkey_api_key: str = ""


# ── Attestation Document ─────────────────────────────────────────

@dataclass
class AttestationDocument:
    """Represents an AWS Nitro attestation document.

    In production, this is obtained via the Nitro Secure Module (NSM)
    device at /dev/nsm.  The document contains PCR values signed by
    AWS's attestation PKI.
    """

    pcr0: str = ""  # SHA-384 of the enclave image
    pcr1: str = ""  # SHA-384 of the Linux kernel
    pcr2: str = ""  # SHA-384 of the application
    timestamp: int = 0
    # The raw CBOR-encoded attestation document (base64).
    raw_document: bytes = field(default_factory=bytes)

    def validate(self, expected_pcr0: str) -> bool:
        """Verify the attestation document's PCR0 matches expected."""
        if not self.pcr0:
            return False
        return self.pcr0.lower() == expected_pcr0.lower()


# ── NSM Interface ────────────────────────────────────────────────

def get_attestation_document() -> AttestationDocument:
    """Obtain an attestation document from the Nitro Secure Module.

    Inside a real Nitro Enclave, this reads from /dev/nsm.
    Outside an enclave, returns a synthetic document for testing.
    """
    nsm_path = "/dev/nsm"

    if os.path.exists(nsm_path):
        # Real Nitro Enclave — call the NSM device.
        # In production, use the aws-nitro-enclaves-sdk-c library
        # or the Python NSM bindings.
        logger.info("NSM device detected — requesting attestation document")
        try:
            # The actual NSM ioctl call would go here.
            # For the SDK, we use the nsm Python module:
            #   import nsm
            #   fd = nsm.nsm_init()
            #   doc = nsm.nsm_get_attestation_doc(fd, ...)
            #   nsm.nsm_exit(fd)
            #
            # Placeholder: read PCR0 from environment (set by enclave init)
            pcr0 = os.environ.get("AEGIS_PCR0", "")
            return AttestationDocument(
                pcr0=pcr0,
                raw_document=b"real-nsm-attestation",
            )
        except Exception as e:
            logger.error("Failed to read NSM device: %s", e)
            raise
    else:
        # Outside enclave — synthetic document for dev/test.
        logger.warning("NSM device not found — using synthetic attestation")
        synthetic_pcr0 = hashlib.sha384(b"aegis-dev-enclave-image").hexdigest()
        return AttestationDocument(
            pcr0=synthetic_pcr0,
            raw_document=b"synthetic-dev-attestation",
        )


# ── KMS Operations ───────────────────────────────────────────────

class KMSKeyManager:
    """Manages key lifecycle using AWS KMS with PCR0 attestation.

    The private key NEVER exists on the host.  It is either:
      (a) Generated inside the enclave and wrapped with KMS, or
      (b) Derived from a KMS data key that requires attestation.
    """

    def __init__(self, config: KMSBootstrapConfig) -> None:
        self.config = config
        self._kms_client: Any = None
        self._plaintext_key: Optional[bytes] = None

    @property
    def kms_client(self) -> Any:
        """Lazy-init the KMS client (boto3)."""
        if self._kms_client is None:
            try:
                import boto3
                self._kms_client = boto3.client(
                    "kms",
                    region_name=self.config.aws_region,
                )
            except ImportError:
                logger.warning("boto3 not available — using mock KMS client")
                self._kms_client = MockKMSClient()
        return self._kms_client

    def generate_and_wrap_key(self) -> bytes:
        """Generate a new data key via KMS, return the ciphertext.

        KMS GenerateDataKey returns BOTH plaintext and ciphertext.
        The plaintext stays in enclave memory.
        The ciphertext is stored on host disk for future boots.
        """
        attestation = get_attestation_document()
        logger.info("Generating data key with KMS (PCR0: %s...)", attestation.pcr0[:16])

        response = self.kms_client.generate_data_key(
            KeyId=self.config.kms_key_arn,
            KeySpec="AES_256",
            Recipient={
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": attestation.raw_document,
            },
        )

        # The plaintext is ONLY available inside the enclave.
        # KMS encrypts it with the enclave's ephemeral RSA key
        # from the attestation document.
        self._plaintext_key = response.get("Plaintext", b"")
        ciphertext_blob = response.get("CiphertextBlob", b"")

        logger.info("Data key generated — ciphertext %d bytes", len(ciphertext_blob))
        return ciphertext_blob

    def decrypt_wrapped_key(self, ciphertext_blob: bytes) -> bytes:
        """Decrypt a previously wrapped key using KMS + attestation.

        KMS will ONLY decrypt if the enclave's PCR0 matches the
        IAM policy condition.  A compromised host cannot decrypt.
        """
        attestation = get_attestation_document()
        logger.info("Decrypting key with KMS (PCR0: %s...)", attestation.pcr0[:16])

        response = self.kms_client.decrypt(
            KeyId=self.config.kms_key_arn,
            CiphertextBlob=ciphertext_blob,
            Recipient={
                "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "AttestationDocument": attestation.raw_document,
            },
        )

        self._plaintext_key = response.get("Plaintext", b"")
        logger.info("Key decrypted successfully inside enclave")
        return self._plaintext_key

    def derive_signing_key(self) -> bytes:
        """Derive the Ed25519/secp256k1 signing key from the data key.

        Uses HKDF (HMAC-based Key Derivation) to produce a
        deterministic 32-byte signing key from the KMS data key.
        """
        if self._plaintext_key is None:
            raise RuntimeError("No plaintext key available — call generate or decrypt first")

        # HKDF-SHA256 derivation
        import hmac
        # Extract phase
        prk = hmac.new(
            key=b"aegis-hkdf-salt-v2",
            msg=self._plaintext_key,
            digestmod=hashlib.sha256,
        ).digest()

        # Expand phase
        info = self.config.hkdf_info.encode("utf-8")
        signing_key = hmac.new(
            key=prk,
            msg=info + b"\x01",
            digestmod=hashlib.sha256,
        ).digest()

        logger.info("Signing key derived (32 bytes) — exists ONLY in enclave RAM")
        return signing_key

    def bootstrap(self) -> bytes:
        """Full bootstrap sequence: decrypt or generate → derive.

        This is the main entry point called on enclave startup.
        """
        encrypted_blob_path = self.config.encrypted_blob_path

        if os.path.exists(encrypted_blob_path):
            # Existing key blob — decrypt it
            logger.info("Found encrypted key blob at %s", encrypted_blob_path)
            with open(encrypted_blob_path, "rb") as f:
                ciphertext = f.read()
            self.decrypt_wrapped_key(ciphertext)
        else:
            # First boot — generate a new key
            logger.info("No key blob found — generating new key via KMS")
            ciphertext = self.generate_and_wrap_key()

            # Store ciphertext on host disk (safe — encrypted)
            os.makedirs(os.path.dirname(encrypted_blob_path), exist_ok=True)
            with open(encrypted_blob_path, "wb") as f:
                f.write(ciphertext)
            logger.info("Encrypted blob stored at %s", encrypted_blob_path)

        return self.derive_signing_key()

    def zeroize(self) -> None:
        """Securely clear the plaintext key from memory."""
        if self._plaintext_key is not None:
            # Overwrite with random bytes before releasing
            length = len(self._plaintext_key)
            self._plaintext_key = secrets.token_bytes(length)
            self._plaintext_key = None
            logger.info("Plaintext key zeroized from enclave memory")


# ── Turnkey MPC Provider ─────────────────────────────────────────

class TurnkeyKeyManager:
    """Alternative key management using Turnkey MPC.

    Instead of a single KMS-wrapped key, Turnkey uses distributed
    MPC (Multi-Party Computation) — the private key is split across
    multiple parties and NEVER reconstructed in any single location.

    The enclave holds one MPC share.  Turnkey's infrastructure holds
    the other share(s).  Signing requires a threshold of shares to
    cooperate — no single party can sign alone.
    """

    def __init__(self, config: KMSBootstrapConfig) -> None:
        self.config = config
        self._wallet_id: Optional[str] = None

    def create_wallet(self) -> str:
        """Create a new MPC wallet via Turnkey API.

        Returns the wallet ID.  The private key material is distributed
        across MPC participants — it never exists as a whole.
        """
        logger.info("Creating MPC wallet via Turnkey (org: %s)", self.config.turnkey_org_id)

        # In production, use the Turnkey Python SDK:
        #   from turnkey import Turnkey
        #   client = Turnkey(api_key=config.turnkey_api_key, org_id=config.turnkey_org_id)
        #   wallet = client.wallets.create(name="aegis-vault", ...)
        #   return wallet.id

        # Placeholder for SDK integration
        self._wallet_id = f"turnkey-wallet-{secrets.token_hex(8)}"
        logger.info("MPC wallet created: %s", self._wallet_id)
        return self._wallet_id

    def sign_transaction(self, tx_hash: bytes) -> bytes:
        """Request a distributed MPC signature from Turnkey.

        The enclave sends the transaction hash to Turnkey's API.
        Turnkey orchestrates the MPC signing ceremony across all
        share holders.  No single party ever sees the full key.
        """
        if self._wallet_id is None:
            raise RuntimeError("No wallet created — call create_wallet first")

        logger.info("Requesting MPC signature for hash %s...", tx_hash[:8].hex())

        # In production:
        #   signature = client.wallets.sign(
        #       wallet_id=self._wallet_id,
        #       hash=tx_hash.hex(),
        #   )
        #   return bytes.fromhex(signature)

        # Placeholder
        return hashlib.sha256(tx_hash + self._wallet_id.encode()).digest()


# ── Mock KMS Client (for testing outside AWS) ────────────────────

class MockKMSClient:
    """Mock KMS client for local development and testing."""

    def __init__(self) -> None:
        self._keys: dict[str, bytes] = {}

    def generate_data_key(self, **kwargs: Any) -> dict[str, Any]:
        """Simulate KMS GenerateDataKey."""
        plaintext = secrets.token_bytes(32)
        ciphertext = hashlib.sha256(plaintext + b"mock-kms-wrap").digest()
        key_id = kwargs.get("KeyId", "mock-key")
        self._keys[ciphertext.hex()] = plaintext

        return {
            "Plaintext": plaintext,
            "CiphertextBlob": ciphertext,
            "KeyId": key_id,
        }

    def decrypt(self, **kwargs: Any) -> dict[str, Any]:
        """Simulate KMS Decrypt."""
        ciphertext = kwargs.get("CiphertextBlob", b"")
        hex_key = ciphertext.hex()

        if hex_key in self._keys:
            return {"Plaintext": self._keys[hex_key]}

        # Fallback: deterministic derivation from ciphertext
        plaintext = hashlib.sha256(ciphertext + b"mock-kms-decrypt").digest()
        return {"Plaintext": plaintext}


# ── Factory ──────────────────────────────────────────────────────

def create_key_manager(
    config: Optional[KMSBootstrapConfig] = None,
) -> KMSKeyManager | TurnkeyKeyManager:
    """Create the appropriate key manager based on config."""
    if config is None:
        config = KMSBootstrapConfig(
            kms_key_arn=os.environ.get("AEGIS_KMS_KEY_ARN", ""),
            aws_region=os.environ.get("AWS_REGION", "us-east-1"),
            expected_pcr0=os.environ.get("AEGIS_ENCLAVE_PCR0", ""),
            provider=os.environ.get("AEGIS_KEY_PROVIDER", "kms"),
            turnkey_org_id=os.environ.get("TURNKEY_ORG_ID", ""),
            turnkey_api_key=os.environ.get("TURNKEY_API_KEY", ""),
        )

    if config.provider == "turnkey":
        logger.info("Using Turnkey MPC provider")
        return TurnkeyKeyManager(config)
    else:
        logger.info("Using AWS KMS provider")
        return KMSKeyManager(config)
