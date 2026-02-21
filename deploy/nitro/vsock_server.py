"""
Aegis Nitro Enclave — vsock signing server with KMS bootstrap.

Runs inside an AWS Nitro Enclave.  Receives transaction signing
requests via vsock (the only permitted I/O channel), runs the full
7-engine Aegis chain, and returns only the signature.

The private key NEVER leaves the enclave.  On boot, the enclave
authenticates to AWS KMS using its PCR0 attestation document to
receive the data key.  The signing key is derived via HKDF and
exists ONLY in enclave RAM.

Protocol (JSON over vsock):
  → {"action": "sign_eth", "key_id": "...", "tx_dict": {...}}
  ← {"ok": true, "signature": "0x..."} | {"ok": false, "error": "..."}
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
from typing import Any

# These imports work because the Dockerfile copies the aegis/ package
from aegis.firewall import AegisFirewall, AegisConfig
from aegis.enclave.vault import KeyVault, AegisEnforcementError

logger = logging.getLogger("aegis.nitro")

# Vsock constants (AWS Nitro)
VSOCK_PORT = 5000
AF_VSOCK = 40  # socket.AF_VSOCK on Linux with vsock support


def handle_request(
    vault: KeyVault,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Process a single signing request."""
    action = data.get("action", "")

    if action == "store_key":
        key_id = data["key_id"]
        secret = data["secret"]
        vault.store(key_id, secret)
        return {"ok": True, "key_id": key_id}

    elif action == "sign_eth":
        key_id = data["key_id"]
        tx_dict = data["tx_dict"]
        spend = float(data.get("spend_amount", 0))
        try:
            signature = vault.sign_eth_transaction(key_id, tx_dict, spend_amount=spend)
            return {"ok": True, "signature": signature}
        except AegisEnforcementError as e:
            return {"ok": False, "error": str(e), "blocked": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    elif action == "sign_typed":
        key_id = data["key_id"]
        typed_data = data["typed_data"]
        try:
            signature = vault.sign_typed_data(key_id, typed_data)
            return {"ok": True, "signature": signature}
        except AegisEnforcementError as e:
            return {"ok": False, "error": str(e), "blocked": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    elif action == "health":
        return {
            "ok": True,
            "status": "enclave_running",
            "keys": len(vault.list_key_ids()),
        }

    else:
        return {"ok": False, "error": f"Unknown action: {action}"}


def _bootstrap_kms_key(vault: KeyVault) -> None:
    """Bootstrap the signing key via KMS PCR0-attested decryption.

    This solves the "God Key" flaw: the private key is NEVER typed
    into a .env file or passed via Docker.  Instead:
      1. The enclave authenticates to KMS with its PCR0 hash.
      2. KMS releases the data key ONLY to the attested enclave.
      3. The signing key is derived via HKDF in enclave RAM.
    """
    try:
        from kms_bootstrap import create_key_manager, KMSBootstrapConfig

        kms_arn = os.environ.get("AEGIS_KMS_KEY_ARN", "")
        if not kms_arn:
            logger.warning(
                "AEGIS_KMS_KEY_ARN not set — skipping KMS bootstrap. "
                "Keys must be injected manually via store_key action."
            )
            return

        config = KMSBootstrapConfig(
            kms_key_arn=kms_arn,
            aws_region=os.environ.get("AWS_REGION", "us-east-1"),
            expected_pcr0=os.environ.get("AEGIS_ENCLAVE_PCR0", ""),
            provider=os.environ.get("AEGIS_KEY_PROVIDER", "kms"),
        )

        manager = create_key_manager(config)
        signing_key = manager.bootstrap()

        # Store the derived key in the vault under the canonical ID
        vault.store("aegis-primary", signing_key.hex())
        logger.info(
            "KMS bootstrap complete — signing key injected into vault "
            "(key never touched host OS)"
        )

        # Zeroize the intermediate key material
        manager.zeroize()

    except ImportError:
        logger.warning("kms_bootstrap module not available — skipping KMS bootstrap")
    except Exception as exc:
        logger.error("KMS bootstrap failed: %s", exc)
        logger.warning("Falling back to manual key injection via store_key action")


def main() -> None:
    """Start the vsock server."""
    logging.basicConfig(level=logging.INFO)
    logger.info("Aegis Nitro Enclave starting on vsock port %d", VSOCK_PORT)

    # Initialize vault with firewall
    config = AegisConfig()
    firewall = AegisFirewall(config=config)
    vault = firewall.vault

    logger.info("Firewall + vault initialized (7 engines active)")

    # ── KMS Bootstrap: PCR0-attested key injection ────────────────
    # The private key is derived from a KMS data key that requires
    # the enclave's PCR0 hash.  No human ever sees the plaintext.
    _bootstrap_kms_key(vault)
    logger.info("Key bootstrap phase complete")

    try:
        # Try real vsock first (only works inside Nitro Enclave)
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        sock.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
    except (AttributeError, OSError):
        # Fallback to TCP for local development/testing
        logger.warning("vsock not available — falling back to TCP :5000")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", VSOCK_PORT))

    sock.listen(5)
    logger.info("Listening for signing requests...")

    while True:
        conn, addr = sock.accept()
        logger.info("Connection from %s", addr)

        try:
            raw = conn.recv(65536)
            if not raw:
                continue

            request = json.loads(raw.decode("utf-8"))
            response = handle_request(vault, request)

            conn.sendall(json.dumps(response).encode("utf-8"))
        except Exception as exc:
            logger.error("Error processing request: %s", exc)
            error_resp = json.dumps({"ok": False, "error": str(exc)})
            conn.sendall(error_resp.encode("utf-8"))
        finally:
            conn.close()


if __name__ == "__main__":
    main()
