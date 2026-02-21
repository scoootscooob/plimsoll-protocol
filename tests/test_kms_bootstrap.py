"""Tests for the Aegis Nitro Enclave KMS bootstrap module.

Validates the full key lifecycle:
  1. Key generation via (mock) KMS
  2. Key wrapping and storage
  3. Key decryption via attestation
  4. HKDF derivation of signing key
  5. Zeroization of plaintext material
  6. Attestation document validation
  7. Factory function routing (KMS vs Turnkey)
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile

import pytest

# Add the deploy/nitro directory to the path so we can import kms_bootstrap
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "deploy", "nitro"))

from kms_bootstrap import (
    AttestationDocument,
    KMSBootstrapConfig,
    KMSKeyManager,
    MockKMSClient,
    TurnkeyKeyManager,
    create_key_manager,
    get_attestation_document,
)


# ── Attestation Document ─────────────────────────────────────────

class TestAttestationDocument:
    def test_validate_matching_pcr0(self):
        doc = AttestationDocument(pcr0="abc123")
        assert doc.validate("ABC123")  # case insensitive

    def test_validate_mismatched_pcr0(self):
        doc = AttestationDocument(pcr0="abc123")
        assert not doc.validate("def456")

    def test_validate_empty_pcr0_fails(self):
        doc = AttestationDocument(pcr0="")
        assert not doc.validate("abc123")

    def test_synthetic_attestation_outside_enclave(self):
        """Outside a Nitro Enclave, we get a synthetic attestation document."""
        doc = get_attestation_document()
        assert doc.pcr0 != ""
        assert doc.raw_document == b"synthetic-dev-attestation"


# ── Mock KMS Client ──────────────────────────────────────────────

class TestMockKMSClient:
    def test_generate_data_key_returns_plaintext_and_ciphertext(self):
        client = MockKMSClient()
        response = client.generate_data_key(KeyId="test-key", KeySpec="AES_256")
        assert "Plaintext" in response
        assert "CiphertextBlob" in response
        assert len(response["Plaintext"]) == 32
        assert len(response["CiphertextBlob"]) == 32

    def test_decrypt_returns_original_plaintext(self):
        client = MockKMSClient()
        gen_response = client.generate_data_key(KeyId="test-key")
        original_plaintext = gen_response["Plaintext"]
        ciphertext = gen_response["CiphertextBlob"]

        dec_response = client.decrypt(CiphertextBlob=ciphertext)
        assert dec_response["Plaintext"] == original_plaintext

    def test_decrypt_unknown_ciphertext_returns_deterministic(self):
        client = MockKMSClient()
        ciphertext = b"unknown-ciphertext-blob"
        r1 = client.decrypt(CiphertextBlob=ciphertext)
        r2 = client.decrypt(CiphertextBlob=ciphertext)
        assert r1["Plaintext"] == r2["Plaintext"]


# ── KMS Key Manager ─────────────────────────────────────────────

class TestKMSKeyManager:
    @staticmethod
    def _make_manager(config=None):
        """Create a KMSKeyManager with MockKMSClient injected (skip real boto3)."""
        if config is None:
            config = KMSBootstrapConfig(kms_key_arn="arn:aws:kms:us-east-1:123:key/test")
        manager = KMSKeyManager(config)
        manager._kms_client = MockKMSClient()
        return manager

    def test_generate_and_wrap_key(self):
        manager = self._make_manager()
        ciphertext = manager.generate_and_wrap_key()
        assert len(ciphertext) > 0
        assert manager._plaintext_key is not None
        assert len(manager._plaintext_key) == 32

    def test_decrypt_wrapped_key(self):
        manager = self._make_manager()

        # Generate first
        ciphertext = manager.generate_and_wrap_key()
        original = manager._plaintext_key

        # Decrypt should return the same key
        decrypted = manager.decrypt_wrapped_key(ciphertext)
        assert decrypted == original

    def test_derive_signing_key_deterministic(self):
        manager = self._make_manager(KMSBootstrapConfig(kms_key_arn="test-key"))
        manager.generate_and_wrap_key()

        key1 = manager.derive_signing_key()
        key2 = manager.derive_signing_key()
        assert key1 == key2
        assert len(key1) == 32

    def test_derive_signing_key_without_plaintext_raises(self):
        config = KMSBootstrapConfig(kms_key_arn="test-key")
        manager = KMSKeyManager(config)
        with pytest.raises(RuntimeError, match="No plaintext key"):
            manager.derive_signing_key()

    def test_different_hkdf_info_produces_different_keys(self):
        config1 = KMSBootstrapConfig(kms_key_arn="test-key", hkdf_info="key-v1")
        config2 = KMSBootstrapConfig(kms_key_arn="test-key", hkdf_info="key-v2")

        m1 = KMSKeyManager(config1)
        m2 = KMSKeyManager(config2)

        # Use same mock client to get same base key
        mock = MockKMSClient()
        m1._kms_client = mock
        m2._kms_client = mock

        ct1 = m1.generate_and_wrap_key()
        # Set m2's plaintext to m1's so they share the same base
        m2._plaintext_key = m1._plaintext_key

        key1 = m1.derive_signing_key()
        key2 = m2.derive_signing_key()
        assert key1 != key2  # Different HKDF info → different derived keys

    def test_zeroize_clears_key(self):
        manager = self._make_manager(KMSBootstrapConfig(kms_key_arn="test-key"))
        manager.generate_and_wrap_key()
        assert manager._plaintext_key is not None

        manager.zeroize()
        assert manager._plaintext_key is None

    def test_bootstrap_first_boot_creates_blob(self):
        """First boot: generates key, stores encrypted blob, derives signing key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            blob_path = os.path.join(tmpdir, "test_key.blob")
            config = KMSBootstrapConfig(
                kms_key_arn="test-key",
                encrypted_blob_path=blob_path,
            )
            manager = KMSKeyManager(config)
            manager._kms_client = MockKMSClient()
            signing_key = manager.bootstrap()

            assert len(signing_key) == 32
            assert os.path.exists(blob_path)
            assert os.path.getsize(blob_path) > 0

    def test_bootstrap_subsequent_boot_decrypts_blob(self):
        """Subsequent boot: reads existing blob, decrypts via KMS, derives same key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            blob_path = os.path.join(tmpdir, "test_key.blob")
            config = KMSBootstrapConfig(
                kms_key_arn="test-key",
                encrypted_blob_path=blob_path,
            )

            # First boot — generates and stores
            mock = MockKMSClient()
            m1 = KMSKeyManager(config)
            m1._kms_client = mock
            key1 = m1.bootstrap()

            # Second boot — reads and decrypts
            m2 = KMSKeyManager(config)
            m2._kms_client = mock  # Share mock so decrypt returns same key
            key2 = m2.bootstrap()

            assert key1 == key2  # Same key on both boots


# ── Turnkey MPC Provider ─────────────────────────────────────────

class TestTurnkeyKeyManager:
    def test_create_wallet(self):
        config = KMSBootstrapConfig(
            provider="turnkey",
            turnkey_org_id="test-org",
            turnkey_api_key="test-key",
        )
        manager = TurnkeyKeyManager(config)
        wallet_id = manager.create_wallet()
        assert wallet_id.startswith("turnkey-wallet-")
        assert manager._wallet_id is not None

    def test_sign_requires_wallet(self):
        config = KMSBootstrapConfig(provider="turnkey")
        manager = TurnkeyKeyManager(config)
        with pytest.raises(RuntimeError, match="No wallet created"):
            manager.sign_transaction(b"test-hash")

    def test_sign_returns_bytes(self):
        config = KMSBootstrapConfig(provider="turnkey")
        manager = TurnkeyKeyManager(config)
        manager.create_wallet()
        sig = manager.sign_transaction(b"test-hash")
        assert isinstance(sig, bytes)
        assert len(sig) == 32


# ── Factory ──────────────────────────────────────────────────────

class TestFactory:
    def test_default_creates_kms_manager(self):
        config = KMSBootstrapConfig(provider="kms")
        manager = create_key_manager(config)
        assert isinstance(manager, KMSKeyManager)

    def test_turnkey_creates_turnkey_manager(self):
        config = KMSBootstrapConfig(provider="turnkey")
        manager = create_key_manager(config)
        assert isinstance(manager, TurnkeyKeyManager)

    def test_factory_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_KMS_KEY_ARN", "arn:test")
        monkeypatch.setenv("AEGIS_KEY_PROVIDER", "kms")
        manager = create_key_manager()
        assert isinstance(manager, KMSKeyManager)
