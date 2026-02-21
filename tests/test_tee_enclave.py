"""Tests for TEE Enclave (Hardware Abstraction Layer)."""

from __future__ import annotations

import time

from aegis.enclave.tee import (
    TEEEnclave,
    TEEConfig,
    TEEBackend,
    SoftwareBackend,
    AttestationReport,
)
from aegis.verdict import VerdictCode


# ── SoftwareBackend tests ────────────────────────────────────────


def test_software_backend_attest():
    """SoftwareBackend should always return valid attestation."""
    backend = SoftwareBackend()
    report = backend.attest()
    assert report.valid
    assert report.backend == "SoftwareBackend"
    assert report.nonce  # Non-empty nonce


def test_software_backend_seal_and_sign():
    """SoftwareBackend should seal a key and produce consistent signatures."""
    backend = SoftwareBackend()
    backend.seal_key("test-key", b"secret-material")

    sig1 = backend.sign("test-key", b"hello world")
    sig2 = backend.sign("test-key", b"hello world")
    assert sig1 == sig2  # Deterministic

    sig3 = backend.sign("test-key", b"different message")
    assert sig1 != sig3  # Different messages → different sigs


def test_software_backend_has_key():
    """SoftwareBackend should track sealed keys."""
    backend = SoftwareBackend()
    assert not backend.has_key("test-key")

    backend.seal_key("test-key", b"secret")
    assert backend.has_key("test-key")


def test_software_backend_destroy_key():
    """SoftwareBackend should destroy sealed keys."""
    backend = SoftwareBackend()
    backend.seal_key("test-key", b"secret")
    assert backend.has_key("test-key")

    result = backend.destroy_key("test-key")
    assert result is True
    assert not backend.has_key("test-key")

    # Destroying non-existent key returns False
    result = backend.destroy_key("nonexistent")
    assert result is False


def test_software_backend_get_public_key():
    """SoftwareBackend should return a public key hash."""
    backend = SoftwareBackend()
    backend.seal_key("test-key", b"secret")
    pub = backend.get_public_key("test-key")
    assert len(pub) == 32  # SHA-256 hash


def test_software_backend_sign_missing_key_raises():
    """Signing with a non-existent key should raise KeyError."""
    backend = SoftwareBackend()
    try:
        backend.sign("nonexistent", b"message")
        assert False, "Should have raised KeyError"
    except KeyError:
        pass


# ── TEEEnclave tests ─────────────────────────────────────────────


def test_tee_disabled_passthrough():
    """Disabled TEE should return ALLOW for all operations."""
    tee = TEEEnclave(config=TEEConfig(enabled=False))
    verdict, sig = tee.request_signature("key", {"amount": 100})
    assert verdict.allowed
    assert sig is None
    assert "disabled" in verdict.reason.lower()


def test_tee_no_backend_fail_closed():
    """Enabled TEE with no backend + fail_closed should block."""
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=None,
        fail_closed=True,
    ))
    verdict, sig = tee.request_signature("key", {"amount": 100})
    assert verdict.blocked
    assert verdict.code == VerdictCode.BLOCK_TEE_REJECTED
    assert sig is None


def test_tee_no_backend_fail_open():
    """Enabled TEE with no backend + fail_closed=False should pass."""
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=None,
        fail_closed=False,
    ))
    verdict, sig = tee.request_signature("key", {"amount": 100})
    assert verdict.allowed
    assert sig is None


def test_tee_seal_and_sign():
    """Full flow: seal key → request signature → get bytes back."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
    ))

    # Seal a key
    seal_v = tee.seal_key("agent-key", b"my-secret-key")
    assert seal_v.allowed

    # Sign a payload
    verdict, sig = tee.request_signature("agent-key", {
        "target": "0xDEAD",
        "amount": 500,
    })
    assert verdict.allowed
    assert sig is not None
    assert len(sig) == 32  # HMAC-SHA256


def test_tee_sign_missing_key_blocks():
    """Signing with a key not in the TEE should block."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
    ))

    verdict, sig = tee.request_signature("nonexistent", {"amount": 100})
    assert verdict.blocked
    assert verdict.code == VerdictCode.BLOCK_TEE_REJECTED
    assert "NOT FOUND" in verdict.reason
    assert sig is None


def test_tee_attestation_required():
    """When require_attestation=True, attestation must pass."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
        require_attestation=True,
    ))
    backend.seal_key("key", b"secret")

    verdict, sig = tee.request_signature("key", {"amount": 100})
    assert verdict.allowed  # SoftwareBackend always passes attestation
    assert sig is not None


def test_tee_attestation_caching():
    """Attestation should be cached within max_age window."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
        require_attestation=True,
        attestation_max_age_seconds=10.0,
    ))

    # First attestation
    report1 = tee.attest()
    assert report1.valid

    # Second call should return cached
    report2 = tee.attest()
    assert report2.valid
    assert report1.nonce == report2.nonce  # Same cached report


def test_tee_attestation_expires():
    """Attestation should re-attest after max_age expires."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
        require_attestation=True,
        attestation_max_age_seconds=0.1,  # 100ms
    ))

    report1 = tee.attest()
    time.sleep(0.15)
    report2 = tee.attest()

    # Different nonces → re-attested
    assert report1.nonce != report2.nonce


class FailingBackend(TEEBackend):
    """TEE backend that fails attestation."""

    def attest(self):
        return AttestationReport(
            valid=False,
            backend="FailingBackend",
            error="Hardware not available",
        )

    def sign(self, key_id, message):
        raise RuntimeError("Cannot sign")

    def get_public_key(self, key_id):
        raise RuntimeError("No keys")

    def seal_key(self, key_id, key_material):
        return True

    def has_key(self, key_id):
        return True

    def destroy_key(self, key_id):
        return True


def test_tee_failed_attestation_blocks():
    """Failed attestation should block signing."""
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=FailingBackend(),
        require_attestation=True,
    ))

    verdict, sig = tee.request_signature("key", {"amount": 100})
    assert verdict.blocked
    assert verdict.code == VerdictCode.BLOCK_TEE_REJECTED
    assert "ATTESTATION FAILED" in verdict.reason


def test_tee_seal_no_backend_fail_closed():
    """Sealing with no backend + fail_closed should block."""
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=None,
        fail_closed=True,
    ))
    v = tee.seal_key("key", b"secret")
    assert v.blocked
    assert "NO TEE BACKEND" in v.reason


def test_tee_seal_disabled():
    """Sealing with disabled TEE should pass (use KeyVault instead)."""
    tee = TEEEnclave(config=TEEConfig(enabled=False))
    v = tee.seal_key("key", b"secret")
    assert v.allowed


def test_tee_deterministic_signatures():
    """Same key + same payload → same signature."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
    ))
    backend.seal_key("key", b"secret")

    payload = {"target": "0xDEAD", "amount": 100}
    _, sig1 = tee.request_signature("key", payload)
    _, sig2 = tee.request_signature("key", payload)
    assert sig1 == sig2


def test_tee_different_payloads_different_sigs():
    """Different payloads → different signatures."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
    ))
    backend.seal_key("key", b"secret")

    _, sig1 = tee.request_signature("key", {"amount": 100})
    _, sig2 = tee.request_signature("key", {"amount": 200})
    assert sig1 != sig2


def test_tee_reset_clears_cache():
    """reset() should clear cached attestation."""
    backend = SoftwareBackend()
    tee = TEEEnclave(config=TEEConfig(
        enabled=True,
        backend=backend,
    ))

    tee.attest()
    assert tee._last_attestation is not None

    tee.reset()
    assert tee._last_attestation is None


def test_tee_no_backend_attestation():
    """Attestation with no backend should return invalid report."""
    tee = TEEEnclave(config=TEEConfig(enabled=True, backend=None))
    report = tee.attest()
    assert not report.valid
    assert "No TEE backend" in report.error
