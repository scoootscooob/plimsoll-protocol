"""Tests for Engine 5: Payload Quantizer (Steganography Defense)."""

from __future__ import annotations

from plimsoll.engines.payload_quantizer import (
    PayloadQuantizerEngine,
    PayloadQuantizerConfig,
)
from plimsoll.verdict import VerdictCode


def test_disabled_passthrough():
    """Disabled quantizer should pass everything through."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(enabled=False)
    )
    v = engine.evaluate({"amount": 1.097, "target": "0xDEAD"})
    assert v.allowed
    assert "disabled" in v.reason.lower()


def test_no_numeric_fields():
    """Payload with no numeric fields should pass."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(enabled=True, tick_size=0.10)
    )
    v = engine.evaluate({"target": "0xDEAD", "function": "transfer"})
    assert v.allowed


def test_aligned_amount_passes():
    """Amount already aligned to tick grid should pass."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(enabled=True, tick_size=0.10)
    )
    v = engine.evaluate({"amount": 1.10, "target": "0xDEAD"})
    assert v.allowed


def test_misaligned_amount_blocks_strict():
    """Off-grid amount in strict mode should be blocked."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=0.10,
            strict_mode=True,
        )
    )
    v = engine.evaluate({"amount": 1.097, "target": "0xDEAD"})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_QUANTIZATION_REJECTED
    assert "STEGANOGRAPHY" in v.reason


def test_misaligned_amount_allows_permissive():
    """Off-grid amount in permissive mode should pass with quantized values."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=0.10,
            strict_mode=False,
        )
    )
    v = engine.evaluate({"amount": 1.097, "target": "0xDEAD"})
    assert v.allowed
    assert v.metadata.get("rewritten") is True
    assert "amount" in v.metadata.get("quantized_values", {})
    assert v.metadata["quantized_values"]["amount"] == 1.10


def test_quantize_to_correct_tick():
    """Values should snap to nearest tick."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(enabled=True, tick_size=0.25)
    )
    # 1.097 → 1.0 (nearest 0.25 tick)
    q = engine._quantize(1.097)
    assert q == 1.0

    # 1.13 → 1.25 (nearest 0.25 tick)
    q = engine._quantize(1.13)
    assert q == 1.25

    # 1.875 → 2.0
    q = engine._quantize(1.875)
    assert q == 2.0


def test_tolerance_allows_small_deviation():
    """Deviations within tolerance should not trigger."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            strict_mode=True,
            tolerance=0.05,  # Allow up to 5 cents deviation
        )
    )
    # 1.03 → quantizes to 1.0, deviation = 0.03 < tolerance 0.05
    v = engine.evaluate({"amount": 1.03})
    assert v.allowed

    # 1.10 → quantizes to 1.0, deviation = 0.10 > tolerance 0.05
    v = engine.evaluate({"amount": 1.10})
    assert v.blocked


def test_min_value_ignores_dust():
    """Values below min_value should be ignored."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            strict_mode=True,
            min_value=0.10,
        )
    )
    # 0.05 is below min_value — should be ignored
    v = engine.evaluate({"amount": 0.05})
    assert v.allowed


def test_quantize_all_numeric():
    """quantize_all_numeric should check all numeric fields."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            quantize_all_numeric=True,
            strict_mode=True,
        )
    )
    v = engine.evaluate({
        "amount": 10.0,  # Aligned
        "gas_price": 5.5,  # NOT aligned
        "target": "0xDEAD",  # Not numeric — ignored
    })
    assert v.blocked
    assert "gas_price" in v.reason or len(v.metadata.get("deviations", [])) > 0


def test_quantize_specific_fields():
    """Only configured fields should be checked."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            quantize_fields=["amount"],  # Only check "amount"
            strict_mode=True,
        )
    )
    # amount is aligned, gas_price is not — but we only check "amount"
    v = engine.evaluate({"amount": 10.0, "gas_price": 5.5})
    assert v.allowed


def test_quantize_payload_helper():
    """quantize_payload() should return a new dict with snapped values."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=0.10,
            quantize_fields=["amount"],
        )
    )
    original = {"amount": 1.097, "target": "0xDEAD"}
    result = engine.quantize_payload(original)

    assert result["amount"] == 1.10
    assert result["target"] == "0xDEAD"
    # Original should be unchanged
    assert original["amount"] == 1.097


def test_quantize_payload_disabled():
    """quantize_payload() with disabled engine returns original."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(enabled=False)
    )
    original = {"amount": 1.097}
    result = engine.quantize_payload(original)
    assert result["amount"] == 1.097


def test_steganography_attack_blocked():
    """Simulate a steganographic key exfil via micro-transaction amounts."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=0.01,  # Cent-level grid
            strict_mode=True,
        )
    )
    # Attacker encodes ASCII 'a' (97) in trailing digits: $1.097
    # 1.097 quantized to 0.01 grid → 1.10 (deviation = 0.003)
    v = engine.evaluate({"amount": 1.097})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_QUANTIZATION_REJECTED

    # Clean amount passes
    v = engine.evaluate({"amount": 1.10})
    assert v.allowed


def test_integer_amount_passes():
    """Integer amounts should always be aligned."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=0.10,
            strict_mode=True,
        )
    )
    v = engine.evaluate({"amount": 100})
    assert v.allowed


def test_boolean_not_quantized():
    """Boolean values should not be treated as numeric."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            quantize_all_numeric=True,
            strict_mode=True,
        )
    )
    v = engine.evaluate({"amount": 10.0, "confirmed": True})
    assert v.allowed


def test_metadata_contains_deviations():
    """Block verdict should contain deviation details."""
    engine = PayloadQuantizerEngine(
        config=PayloadQuantizerConfig(
            enabled=True,
            tick_size=1.0,
            strict_mode=True,
        )
    )
    v = engine.evaluate({"amount": 5.7})
    assert v.blocked
    devs = v.metadata.get("deviations", [])
    assert len(devs) == 1
    assert devs[0]["field"] == "amount"
    assert devs[0]["original"] == 5.7
    assert devs[0]["quantized"] == 6.0


def test_reset_is_noop():
    """PayloadQuantizer is stateless, reset should not fail."""
    engine = PayloadQuantizerEngine()
    engine.reset()
