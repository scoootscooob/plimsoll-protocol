"""Tests for Engine 1: State-Space Trajectory Hashing."""

import time

from plimsoll.engines.trajectory_hash import TrajectoryHashEngine, TrajectoryHashConfig
from plimsoll.verdict import VerdictCode


def test_allows_unique_payloads():
    engine = TrajectoryHashEngine()
    payloads = [
        {"target": f"0x{i:040x}", "amount": i * 100, "function": "transfer"}
        for i in range(10)
    ]
    for p in payloads:
        v = engine.evaluate(p)
        assert v.allowed, f"Should allow unique payload: {p}"


def test_blocks_repeated_identical_payloads():
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=3, window_seconds=60)
    )
    payload = {"target": "0xDEAD", "amount": 500, "function": "transfer"}

    # First 3 should pass
    for i in range(3):
        v = engine.evaluate(payload)
        assert v.allowed, f"Attempt {i+1} should be allowed"

    # 4th should block
    v = engine.evaluate(payload)
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_LOOP_DETECTED
    assert "LOOP DETECTED" in v.reason


def test_rephrased_same_intent_still_blocked():
    """LLM rephrasing should not evade detection — we hash execution params."""
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=2, window_seconds=60)
    )
    # Same deterministic params, regardless of how the LLM frames it
    payload = {"target": "0xBEEF", "amount": 1000, "function": "swap"}

    engine.evaluate(payload)
    engine.evaluate(payload)
    v = engine.evaluate(payload)
    assert v.blocked


def test_window_expiry_allows_retry():
    """After the sliding window expires, identical payloads should be allowed again."""
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=2, window_seconds=0.1)
    )
    payload = {"target": "0xAAAA", "amount": 10, "function": "send"}

    engine.evaluate(payload)
    engine.evaluate(payload)
    v = engine.evaluate(payload)
    assert v.blocked

    # Wait for window to expire
    time.sleep(0.15)

    v = engine.evaluate(payload)
    assert v.allowed


def test_reset_clears_state():
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=1)
    )
    payload = {"target": "0x1", "amount": 1, "function": "f"}
    engine.evaluate(payload)
    v = engine.evaluate(payload)
    assert v.blocked

    engine.reset()
    v = engine.evaluate(payload)
    assert v.allowed


def test_feedback_prompt_on_block():
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=1)
    )
    payload = {"target": "0x1", "amount": 1, "function": "f"}
    engine.evaluate(payload)
    v = engine.evaluate(payload)
    feedback = v.feedback_prompt()
    assert "PLIMSOLL FIREWALL" in feedback
    assert "DO NOT RETRY" in feedback


def test_different_amounts_are_different_hashes():
    engine = TrajectoryHashEngine(
        config=TrajectoryHashConfig(max_duplicates=1)
    )
    p1 = {"target": "0xA", "amount": 100, "function": "transfer"}
    p2 = {"target": "0xA", "amount": 200, "function": "transfer"}

    engine.evaluate(p1)
    v = engine.evaluate(p2)
    assert v.allowed, "Different amounts should produce different hashes"
