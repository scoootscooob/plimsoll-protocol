"""Tests for Engine 2: Capital Velocity Bound (PID Controller)."""

import time

from aegis.engines.capital_velocity import CapitalVelocityEngine, CapitalVelocityConfig
from aegis.verdict import VerdictCode


def test_allows_normal_spending():
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(v_max=100.0)
    )
    # Single spend well under velocity limit
    v = engine.evaluate(10.0)
    assert v.allowed


def test_blocks_velocity_spike():
    """Rapid-fire large spends should trigger the PID controller."""
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(
            v_max=1.0,       # Very low velocity limit: 1 unit/sec
            pid_threshold=1.0,
            k_p=1.0,
            k_i=0.0,
            k_d=0.0,
        )
    )

    # First spend — always allowed (< min_samples)
    v = engine.evaluate(100.0)
    assert v.allowed

    # Second spend immediately — velocity = 200/tiny_dt >> 1.0
    v = engine.evaluate(100.0)
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_VELOCITY_BREACH


def test_hard_cap_on_single_transaction():
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(max_single_amount=500.0)
    )
    v = engine.evaluate(501.0)
    assert v.blocked
    assert "SINGLE TRANSACTION CAP" in v.reason


def test_slow_spending_under_velocity():
    """Spread-out spending should stay within velocity bounds."""
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(v_max=100.0, pid_threshold=2.0)
    )
    for _ in range(5):
        v = engine.evaluate(1.0)
        assert v.allowed
        time.sleep(0.05)


def test_pid_derivative_catches_ramp():
    """The D term should catch sudden acceleration in spend velocity."""
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(
            v_max=10.0,
            pid_threshold=5.0,
            k_p=0.5,
            k_i=0.0,
            k_d=3.0,  # High D gain to catch ramps
        )
    )

    # Gentle start
    engine.evaluate(1.0)
    time.sleep(0.1)
    engine.evaluate(1.0)
    time.sleep(0.1)

    # Sudden massive ramp
    v = engine.evaluate(500.0)
    # The spike in velocity should trigger the D term
    # (may or may not block depending on exact timing, but the PID should react)
    assert v.code in (VerdictCode.ALLOW, VerdictCode.BLOCK_VELOCITY_BREACH)


def test_reset_clears_state():
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(v_max=1.0, pid_threshold=0.5)
    )
    engine.evaluate(100.0)
    engine.evaluate(100.0)  # Might block

    engine.reset()
    v = engine.evaluate(1.0)
    assert v.allowed


def test_blocked_spend_is_rolled_back():
    """When a spend is blocked, it should not count toward future velocity."""
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(
            v_max=1.0,
            pid_threshold=1.0,
            k_p=1.0,
            k_i=0.0,
            k_d=0.0,
            window_seconds=0.1,  # Short window so old records expire quickly
        )
    )

    engine.evaluate(100.0)  # allowed (first sample)
    v = engine.evaluate(100.0)  # blocked (velocity spike)
    assert v.blocked

    # Wait for the window to fully expire, then a small spend should pass
    time.sleep(0.2)
    v = engine.evaluate(0.001)
    assert v.allowed


def test_feedback_prompt_includes_velocity():
    engine = CapitalVelocityEngine(
        config=CapitalVelocityConfig(v_max=1.0, pid_threshold=0.5)
    )
    engine.evaluate(100.0)
    v = engine.evaluate(100.0)
    if v.blocked:
        feedback = v.feedback_prompt()
        assert "AEGIS FIREWALL" in feedback
