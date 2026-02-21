"""Tests for Engine 6: EVM Simulator (Pre-Execution Validation)."""

from __future__ import annotations

from plimsoll.engines.evm_simulator import (
    EVMSimulatorEngine,
    EVMSimulatorConfig,
    SimulationResult,
)
from plimsoll.verdict import VerdictCode


def test_disabled_passthrough():
    """Disabled simulator should pass everything through."""
    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(enabled=False)
    )
    v = engine.evaluate({"to": "0xDEAD", "data": "0x1234"})
    assert v.allowed
    assert "disabled" in v.reason.lower()


def test_no_evm_fields_passthrough():
    """Payloads without EVM transaction fields should pass."""
    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(enabled=True)
    )
    v = engine.evaluate({"amount": 100, "function": "transfer"})
    assert v.allowed
    assert "No EVM" in v.reason


def test_no_simulator_fail_closed():
    """No simulator configured + fail_closed should block."""
    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=None,
            fail_closed=True,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_SIMULATION_REJECTED
    assert "NO SIMULATOR" in v.reason


def test_no_simulator_fail_open():
    """No simulator configured + fail_closed=False should pass."""
    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=None,
            fail_closed=False,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.allowed


def test_simulation_success_passes():
    """Successful simulation with no issues should pass."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            gas_used=21000,
            balance_before=10.0,
            balance_after=9.5,
            net_worth_before_usd=10000,
            net_worth_after_usd=9500,
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            max_loss_pct=20.0,
        )
    )
    v = engine.evaluate({"to": "0xDEAD", "value": 0.5})
    assert v.allowed
    assert v.metadata["gas_used"] == 21000


def test_simulation_revert_blocks():
    """Reverted simulation should block."""
    def mock_sim(payload):
        return SimulationResult(
            success=False,
            error="execution reverted: insufficient balance",
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(enabled=True, simulator=mock_sim)
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_SIMULATION_REJECTED
    assert "REVERTED" in v.reason


def test_excessive_loss_blocks():
    """Net worth drop exceeding max_loss_pct should block."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            net_worth_before_usd=10000,
            net_worth_after_usd=5000,  # 50% loss
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            max_loss_pct=20.0,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_SIMULATION_REJECTED
    assert "EXCESSIVE LOSS" in v.reason
    assert v.metadata["loss_pct"] == 50.0


def test_loss_within_limit_passes():
    """Net worth drop within max_loss_pct should pass."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            net_worth_before_usd=10000,
            net_worth_after_usd=8500,  # 15% loss
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            max_loss_pct=20.0,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.allowed


def test_approval_change_blocks():
    """Unexpected token approval changes should block."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            approvals_changed=["0xUSDC", "0xWETH"],
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            block_on_approval_change=True,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert "APPROVAL MANIPULATION" in v.reason


def test_approval_change_allowed_when_disabled():
    """Approval changes should pass when block_on_approval_change=False."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            approvals_changed=["0xUSDC"],
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            block_on_approval_change=False,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.allowed


def test_blocked_contract_blocks():
    """Interaction with blocked contract should block."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            calls_trace=["0xRouterV2", "0xMalicious", "0xUSDC"],
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            blocked_contracts=["0xmalicious"],  # Case insensitive
        )
    )
    v = engine.evaluate({"to": "0xRouterV2"})
    assert v.blocked
    assert "BLOCKED CONTRACT" in v.reason


def test_blocked_contract_case_insensitive():
    """Blocked contract matching should be case insensitive."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            calls_trace=["0xAABB"],
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            blocked_contracts=["0xaabb"],
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked


def test_simulator_exception_fail_closed():
    """Simulator throwing exception + fail_closed should block."""
    def broken_sim(payload):
        raise ConnectionError("Tenderly API down")

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=broken_sim,
            fail_closed=True,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert "SIMULATION FAILURE" in v.reason


def test_simulator_exception_fail_open():
    """Simulator throwing exception + fail_closed=False should pass."""
    def broken_sim(payload):
        raise ConnectionError("Tenderly API down")

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=broken_sim,
            fail_closed=False,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.allowed


def test_check_order_revert_before_loss():
    """Revert check should come before net worth loss check."""
    def mock_sim(payload):
        return SimulationResult(
            success=False,
            error="revert",
            net_worth_before_usd=10000,
            net_worth_after_usd=0,  # Total loss, but tx reverted
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(enabled=True, simulator=mock_sim)
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.blocked
    assert "REVERTED" in v.reason  # Not EXCESSIVE LOSS


def test_target_field_recognized():
    """'target' field (Plimsoll convention) should trigger simulation."""
    sim_called = []

    def spy_sim(payload):
        sim_called.append(True)
        return SimulationResult(success=True)

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(enabled=True, simulator=spy_sim)
    )
    v = engine.evaluate({"target": "0xDEAD", "amount": 100})
    assert v.allowed
    assert len(sim_called) == 1


def test_zero_net_worth_skips_loss_check():
    """Zero net_worth_before should skip the percentage loss check."""
    def mock_sim(payload):
        return SimulationResult(
            success=True,
            net_worth_before_usd=0.0,
            net_worth_after_usd=0.0,
        )

    engine = EVMSimulatorEngine(
        config=EVMSimulatorConfig(
            enabled=True,
            simulator=mock_sim,
            max_loss_pct=20.0,
        )
    )
    v = engine.evaluate({"to": "0xDEAD"})
    assert v.allowed  # No division by zero


def test_reset_is_noop():
    """EVMSimulator is stateless, reset should not fail."""
    engine = EVMSimulatorEngine()
    engine.reset()
