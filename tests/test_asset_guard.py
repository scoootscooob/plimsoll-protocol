"""Tests for Engine 4: Asset Guard (Oracle-Backed Swap Validation)."""

from __future__ import annotations

from plimsoll.engines.asset_guard import (
    AssetGuardEngine,
    AssetGuardConfig,
    OracleResult,
)
from plimsoll.verdict import VerdictCode


def test_passthrough_no_swap_fields():
    """Payloads without swap fields should pass through."""
    engine = AssetGuardEngine()
    v = engine.evaluate({"target": "0xDEAD", "amount": 100, "function": "transfer"})
    assert v.allowed
    assert "passthrough" in v.reason.lower()


def test_allow_list_pass():
    """Token on the allow-list should pass."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            allowed_assets=["0xAAA", "0xBBB"],
        )
    )
    v = engine.evaluate({"token_address": "0xAAA", "slippage_bps": 100})
    assert v.allowed


def test_allow_list_block():
    """Token NOT on the allow-list should be blocked."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            allowed_assets=["0xAAA", "0xBBB"],
        )
    )
    v = engine.evaluate({"token_address": "0xCCC", "slippage_bps": 100})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_ASSET_REJECTED
    assert "NOT APPROVED" in v.reason


def test_allow_list_case_insensitive():
    """Allow-list comparison should be case-insensitive."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            allowed_assets=["0xAaA"],
        )
    )
    v = engine.evaluate({"token_address": "0xaaa", "slippage_bps": 100})
    assert v.allowed


def test_empty_allow_list_allows_all():
    """Empty allow-list means all tokens are allowed."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            allowed_assets=[],  # Empty — allow all
        )
    )
    v = engine.evaluate({"token_address": "0xANYTHING", "slippage_bps": 100})
    assert v.allowed


def test_slippage_within_limit():
    """Slippage within limit should pass."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(max_slippage_bps=300)
    )
    v = engine.evaluate({"slippage_bps": 200})
    assert v.allowed


def test_slippage_exceeds_limit():
    """Slippage above limit should be blocked."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(max_slippage_bps=300)
    )
    v = engine.evaluate({"slippage_bps": 500})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_ASSET_REJECTED
    assert "SLIPPAGE TOO HIGH" in v.reason


def test_slippage_exact_limit():
    """Slippage exactly at limit should pass (not greater than)."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(max_slippage_bps=300)
    )
    v = engine.evaluate({"slippage_bps": 300})
    assert v.allowed


def test_oracle_liquidity_pass():
    """Sufficient liquidity should pass."""
    def mock_oracle(token: str) -> OracleResult:
        return OracleResult(liquidity_usd=5_000_000, price_usd=1.0, source="test")

    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            min_liquidity_usd=1_000_000,
            oracle_provider=mock_oracle,
        )
    )
    v = engine.evaluate({"token_address": "0xAAA", "slippage_bps": 100})
    assert v.allowed


def test_oracle_liquidity_fail():
    """Insufficient liquidity should be blocked."""
    def mock_oracle(token: str) -> OracleResult:
        return OracleResult(liquidity_usd=100_000, price_usd=0.01, source="test")

    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            min_liquidity_usd=1_000_000,
            oracle_provider=mock_oracle,
        )
    )
    v = engine.evaluate({"token_address": "0xAAA", "slippage_bps": 100})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_ASSET_REJECTED
    assert "INSUFFICIENT LIQUIDITY" in v.reason


def test_oracle_failure_fail_closed():
    """Oracle exception should result in a block (fail closed)."""
    def broken_oracle(token: str) -> OracleResult:
        raise ConnectionError("Oracle unavailable")

    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            oracle_provider=broken_oracle,
        )
    )
    v = engine.evaluate({"token_address": "0xAAA", "slippage_bps": 100})
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_ASSET_REJECTED
    assert "ORACLE FAILURE" in v.reason


def test_oracle_not_called_without_token_address():
    """Oracle should not be invoked if there's no token_address."""
    oracle_called = []

    def spy_oracle(token: str) -> OracleResult:
        oracle_called.append(token)
        return OracleResult(liquidity_usd=5_000_000)

    engine = AssetGuardEngine(
        config=AssetGuardConfig(oracle_provider=spy_oracle)
    )
    # Only slippage_bps, no token_address
    v = engine.evaluate({"slippage_bps": 100})
    assert v.allowed
    assert len(oracle_called) == 0


def test_check_order_allow_list_before_slippage():
    """Allow-list check should come before slippage check."""
    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            allowed_assets=["0xAAA"],
            max_slippage_bps=300,
        )
    )
    # Token not in allow-list AND slippage too high
    v = engine.evaluate({"token_address": "0xBAD", "slippage_bps": 999})
    assert v.blocked
    assert "NOT APPROVED" in v.reason  # Should be allow-list, not slippage


def test_check_order_slippage_before_oracle():
    """Slippage check should come before oracle liquidity check."""
    oracle_called = []

    def spy_oracle(token: str) -> OracleResult:
        oracle_called.append(token)
        return OracleResult(liquidity_usd=100)  # Low liquidity

    engine = AssetGuardEngine(
        config=AssetGuardConfig(
            max_slippage_bps=100,
            oracle_provider=spy_oracle,
        )
    )
    # Slippage too high — oracle should NOT be called
    v = engine.evaluate({"token_address": "0xAAA", "slippage_bps": 500})
    assert v.blocked
    assert "SLIPPAGE" in v.reason
    assert len(oracle_called) == 0


def test_reset_is_noop():
    """AssetGuard is stateless, reset should not fail."""
    engine = AssetGuardEngine()
    engine.evaluate({"token_address": "0xAAA"})
    engine.reset()
    v = engine.evaluate({"token_address": "0xAAA"})
    assert v.allowed  # Still works after reset
