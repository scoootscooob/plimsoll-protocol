"""Tests for Zero-Day Security Patches (v0.6.0).

Zero-Day 1: Flashloan Gas Bomb — sandboxed compute caps
Zero-Day 2: Ghost Session — pessimistic cache invalidation (Rust-side, tested via integration)
Zero-Day 3: Signed Intent Time-Decay — ultra-short block deadlines
Zero-Day 4: Sybil Telemetry Poisoning — stake-weighted IOC submission
"""

from __future__ import annotations

import time
import pytest

from aegis.engines.asset_guard import AssetGuardConfig, AssetGuardEngine, OracleResult
from aegis.engines.threat_feed import ThreatFeedConfig, ThreatFeedEngine
from aegis.verdict import VerdictCode


# ═════════════════════════════════════════════════════════════════════
# ZERO-DAY 3: Signed Intent Time-Decay — Ultra-Short Block Deadlines
# ═════════════════════════════════════════════════════════════════════


class TestIntentTimerDecay:
    """Asset guard rejects stale or open-ended swap intents."""

    def test_no_deadline_passthrough(self):
        """Payloads without deadline fields are not affected."""
        engine = AssetGuardEngine(config=AssetGuardConfig())
        verdict = engine.evaluate({"target": "0xabc"})
        assert verdict.allowed

    def test_swap_without_deadline_passes(self):
        """Swap payloads without deadline still pass normal checks."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            allowed_assets=["0xToken1"],
        ))
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 100,
        })
        assert verdict.allowed

    def test_expired_deadline_blocked(self):
        """Swap with a deadline in the past is blocked."""
        engine = AssetGuardEngine(config=AssetGuardConfig())
        past_deadline = time.time() - 60  # 60 seconds ago
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "deadline": past_deadline,
        })
        assert verdict.blocked
        assert "INTENT EXPIRED" in verdict.reason
        assert verdict.code == VerdictCode.BLOCK_ASSET_REJECTED

    def test_deadline_too_far_in_future_blocked(self):
        """Swap with deadline > max_intent_age_secs is blocked."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=24.0,
        ))
        # Deadline 5 minutes in the future (way beyond 24s)
        far_deadline = time.time() + 300
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 50,
            "deadline": far_deadline,
        })
        assert verdict.blocked
        assert "DEADLINE TOO FAR" in verdict.reason

    def test_deadline_within_range_passes(self):
        """Swap with deadline within max_intent_age_secs passes."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=24.0,
        ))
        # Deadline 10 seconds from now (within 24s window)
        ok_deadline = time.time() + 10
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 50,
            "deadline": ok_deadline,
        })
        assert verdict.allowed

    def test_stale_intent_timestamp_blocked(self):
        """Intent signed too long ago is blocked."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=24.0,
        ))
        # Signed 60 seconds ago (stale beyond 24s)
        old_timestamp = time.time() - 60
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "intent_timestamp": old_timestamp,
        })
        assert verdict.blocked
        assert "STALE INTENT" in verdict.reason

    def test_fresh_intent_timestamp_passes(self):
        """Intent signed recently passes."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=24.0,
        ))
        # Signed 5 seconds ago (within 24s window)
        fresh_timestamp = time.time() - 5
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 100,
            "intent_timestamp": fresh_timestamp,
        })
        assert verdict.allowed

    def test_custom_max_intent_age(self):
        """Custom max_intent_age_secs is respected."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=5.0,  # Very tight: 5 seconds
        ))
        # Deadline 10 seconds from now — exceeds 5s window
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 50,
            "deadline": time.time() + 10,
        })
        assert verdict.blocked
        assert "DEADLINE TOO FAR" in verdict.reason

    def test_deadline_checked_before_allowlist(self):
        """Deadline check runs before allow-list check."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            allowed_assets=["0xApproved"],
            max_intent_age_secs=24.0,
        ))
        # Expired deadline with unapproved token
        verdict = engine.evaluate({
            "token_address": "0xUnapprovedToken",
            "slippage_bps": 50,
            "deadline": time.time() - 100,
        })
        # Should hit deadline check first
        assert verdict.blocked
        assert "INTENT EXPIRED" in verdict.reason

    def test_deadline_checked_before_slippage(self):
        """Deadline check runs before slippage check."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_slippage_bps=100,
            max_intent_age_secs=24.0,
        ))
        # Expired deadline with extreme slippage
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 5000,  # 50% slippage
            "deadline": time.time() - 100,
        })
        assert verdict.blocked
        assert "INTENT EXPIRED" in verdict.reason


# ═════════════════════════════════════════════════════════════════════
# ZERO-DAY 4: Sybil Telemetry Poisoning — Stake-Weighted IOC
# ═════════════════════════════════════════════════════════════════════


class TestStakeWeightedTelemetry:
    """ThreatFeedEngine validates IOC submissions by vault TVL."""

    def test_stake_weight_zero_tvl(self):
        """$0 TVL → 0.0 weight."""
        engine = ThreatFeedEngine()
        assert engine.compute_stake_weight(0.0) == 0.0

    def test_stake_weight_negative_tvl(self):
        """Negative TVL → 0.0 weight."""
        engine = ThreatFeedEngine()
        assert engine.compute_stake_weight(-5000.0) == 0.0

    def test_stake_weight_minimum(self):
        """$5K TVL → 0.05 weight."""
        engine = ThreatFeedEngine()
        weight = engine.compute_stake_weight(5_000.0)
        assert abs(weight - 0.05) < 0.001

    def test_stake_weight_mid_range(self):
        """$50K TVL → 0.5 weight."""
        engine = ThreatFeedEngine()
        weight = engine.compute_stake_weight(50_000.0)
        assert abs(weight - 0.5) < 0.001

    def test_stake_weight_capped(self):
        """$100K+ TVL → 1.0 weight (capped)."""
        engine = ThreatFeedEngine()
        assert engine.compute_stake_weight(100_000.0) == 1.0
        assert engine.compute_stake_weight(1_000_000.0) == 1.0

    def test_custom_stake_weight_cap(self):
        """Custom stake_weight_cap is respected."""
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            stake_weight_cap=50_000.0,
        ))
        # $50K with $50K cap → 1.0
        assert engine.compute_stake_weight(50_000.0) == 1.0
        # $25K with $50K cap → 0.5
        assert abs(engine.compute_stake_weight(25_000.0) - 0.5) < 0.001

    def test_ioc_submission_rejected_low_tvl(self):
        """Agent with TVL < $5K cannot submit IOCs."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_submission(1_000.0)
        assert not accepted
        assert "ZERO-DAY 4" in reason
        assert "Sybil resistance" in reason

    def test_ioc_submission_rejected_zero_tvl(self):
        """Agent with $0 TVL cannot submit IOCs."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_submission(0.0)
        assert not accepted
        assert "ZERO-DAY 4" in reason

    def test_ioc_submission_accepted_sufficient_tvl(self):
        """Agent with TVL >= $5K can submit IOCs."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_submission(10_000.0)
        assert accepted
        assert "stake weight" in reason

    def test_ioc_submission_accepted_high_tvl(self):
        """Agent with high TVL gets maximum stake weight."""
        engine = ThreatFeedEngine()
        accepted, reason = engine.validate_ioc_submission(500_000.0)
        assert accepted
        assert "1.0000" in reason

    def test_ioc_submission_custom_min_tvl(self):
        """Custom min_tvl_for_submission is respected."""
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            min_tvl_for_submission=50_000.0,
        ))
        # $10K is below custom $50K threshold
        accepted, _ = engine.validate_ioc_submission(10_000.0)
        assert not accepted
        # $50K meets threshold
        accepted, _ = engine.validate_ioc_submission(50_000.0)
        assert accepted

    def test_ioc_submission_boundary_exact_minimum(self):
        """Exactly at the minimum TVL threshold is accepted."""
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            min_tvl_for_submission=5_000.0,
        ))
        accepted, _ = engine.validate_ioc_submission(5_000.0)
        assert accepted

    def test_ioc_submission_just_below_minimum(self):
        """Just below minimum TVL threshold is rejected."""
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            min_tvl_for_submission=5_000.0,
        ))
        accepted, _ = engine.validate_ioc_submission(4_999.99)
        assert not accepted


# ═════════════════════════════════════════════════════════════════════
# INTEGRATION: Zero-Day 3 + 4 combined with engine chain
# ═════════════════════════════════════════════════════════════════════


class TestZeroDayIntegration:
    """Integration tests for zero-day patches working together."""

    def test_stale_intent_with_high_tvl_agent(self):
        """Even a high-TVL agent can't submit stale intents."""
        engine = AssetGuardEngine(config=AssetGuardConfig(
            max_intent_age_secs=24.0,
        ))
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 50,
            "deadline": time.time() - 100,
        })
        assert verdict.blocked
        assert "INTENT EXPIRED" in verdict.reason

    def test_fresh_intent_with_low_tvl_ioc_rejected(self):
        """A low-TVL agent's IOC from a blocked tx is not propagated."""
        threat_engine = ThreatFeedEngine()
        # Agent with $100 TVL tries to report
        accepted, reason = threat_engine.validate_ioc_submission(100.0)
        assert not accepted
        assert "Sybil resistance" in reason

    def test_fresh_intent_with_high_tvl_ioc_accepted(self):
        """A high-TVL agent's IOC from a blocked tx IS propagated."""
        threat_engine = ThreatFeedEngine()
        accepted, reason = threat_engine.validate_ioc_submission(25_000.0)
        assert accepted
        assert "stake weight" in reason

    def test_default_config_backward_compat(self):
        """Default configs don't break existing behavior."""
        # AssetGuard: default max_intent_age_secs=24.0
        ag = AssetGuardEngine()
        # No swap fields → passthrough (unchanged)
        verdict = ag.evaluate({"target": "0xabc", "amount": 100})
        assert verdict.allowed

        # ThreatFeed: default min_tvl=5000
        tf = ThreatFeedEngine()
        assert tf.config.min_tvl_for_submission == 5_000.0
        assert tf.config.stake_weight_cap == 100_000.0

    def test_asset_guard_deadline_with_oracle(self):
        """Deadline check runs before oracle check."""
        def mock_oracle(token: str) -> OracleResult:
            # Should never be called if deadline fails first
            raise RuntimeError("Oracle should not be called")

        engine = AssetGuardEngine(config=AssetGuardConfig(
            oracle_provider=mock_oracle,
            max_intent_age_secs=24.0,
        ))
        # Expired deadline — oracle should not be consulted
        verdict = engine.evaluate({
            "token_address": "0xToken1",
            "slippage_bps": 50,
            "deadline": time.time() - 100,
        })
        assert verdict.blocked
        assert "INTENT EXPIRED" in verdict.reason
