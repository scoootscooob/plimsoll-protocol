"""Tests for Engine 0: Global Threat Feed (Python SDK)."""

from __future__ import annotations

import pytest
from plimsoll.engines.threat_feed import (
    ThreatFeedEngine,
    ThreatFeedConfig,
    IMMUNE_PROTOCOLS,
)
from plimsoll.verdict import VerdictCode
from plimsoll.firewall import PlimsollFirewall, PlimsollConfig


# ── Unit tests: ThreatFeedEngine ──────────────────────────────────────


class TestThreatFeedDisabledByDefault:
    """Engine 0 is disabled by default for backward compatibility."""

    def test_disabled_allows_everything(self):
        engine = ThreatFeedEngine()
        engine.add_address("0xHacker")
        v = engine.evaluate({"target": "0xhacker", "amount": 100})
        assert v.allowed
        assert v.reason == "Engine 0 disabled"

    def test_enabled_but_empty_allows(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        v = engine.evaluate({"target": "0xAnything", "amount": 100})
        assert v.allowed
        assert v.reason == "No threat feed loaded"


class TestAddressBlacklist:
    """Address-based blacklisting."""

    def test_blacklisted_address_blocked(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xHacker123")
        engine._version = 1
        engine._consensus_count = 12
        v = engine.evaluate({"target": "0xhacker123", "amount": 100})
        assert v.blocked
        assert v.code is VerdictCode.BLOCK_GLOBAL_BLACKLIST
        assert "globally blacklisted" in v.reason
        assert "12 agents" in v.reason
        assert v.metadata["blocked_field"] == "address"

    def test_case_insensitive_match(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xABCDEF")
        v = engine.evaluate({"target": "0xabcdef"})
        assert v.blocked

    def test_clean_address_passes(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xBadGuy")
        v = engine.evaluate({"target": "0xGoodGuy", "amount": 100})
        assert v.allowed

    def test_no_target_field_passes(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xBadGuy")
        v = engine.evaluate({"amount": 100})
        assert v.allowed


class TestSelectorBlacklist:
    """Function selector blacklisting."""

    def test_blacklisted_selector_blocked(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_selector("0xdeadbeef")
        v = engine.evaluate({
            "target": "0xSafe",
            "function": "0xDEADBEEF",
        })
        assert v.blocked
        assert v.code is VerdictCode.BLOCK_GLOBAL_BLACKLIST
        assert "known drainer signature" in v.reason
        assert v.metadata["blocked_field"] == "selector"

    def test_clean_selector_passes(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_selector("0xdeadbeef")
        v = engine.evaluate({
            "target": "0xSafe",
            "function": "0xa9059cbb",  # transfer()
        })
        assert v.allowed


class TestCalldataHashBlacklist:
    """Calldata hash blacklisting."""

    def test_blacklisted_calldata_blocked(self):
        import hashlib
        data_hex = "0xdeadbeef01020304"
        expected_hash = hashlib.sha256(data_hex.encode()).hexdigest()[:16]

        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_calldata_hash(expected_hash)
        v = engine.evaluate({
            "target": "0xSafe",
            "data": data_hex,
        })
        assert v.blocked
        assert v.code is VerdictCode.BLOCK_GLOBAL_BLACKLIST
        assert "exploit payload" in v.reason

    def test_clean_calldata_passes(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_calldata_hash("aaaaaaaaaaaaaaaa")
        v = engine.evaluate({
            "target": "0xSafe",
            "data": "0x01020304",
        })
        assert v.allowed


class TestAntiGriefing:
    """Anti-griefing: immune protocols cannot be blacklisted."""

    def test_uniswap_v2_immune(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        uniswap = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        engine.add_address(uniswap)
        v = engine.evaluate({"target": uniswap})
        # Despite being in the blacklist, Uniswap is immune
        assert v.allowed

    def test_aave_v3_immune(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        aave = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
        engine.add_address(aave)
        v = engine.evaluate({"target": aave})
        assert v.allowed

    def test_custom_immune_address(self):
        custom = "0xMyProtocol123"
        engine = ThreatFeedEngine(config=ThreatFeedConfig(
            enabled=True,
            immune_addresses={custom},
        ))
        engine.add_address(custom)
        v = engine.evaluate({"target": custom})
        assert v.allowed

    def test_unknown_address_not_immune(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        assert not engine.is_immune("0xNewDrainer123")

    def test_all_builtin_protocols_immune(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        for addr in IMMUNE_PROTOCOLS:
            assert engine.is_immune(addr), f"{addr} should be immune"


class TestCloudReplacement:
    """Cloud push replaces entire filter."""

    def test_replace_clears_old_entries(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xOldThreat")

        engine.replace_from_cloud(
            addresses=["0xNewThreat1", "0xNewThreat2"],
            selectors=[],
            calldata_hashes=[],
            version=42,
            consensus_count=100,
        )

        # Old threat is gone
        v = engine.evaluate({"target": "0xoldthreat"})
        assert v.allowed

        # New threats are active
        v = engine.evaluate({"target": "0xnewthreat1"})
        assert v.blocked

        assert engine._version == 42
        assert engine._consensus_count == 100

    def test_replace_updates_metadata(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.replace_from_cloud([], [], [], 99, 500)
        assert engine._version == 99
        assert engine._consensus_count == 500
        assert engine._last_updated > 0


class TestEngineStats:
    """Stats and size tracking."""

    def test_empty_engine(self):
        engine = ThreatFeedEngine()
        assert engine.is_empty()
        assert engine.size == 0

    def test_size_counts_all_types(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xa")
        engine.add_selector("0xb")
        engine.add_calldata_hash("c")
        assert engine.size == 3
        assert not engine.is_empty()

    def test_stats_tracks_blocks(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xBad")
        engine.evaluate({"target": "0xbad"})
        engine.evaluate({"target": "0xbad"})
        assert engine.stats["blocks"] == 2

    def test_reset_clears_everything(self):
        engine = ThreatFeedEngine(config=ThreatFeedConfig(enabled=True))
        engine.add_address("0xBad")
        engine.evaluate({"target": "0xbad"})
        engine.reset()
        assert engine.is_empty()
        assert engine.stats["blocks"] == 0
        assert engine._version == 0


# ── Integration tests: Firewall ──────────────────────────────────────


class TestFirewallIntegration:
    """Engine 0 wired into the firewall chain."""

    def test_disabled_by_default_no_impact(self):
        """Default config has threat_feed disabled — zero behavioral change."""
        fw = PlimsollFirewall()
        v = fw.evaluate({"target": "0xAnything", "amount": 100}, spend_amount=100)
        assert v.allowed

    def test_enabled_blocks_blacklisted_address(self):
        cfg = PlimsollConfig(
            threat_feed=ThreatFeedConfig(enabled=True),
        )
        fw = PlimsollFirewall(config=cfg)
        fw.threat_feed.add_address("0xDrainer666")
        fw.threat_feed._version = 5
        fw.threat_feed._consensus_count = 25

        v = fw.evaluate({"target": "0xdrainer666", "amount": 100}, spend_amount=100)
        assert v.blocked
        assert v.code is VerdictCode.BLOCK_GLOBAL_BLACKLIST
        assert "globally blacklisted" in v.reason

    def test_engine0_runs_before_trajectory(self):
        """Engine 0 should catch threats before Engine 1 even sees them."""
        cfg = PlimsollConfig(
            threat_feed=ThreatFeedConfig(enabled=True),
        )
        fw = PlimsollFirewall(config=cfg)
        fw.threat_feed.add_address("0xAttacker")

        # Same payload twice — if Engine 0 weren't first, Engine 1 (trajectory)
        # would catch the loop on the second call. But Engine 0 catches on first.
        v1 = fw.evaluate({"target": "0xattacker", "amount": 100})
        assert v1.code is VerdictCode.BLOCK_GLOBAL_BLACKLIST

    def test_immune_address_passes_through(self):
        """Immune protocols pass Engine 0 even if blacklisted."""
        cfg = PlimsollConfig(
            threat_feed=ThreatFeedConfig(enabled=True),
        )
        fw = PlimsollFirewall(config=cfg)
        uniswap = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
        fw.threat_feed.add_address(uniswap)

        v = fw.evaluate({"target": uniswap, "amount": 100}, spend_amount=100)
        # Should pass Engine 0 (immune) and reach Engine 1+
        assert v.code is not VerdictCode.BLOCK_GLOBAL_BLACKLIST

    def test_reset_clears_threat_feed(self):
        cfg = PlimsollConfig(
            threat_feed=ThreatFeedConfig(enabled=True),
        )
        fw = PlimsollFirewall(config=cfg)
        fw.threat_feed.add_address("0xBadGuy")
        fw.reset()
        assert fw.threat_feed.is_empty()

    def test_stats_includes_engine0_blocks(self):
        cfg = PlimsollConfig(
            threat_feed=ThreatFeedConfig(enabled=True),
        )
        fw = PlimsollFirewall(config=cfg)
        fw.threat_feed.add_address("0xBad")
        fw.evaluate({"target": "0xbad"})
        assert fw.stats["blocked"] == 1
