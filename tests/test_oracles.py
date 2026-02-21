"""Tests for the ``plimsoll.oracles.price_feed`` module."""

from __future__ import annotations

import time

import pytest

from plimsoll.oracles.price_feed import PriceFeed, PriceFeedConfig, PriceQuote


class TestPriceFeedFallbacks:
    def test_default_eth_price(self) -> None:
        feed = PriceFeed()
        assert feed.get_price_usd("ETH") == 3_000.0

    def test_default_btc_price(self) -> None:
        feed = PriceFeed()
        assert feed.get_price_usd("BTC") == 60_000.0

    def test_default_sol_price(self) -> None:
        feed = PriceFeed()
        assert feed.get_price_usd("SOL") == 150.0

    def test_unknown_asset_returns_zero(self) -> None:
        feed = PriceFeed()
        assert feed.get_price_usd("UNKNOWN_COIN") == 0.0

    def test_case_insensitive(self) -> None:
        feed = PriceFeed()
        assert feed.get_price_usd("eth") == 3_000.0
        assert feed.get_price_usd("Eth") == 3_000.0


class TestPriceFeedProvider:
    def test_provider_called(self) -> None:
        calls = []

        def provider(asset: str) -> PriceQuote:
            calls.append(asset)
            return PriceQuote(asset=asset, price_usd=4000.0, timestamp=time.time())

        feed = PriceFeed(config=PriceFeedConfig(provider=provider))
        price = feed.get_price_usd("ETH")
        assert price == 4000.0
        assert calls == ["ETH"]

    def test_provider_failure_falls_back(self) -> None:
        def failing_provider(asset: str) -> PriceQuote:
            raise ConnectionError("Network down")

        feed = PriceFeed(config=PriceFeedConfig(provider=failing_provider))
        price = feed.get_price_usd("ETH")
        assert price == 3_000.0  # Fallback

    def test_cache_hit(self) -> None:
        call_count = 0

        def provider(asset: str) -> PriceQuote:
            nonlocal call_count
            call_count += 1
            return PriceQuote(asset=asset, price_usd=5000.0, timestamp=time.time())

        feed = PriceFeed(config=PriceFeedConfig(
            provider=provider,
            cache_ttl_seconds=60.0,
        ))

        feed.get_price_usd("ETH")
        feed.get_price_usd("ETH")
        feed.get_price_usd("ETH")
        assert call_count == 1  # Only called once, then cached


class TestConversions:
    def test_wei_to_usd(self) -> None:
        feed = PriceFeed()  # ETH=$3000
        usd = feed.wei_to_usd(1e18)  # 1 ETH
        assert usd == pytest.approx(3_000.0)

    def test_lamports_to_usd(self) -> None:
        feed = PriceFeed()  # SOL=$150
        usd = feed.lamports_to_usd(1e9)  # 1 SOL
        assert usd == pytest.approx(150.0)

    def test_satoshis_to_usd(self) -> None:
        feed = PriceFeed()  # BTC=$60000
        usd = feed.satoshis_to_usd(1e8)  # 1 BTC
        assert usd == pytest.approx(60_000.0)

    def test_normalize_to_usd_wei(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(1e18, "wei") == pytest.approx(3_000.0)

    def test_normalize_to_usd_gwei(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(1e9, "gwei") == pytest.approx(3_000.0)

    def test_normalize_to_usd_cents(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(5000, "cents") == pytest.approx(50.0)

    def test_normalize_to_usd_usd_passthrough(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(42.0, "usd") == 42.0

    def test_normalize_to_usd_unknown_unit(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(123.0, "zorkmid") == 123.0

    def test_normalize_sol(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(2.0, "sol") == pytest.approx(300.0)

    def test_normalize_btc(self) -> None:
        feed = PriceFeed()
        assert feed.normalize_to_usd(0.5, "btc") == pytest.approx(30_000.0)
