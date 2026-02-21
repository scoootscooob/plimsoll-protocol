"""
plimsoll.oracles.price_feed — Pluggable price oracle with caching.

Converts Wei, Lamports, and Satoshis into a Universal USD Value so that
$5 of Stripe API spend and $5 of ETH slippage hit the *exact same*
CapitalVelocity PID limit.

Usage::

    from plimsoll.oracles.price_feed import PriceFeed, PriceFeedConfig

    # With hardcoded fallback prices (no network calls)
    feed = PriceFeed()
    usd = feed.wei_to_usd(1e18)           # 1 ETH → ~$3000
    usd = feed.lamports_to_usd(1e9)       # 1 SOL → ~$150
    usd = feed.satoshis_to_usd(1e8)       # 1 BTC → ~$60000

    # With a live provider (Pyth / Chainlink / CoinGecko / custom)
    def my_provider(asset: str) -> PriceQuote:
        price = fetch_from_pyth(asset)
        return PriceQuote(asset=asset, price_usd=price, ...)

    feed = PriceFeed(config=PriceFeedConfig(provider=my_provider))
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("plimsoll.oracles")


# ── PriceQuote ────────────────────────────────────────────────────


@dataclass(frozen=True)
class PriceQuote:
    """An immutable price quote from an oracle."""

    asset: str
    price_usd: float
    timestamp: float
    source: str = ""


# ── PriceFeedConfig ───────────────────────────────────────────────


@dataclass
class PriceFeedConfig:
    """Configuration for the price feed oracle.

    Attributes
    ----------
    cache_ttl_seconds : float
        How long a cached price is valid (default 60 s).
    fallback_prices : dict
        Static USD prices used when the live provider is unavailable.
    provider : callable, optional
        ``(asset: str) → PriceQuote``.  If ``None``, fallback prices
        are used exclusively.
    """

    cache_ttl_seconds: float = 60.0
    fallback_prices: dict[str, float] = field(default_factory=lambda: {
        "ETH":   3_000.0,
        "BTC":  60_000.0,
        "SOL":     150.0,
        "MATIC":     0.50,
        "AVAX":     35.0,
        "BNB":     600.0,
    })
    provider: Optional[Callable[[str], PriceQuote]] = None


# ── PriceFeed ─────────────────────────────────────────────────────


@dataclass
class PriceFeed:
    """Pluggable price oracle with in-memory TTL cache."""

    config: PriceFeedConfig = field(default_factory=PriceFeedConfig)

    # Internal cache: asset_upper → (fetched_at, PriceQuote)
    _cache: dict[str, tuple[float, PriceQuote]] = field(
        default_factory=dict, init=False, repr=False,
    )

    # ── Core query ────────────────────────────────────────────────

    def get_price_usd(self, asset: str) -> float:
        """Return the USD price of *asset*.  Falls back to hardcoded price."""
        key = asset.upper()
        now = time.time()

        # 1. Cache hit
        if key in self._cache:
            fetched_at, quote = self._cache[key]
            if now - fetched_at < self.config.cache_ttl_seconds:
                return quote.price_usd

        # 2. Live provider
        if self.config.provider is not None:
            try:
                quote = self.config.provider(key)
                self._cache[key] = (now, quote)
                return quote.price_usd
            except Exception as exc:
                logger.warning("Price oracle failed for %s: %s", key, exc)

        # 3. Static fallback
        return self.config.fallback_prices.get(key, 0.0)

    # ── Convenience converters ────────────────────────────────────

    def wei_to_usd(self, wei: float) -> float:
        """Convert Wei to USD (1 ETH = 10^18 Wei)."""
        return (wei / 1e18) * self.get_price_usd("ETH")

    def lamports_to_usd(self, lamports: float) -> float:
        """Convert Lamports to USD (1 SOL = 10^9 Lamports)."""
        return (lamports / 1e9) * self.get_price_usd("SOL")

    def satoshis_to_usd(self, sats: float) -> float:
        """Convert Satoshis to USD (1 BTC = 10^8 Satoshis)."""
        return (sats / 1e8) * self.get_price_usd("BTC")

    def normalize_to_usd(self, amount: float, unit: str) -> float:
        """Convert any supported unit to USD.

        Supported units: ``wei``, ``gwei``, ``eth``, ``lamports``, ``sol``,
        ``satoshis`` / ``sats``, ``btc``, ``usd``, ``cents``.
        """
        converters: dict[str, Callable[[float], float]] = {
            "wei":      self.wei_to_usd,
            "gwei":     lambda x: self.wei_to_usd(x * 1e9),
            "eth":      lambda x: x * self.get_price_usd("ETH"),
            "lamports": self.lamports_to_usd,
            "sol":      lambda x: x * self.get_price_usd("SOL"),
            "satoshis": self.satoshis_to_usd,
            "sats":     self.satoshis_to_usd,
            "btc":      lambda x: x * self.get_price_usd("BTC"),
            "usd":      lambda x: x,
            "cents":    lambda x: x / 100.0,
        }
        converter = converters.get(unit.lower())
        if converter is not None:
            return converter(amount)
        # Unknown unit — return raw value
        return amount
