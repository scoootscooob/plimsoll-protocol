"""
Engine 4: Asset Guard — Oracle-Backed Swap Validation.

Protects against economic manipulation attacks where an AI agent is tricked
into executing bad swaps (e.g., buying illiquid tokens, accepting extreme
slippage, trading unapproved assets). This is *not* theft of funds via
direct transfer — it's theft via intentionally bad trades.

Checks (in order):
    1. Allow-list: Is the token on the approved trading list?
    2. Slippage:   Does the proposed slippage exceed the max?
    3. Liquidity:  Does the oracle confirm sufficient market depth?

The oracle provider is a pluggable callable, so Aegis itself never
imports any specific DeFi SDK.

Time complexity: O(1) + oracle latency.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from aegis.verdict import Verdict, VerdictCode

_ENGINE_NAME = "AssetGuard"
logger = logging.getLogger("aegis")


@dataclass(frozen=True)
class OracleResult:
    """Response from a liquidity oracle query."""

    liquidity_usd: float
    price_usd: float = 0.0
    source: str = "unknown"


@dataclass
class AssetGuardConfig:
    """Tunable parameters for the asset guard engine."""

    min_liquidity_usd: float = 1_000_000.0   # $1M minimum pool liquidity
    max_slippage_bps: int = 300                # 3% max slippage (basis points)
    allowed_assets: list[str] = field(default_factory=list)  # Empty = allow all
    oracle_provider: Optional[Callable[[str], OracleResult]] = None


@dataclass
class AssetGuardEngine:
    """Oracle-backed swap validation engine.

    Evaluates payloads that contain swap-related fields:
        - ``token_address``: The token being swapped to/from.
        - ``slippage_bps``: Proposed slippage tolerance in basis points.

    Payloads without these fields pass through (ALLOW).
    """

    config: AssetGuardConfig = field(default_factory=AssetGuardConfig)

    def evaluate(self, payload: dict[str, Any]) -> Verdict:
        """Evaluate a payload for asset-related risks."""

        token_address = payload.get("token_address")
        slippage_bps = payload.get("slippage_bps")

        # No swap fields → passthrough
        if token_address is None and slippage_bps is None:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No swap fields in payload — passthrough",
                engine=_ENGINE_NAME,
            )

        # ── Check 1: Allow-list ──────────────────────────────────
        if token_address and self.config.allowed_assets:
            normalised = token_address.lower()
            allowed_lower = [a.lower() for a in self.config.allowed_assets]
            if normalised not in allowed_lower:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"ASSET NOT APPROVED: {token_address} is not in the "
                        f"allow-list ({len(self.config.allowed_assets)} assets)"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "token_address": token_address,
                        "allowed_count": len(self.config.allowed_assets),
                    },
                )

        # ── Check 2: Slippage ────────────────────────────────────
        if slippage_bps is not None:
            if slippage_bps > self.config.max_slippage_bps:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"SLIPPAGE TOO HIGH: {slippage_bps} bps exceeds "
                        f"max {self.config.max_slippage_bps} bps"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "slippage_bps": slippage_bps,
                        "max_slippage_bps": self.config.max_slippage_bps,
                    },
                )

        # ── Check 3: Oracle liquidity ────────────────────────────
        if token_address and self.config.oracle_provider is not None:
            try:
                oracle_result = self.config.oracle_provider(token_address)
            except Exception as exc:
                # Fail closed — oracle error means we block
                logger.warning(
                    "AssetGuard oracle failure for %s: %s", token_address, exc
                )
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"ORACLE FAILURE: Could not verify liquidity for "
                        f"{token_address} — fail closed. Error: {exc}"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={"token_address": token_address, "error": str(exc)},
                )

            if oracle_result.liquidity_usd < self.config.min_liquidity_usd:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"INSUFFICIENT LIQUIDITY: {token_address} has "
                        f"${oracle_result.liquidity_usd:,.0f} liquidity "
                        f"(min ${self.config.min_liquidity_usd:,.0f})"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "token_address": token_address,
                        "liquidity_usd": oracle_result.liquidity_usd,
                        "min_liquidity_usd": self.config.min_liquidity_usd,
                        "price_usd": oracle_result.price_usd,
                        "source": oracle_result.source,
                    },
                )

        # All checks passed
        return Verdict(
            code=VerdictCode.ALLOW,
            reason="Asset guard checks passed",
            engine=_ENGINE_NAME,
            metadata={
                "token_address": token_address,
                "slippage_bps": slippage_bps,
            },
        )

    def reset(self) -> None:
        """No-op — AssetGuard is stateless."""
        pass
