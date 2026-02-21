"""
Engine 0: Global Threat Feed — The Swarm's Immune System (Python SDK).

Every Plimsoll firewall instance can optionally maintain a local threat filter
containing confirmed attacker addresses, malicious function selectors, and
drainer contract hashes. This filter runs BEFORE Engines 1-6 and provides
sub-millisecond O(1) lookup.

Architecture
------------
::

    Plimsoll Cloud (compiles Sybil consensus)
          |
          v  WebSocket / REST push
    +---------------------------------+
    |  Local Threat Filter (Engine 0) | <-- O(1) set lookup
    |  - Attacker addresses           |
    |  - Malicious selectors          |
    |  - Drainer contract hashes      |
    +---------------------------------+
          |
          v  Pre-flight check (before Engine 1-6)
      BLOCK or PASS

Anti-Griefing
-------------
Verified protocols with significant TVL are IMMUNE to blacklisting:
- Uniswap, Aave, Compound, 1inch, SushiSwap, 0x
- Any address in the ``immune_addresses`` config set
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Set

from plimsoll.verdict import Verdict, VerdictCode


# ── Well-known protocol addresses (always immune) ─────────────────────

IMMUNE_PROTOCOLS: frozenset[str] = frozenset({
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",  # Uniswap V2 Router
    "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap V3 Router
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",  # Uniswap Universal Router
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # Aave V3 Pool
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave V2 Pool
    "0x3d9819210a31b4961b30ef54be2aed79b9c9cd3b",  # Compound Comptroller
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff",  # 0x Exchange Proxy
    "0x1111111254eeb25477b68fb85ed929f73a960582",  # 1inch Router
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f",  # SushiSwap Router
})


@dataclass
class ThreatFeedConfig:
    """Configuration for Engine 0."""

    enabled: bool = False
    """Enable Engine 0 pre-flight checks. Disabled by default for
    backward compatibility."""

    immune_addresses: Set[str] = field(default_factory=set)
    """Additional addresses immune to blacklisting (beyond built-in protocols)."""

    # Zero-Day 4: Sybil Telemetry Poisoning defense
    min_tvl_for_submission: float = 5_000.0
    """Minimum vault TVL (USD) required to submit IOCs to the Swarm.
    Agents below this threshold have their IOCs logged locally but
    NOT propagated to the Cloud consensus."""

    stake_weight_cap: float = 100_000.0
    """TVL cap for stake weight calculation. TVL above this value
    gives the same weight (1.0) to prevent plutocratic dominance."""


@dataclass
class ThreatFeedEngine:
    """Engine 0: Global Bloom Filter pre-check.

    Maintains local sets of blacklisted addresses, selectors, and
    calldata hashes. Provides O(1) lookup before the heavier engines
    run.

    Usage::

        engine = ThreatFeedEngine()
        engine.add_address("0xHacker123")

        verdict = engine.evaluate({"target": "0xhacker123", "amount": 100})
        assert verdict.blocked
    """

    config: ThreatFeedConfig = field(default_factory=ThreatFeedConfig)

    # Blacklisted entries (all lowercase, 0x-prefixed where applicable)
    _addresses: Set[str] = field(default_factory=set, init=False, repr=False)
    _selectors: Set[str] = field(default_factory=set, init=False, repr=False)
    _calldata_hashes: Set[str] = field(default_factory=set, init=False, repr=False)

    # Metadata
    _version: int = field(default=0, init=False, repr=False)
    _consensus_count: int = field(default=0, init=False, repr=False)
    _last_updated: float = field(default=0.0, init=False, repr=False)
    _block_count: int = field(default=0, init=False, repr=False)

    # ── Mutation methods (called on Cloud push) ──────────────────

    def add_address(self, address: str) -> None:
        """Add an address to the blacklist."""
        self._addresses.add(address.lower())

    def add_selector(self, selector: str) -> None:
        """Add a function selector to the blacklist (e.g., '0xa9059cbb')."""
        self._selectors.add(selector.lower())

    def add_calldata_hash(self, hash_hex: str) -> None:
        """Add a calldata hash to the blacklist."""
        self._calldata_hashes.add(hash_hex)

    def replace_from_cloud(
        self,
        addresses: list[str],
        selectors: list[str],
        calldata_hashes: list[str],
        version: int,
        consensus_count: int,
    ) -> None:
        """Replace the entire filter with a Cloud-pushed update."""
        self._addresses = {a.lower() for a in addresses}
        self._selectors = {s.lower() for s in selectors}
        self._calldata_hashes = set(calldata_hashes)
        self._version = version
        self._consensus_count = consensus_count
        self._last_updated = time.time()

    # ── Anti-Griefing ────────────────────────────────────────────

    def is_immune(self, address: str) -> bool:
        """Check if an address is immune to Swarm blacklisting."""
        addr_lower = address.lower()
        if addr_lower in IMMUNE_PROTOCOLS:
            return True
        if addr_lower in {a.lower() for a in self.config.immune_addresses}:
            return True
        return False

    # ── Evaluation ───────────────────────────────────────────────

    def evaluate(self, payload: dict[str, Any]) -> Verdict:
        """Run Engine 0 pre-flight check.

        Checks the payload's ``target`` address, ``function`` selector,
        and calldata hash against the global blacklist.

        Parameters
        ----------
        payload : dict
            Must contain ``target`` (address). Optionally ``function``
            (selector string) and ``data`` (hex calldata).

        Returns
        -------
        Verdict
            ALLOW if not in blacklist, BLOCK_GLOBAL_BLACKLIST if matched.
        """
        if not self.config.enabled:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="Engine 0 disabled",
                engine="ThreatFeed",
            )

        if self.is_empty():
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No threat feed loaded",
                engine="ThreatFeed",
            )

        target = payload.get("target", "")

        # Check 1: Address blacklist
        if target and target.lower() in self._addresses:
            # Anti-griefing: immune addresses cannot be blacklisted
            if not self.is_immune(target):
                self._block_count += 1
                return Verdict(
                    code=VerdictCode.BLOCK_GLOBAL_BLACKLIST,
                    reason=(
                        f"ENGINE 0: Address {target} is globally blacklisted "
                        f"(Swarm consensus: {self._consensus_count} agents, "
                        f"v{self._version})"
                    ),
                    engine="ThreatFeed",
                    metadata={
                        "blocked_field": "address",
                        "version": self._version,
                        "consensus": self._consensus_count,
                    },
                )

        # Check 2: Function selector blacklist
        selector = payload.get("function", "")
        if selector and selector.lower() in self._selectors:
            self._block_count += 1
            return Verdict(
                code=VerdictCode.BLOCK_GLOBAL_BLACKLIST,
                reason=(
                    f"ENGINE 0: Selector {selector} is globally blacklisted "
                    f"(known drainer signature)"
                ),
                engine="ThreatFeed",
                metadata={"blocked_field": "selector"},
            )

        # Check 3: Calldata hash blacklist
        data_hex = payload.get("data", "")
        if data_hex:
            calldata_hash = hashlib.sha256(
                data_hex.encode() if isinstance(data_hex, str) else data_hex
            ).hexdigest()[:16]
            if calldata_hash in self._calldata_hashes:
                self._block_count += 1
                return Verdict(
                    code=VerdictCode.BLOCK_GLOBAL_BLACKLIST,
                    reason=(
                        f"ENGINE 0: Calldata hash {calldata_hash} matches "
                        f"known exploit payload"
                    ),
                    engine="ThreatFeed",
                    metadata={"blocked_field": "calldata_hash"},
                )

        return Verdict(
            code=VerdictCode.ALLOW,
            reason="Engine 0 passed",
            engine="ThreatFeed",
        )

    # ── Helpers ──────────────────────────────────────────────────

    def is_empty(self) -> bool:
        """True if no threats are loaded."""
        return len(self._addresses) == 0 and len(self._selectors) == 0 and len(self._calldata_hashes) == 0

    @property
    def size(self) -> int:
        """Total number of entries in the filter."""
        return len(self._addresses) + len(self._selectors) + len(self._calldata_hashes)

    @property
    def stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "addresses": len(self._addresses),
            "selectors": len(self._selectors),
            "calldata_hashes": len(self._calldata_hashes),
            "total_entries": self.size,
            "version": self._version,
            "consensus_count": self._consensus_count,
            "blocks": self._block_count,
            "last_updated": self._last_updated,
        }

    def reset(self) -> None:
        """Clear all state."""
        self._addresses.clear()
        self._selectors.clear()
        self._calldata_hashes.clear()
        self._version = 0
        self._consensus_count = 0
        self._last_updated = 0.0
        self._block_count = 0

    # ── Zero-Day 4: Sybil Telemetry Poisoning Defense ─────────

    def compute_stake_weight(self, vault_tvl_usd: float) -> float:
        """Compute stake weight from vault TVL.

        Linear scale capped at ``stake_weight_cap``::

            $0      → 0.0 (rejected)
            $5,000  → 0.05 (minimum accepted)
            $50,000 → 0.5
            $100K+  → 1.0 (maximum weight)
        """
        if vault_tvl_usd <= 0.0:
            return 0.0
        weight = vault_tvl_usd / self.config.stake_weight_cap
        return min(weight, 1.0)

    def validate_ioc_submission(self, vault_tvl_usd: float) -> tuple:
        """Validate an IOC submission for Sybil resistance.

        Returns (accepted: bool, reason: str).

        IOCs from agents with TVL below ``min_tvl_for_submission`` are
        rejected to prevent Sybil poisoning.
        """
        min_tvl = self.config.min_tvl_for_submission
        stake_weight = self.compute_stake_weight(vault_tvl_usd)

        if vault_tvl_usd < min_tvl:
            return (False, (
                f"ZERO-DAY 4: IOC rejected — agent TVL ${vault_tvl_usd:,.0f} "
                f"< minimum ${min_tvl:,.0f}. Sybil resistance requires "
                f"skin in the game."
            ))

        if stake_weight <= 0.0:
            return (False, (
                f"ZERO-DAY 4: IOC rejected — stake weight {stake_weight:.4f} "
                f"is zero or negative."
            ))

        return (True, (
            f"IOC accepted with stake weight {stake_weight:.4f} "
            f"(TVL ${vault_tvl_usd:,.0f})"
        ))

    # ── GOD-TIER 2: Flashloan Sybil Defense (TWAB) ────────────

    # Minimum vault age in blocks before IOC submission is accepted.
    TWAB_WINDOW_BLOCKS: int = 20_000  # ~72 hours at 12s/block

    def validate_ioc_with_twab(
        self,
        twab_usd: float,
        vault_age_blocks: int,
    ) -> tuple:
        """Validate an IOC submission using Time-Weighted Average Balance.

        Unlike ``validate_ioc_submission()`` which uses a point-in-time TVL
        snapshot (fakeable via flash loans), TWAB requires the vault to have
        maintained the minimum balance for 72 hours (20,000 blocks).

        A $50M flash loan split into 10,000 vaults at $5K each contributes
        only $5K / 20,000 = $0.25 TWAB per vault. Attack cost: impossible.

        Returns (accepted: bool, reason: str).
        """
        min_tvl = self.config.min_tvl_for_submission

        # Check vault age first — new vaults can't vote
        if vault_age_blocks < self.TWAB_WINDOW_BLOCKS:
            return (False, (
                f"GOD-TIER 2: IOC rejected — vault age {vault_age_blocks} blocks "
                f"< minimum {self.TWAB_WINDOW_BLOCKS} blocks (~72h). "
                f"New vaults cannot influence Swarm consensus."
            ))

        # Check TWAB meets threshold
        if twab_usd < min_tvl:
            return (False, (
                f"GOD-TIER 2: IOC rejected — TWAB ${twab_usd:,.0f} "
                f"< minimum ${min_tvl:,.0f}. Flash-loan Sybil defense: "
                f"72-hour average balance required, not point-in-time snapshot."
            ))

        stake_weight = self.compute_stake_weight(twab_usd)
        return (True, (
            f"IOC accepted via TWAB validation: ${twab_usd:,.0f} avg over "
            f"{vault_age_blocks} blocks (stake weight {stake_weight:.4f})"
        ))
