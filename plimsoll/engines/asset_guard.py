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

The oracle provider is a pluggable callable, so Plimsoll itself never
imports any specific DeFi SDK.

Time complexity: O(1) + oracle latency.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from plimsoll.verdict import Verdict, VerdictCode

_ENGINE_NAME = "AssetGuard"
logger = logging.getLogger("plimsoll")

# ZERO-DAY 3 (v1.0.1): Known cross-chain bridge and router addresses.
# When a transaction targets one of these, Plimsoll must unroll the calldata
# to extract the L2/cross-chain destination address. If the destination
# is not an Plimsoll-secured vault, the transaction is hard-blocked.
KNOWN_BRIDGE_ADDRESSES: frozenset[str] = frozenset({
    # Ethereum L1 bridges
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1",  # Optimism L1 Bridge
    "0x3154cf16ccdb4c6d922629664174b904d80f2c35",  # Base L1 Bridge
    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f",  # Arbitrum Inbox
    "0xa3a7b6f88361f48403514059f1f16c8e78d60eec",  # Arbitrum L1 Gateway
    "0x72ce9c846789fdb6fc1f34ac4ad25dd9ef7031ef",  # Arbitrum Gateway Router
    # Interoperability protocols
    "0x3c2269811836af69497e5f486a85d7316753cf62",  # LayerZero Endpoint (ETH)
    "0x98f3c9e6e3face36baad05fe09d375ef1464288b",  # Wormhole Core Bridge
    "0xe4ef8e4c0110c0e960b0b3fd4ce4c5dce7e62b6e",  # CCIP Router (Chainlink)
    # L2 token bridges
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf",  # Polygon PoS Bridge
    "0xa0c68c638235ee32657e8f720a23cec1bfc6c9a8",  # Polygon zkEVM Bridge
    "0x2a3dd3eb832af982ec71669e178424b10dca2ede",  # zkSync Era Diamond Proxy
    "0x32400084d98d560893a97d1c80eb3b1e906e3034",  # zkSync Era Mailbox
    # Aggregator routers
    "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae",  # LI.FI Diamond
    "0x881d40237659c251811cec9c364ef91dc08d300c",  # Metamask Bridge
})

# ZERO-DAY 3: Known function selectors for bridge deposit/transfer calls.
# These are the first 4 bytes of the calldata (function selector) that
# indicate a cross-chain deposit or token transfer through a bridge.
BRIDGE_FUNCTION_SELECTORS: frozenset[str] = frozenset({
    "0xb1a1a882",  # depositETHTo(address,uint32,bytes) — Optimism
    "0x9a2ac6d5",  # outboundTransfer(address,address,uint256,uint256,uint256,bytes) — Arb
    "0x1a98b2e0",  # depositTo(address,uint256,uint32,bytes) — generic bridge
    "0xa9059cbb",  # transfer(address,uint256) — ERC20 (to bridge contract)
    "0x23b872dd",  # transferFrom(address,address,uint256) — ERC20
    "0xe11013dd",  # depositETHTo(address,uint32,bytes) — Base bridge
    "0x838b2520",  # bridge(address,uint256,uint256,bytes) — LI.FI
    "0x2e1a7d4d",  # withdraw(uint256) — WETH (used in bridge flows)
    "0xc68a0e71",  # sendMessage(address,bytes,uint32) — L1 messenger
    "0x3dbb202b",  # sendMessage(address,bytes,uint32) — OP CrossDomainMessenger
})


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

    # Zero-Day 3 (v0.6.0): Signed Intent Time-Decay
    # Maximum age (seconds) of a swap intent before it's considered stale.
    # Default: 24 seconds (2 Ethereum block slots).
    max_intent_age_secs: float = 24.0

    # ZERO-DAY 3 (v1.0.1): Jurisdictional Arbitrage — Cross-Chain Bridge Defense
    # List of whitelisted L2/cross-chain destination addresses.
    # When a tx targets a bridge, the nested destination address MUST be
    # in this list or the tx is blocked.
    # Empty = cross-chain destination checking disabled (backward compat).
    approved_destinations: list[str] = field(default_factory=list)


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

        # ── Check 0 (Zero-Day 3): Intent Time-Decay ─────────────
        # If the payload carries a `deadline` or `intent_timestamp`,
        # reject stale intents that could be exploited by MEV builders
        # holding the transaction until slippage favors them.
        intent_deadline = payload.get("deadline")
        intent_timestamp = payload.get("intent_timestamp")
        now = time.time()

        if intent_deadline is not None:
            if float(intent_deadline) < now:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"INTENT EXPIRED: deadline {intent_deadline} is in the "
                        f"past (now={now:.0f}). Stale intents rejected to "
                        f"prevent MEV time-decay exploitation."
                    ),
                    engine=_ENGINE_NAME,
                    metadata={"deadline": intent_deadline, "now": now},
                )
            # Deadline too far in the future → potential builder exploit
            max_future = now + self.config.max_intent_age_secs
            if float(intent_deadline) > max_future:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"INTENT DEADLINE TOO FAR: deadline {intent_deadline} is "
                        f"{float(intent_deadline) - now:.0f}s in the future "
                        f"(max {self.config.max_intent_age_secs:.0f}s). "
                        f"Ultra-short deadlines prevent MEV time-decay."
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "deadline": intent_deadline,
                        "max_intent_age_secs": self.config.max_intent_age_secs,
                    },
                )

        if intent_timestamp is not None:
            age = now - float(intent_timestamp)
            if age > self.config.max_intent_age_secs:
                return Verdict(
                    code=VerdictCode.BLOCK_ASSET_REJECTED,
                    reason=(
                        f"STALE INTENT: signed {age:.0f}s ago "
                        f"(max {self.config.max_intent_age_secs:.0f}s). "
                        f"Re-sign with a fresh timestamp."
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "intent_age_secs": age,
                        "max_intent_age_secs": self.config.max_intent_age_secs,
                    },
                )

        # ── Check 0.5 (ZERO-DAY 3): Cross-Chain Bridge Destination ─
        # If the transaction targets a known bridge or interoperability
        # router, we MUST unroll the calldata to extract the L2/cross-chain
        # destination address. If the destination is not an approved vault,
        # the transaction is blocked — even if the L1 target is "safe."
        bridge_result = self._check_bridge_destination(payload)
        if bridge_result is not None:
            return bridge_result

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

    # ── ZERO-DAY 3: Bridge Destination Decoder ──────────────────

    def _check_bridge_destination(self, payload: dict[str, Any]) -> Verdict | None:
        """Check if the transaction targets a known bridge and validate destination.

        ZERO-DAY 3 (Jurisdictional Arbitrage): An attacker tricks the agent into
        sending funds to a whitelisted bridge contract (L1 tx looks safe), but
        sets the L2 destination to a hacker's address. Plimsoll was "spatially blind"
        — it secured the L1 payload but missed the cross-chain escape route.

        This method:
        1. Checks if the target address is a known bridge/router
        2. Extracts the L2 destination from the calldata
        3. Validates the destination against approved_destinations
        4. Blocks if the destination is not an approved vault

        Returns None if the tx doesn't target a bridge (passthrough).
        Returns a Verdict if a bridge is detected and checked.
        """
        if not self.config.approved_destinations:
            return None  # Feature disabled (backward compat)

        target = payload.get("target", "")
        if not target:
            return None

        target_lower = target.lower()

        # Check if target is a known bridge
        if target_lower not in KNOWN_BRIDGE_ADDRESSES:
            # Also check via explicit bridge_contract field
            bridge_contract = payload.get("bridge_contract", "")
            if not bridge_contract or bridge_contract.lower() not in KNOWN_BRIDGE_ADDRESSES:
                return None  # Not a bridge tx

        # Target IS a bridge — extract the L2 destination
        calldata = payload.get("data", payload.get("calldata", b""))
        destination_address = payload.get("destination_address", "")
        destination_chain = payload.get("destination_chain", "")

        # Try to extract from explicit payload fields first
        if not destination_address:
            destination_address = self._extract_destination_from_calldata(calldata)

        if not destination_address:
            # Cannot determine destination — fail closed
            return Verdict(
                code=VerdictCode.BLOCK_ASSET_REJECTED,
                reason=(
                    f"ZERO-DAY 3 (JURISDICTIONAL ARBITRAGE): Transaction targets "
                    f"bridge {target} but destination address could not be "
                    f"extracted from calldata. Fail-closed: cross-chain "
                    f"transfers require explicit destination validation."
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "bridge": target,
                    "destination_chain": destination_chain,
                },
            )

        # Validate destination against approved list
        dest_lower = destination_address.lower()
        approved_lower = [a.lower() for a in self.config.approved_destinations]

        if dest_lower not in approved_lower:
            return Verdict(
                code=VerdictCode.BLOCK_ASSET_REJECTED,
                reason=(
                    f"ZERO-DAY 3 (JURISDICTIONAL ARBITRAGE): Cross-chain "
                    f"destination {destination_address} is NOT an approved "
                    f"Plimsoll-secured vault. L1 target {target} is a bridge — "
                    f"the agent would walk funds out the front door to "
                    f"an unsecured address on {destination_chain or 'L2'}."
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "bridge": target,
                    "destination_address": destination_address,
                    "destination_chain": destination_chain,
                    "approved_count": len(self.config.approved_destinations),
                },
            )

        # Destination is approved
        logger.info(
            "ZERO-DAY 3: Bridge %s → destination %s APPROVED",
            target, destination_address,
        )
        return None  # Passthrough — destination is safe

    @staticmethod
    def _extract_destination_from_calldata(calldata: Any) -> str:
        """Extract the L2 destination address from bridge calldata.

        Most bridge functions encode the destination as the first address
        parameter after the 4-byte function selector. We extract the
        first 20-byte address from the ABI-encoded parameters.

        Supports both bytes and hex string calldata.
        """
        if not calldata:
            return ""

        # Convert to bytes if hex string
        if isinstance(calldata, str):
            calldata = calldata.strip()
            if calldata.startswith("0x"):
                calldata = calldata[2:]
            try:
                calldata = bytes.fromhex(calldata)
            except (ValueError, TypeError):
                return ""

        if not isinstance(calldata, (bytes, bytearray)):
            return ""

        # Need at least 4 (selector) + 32 (first param) bytes
        if len(calldata) < 36:
            return ""

        selector = "0x" + calldata[:4].hex()

        # Check if this is a known bridge function
        if selector not in BRIDGE_FUNCTION_SELECTORS:
            # Still try to extract — many bridge functions put address first
            pass

        # ABI decoding: first parameter starts at byte 4.
        # Addresses are left-padded to 32 bytes.
        # Extract bytes 4..36, take last 20 bytes as the address.
        first_param = calldata[4:36]
        # Address is in the last 20 bytes of the 32-byte word
        address_bytes = first_param[12:32]

        if len(address_bytes) != 20:
            return ""

        # Check it looks like a valid address (not all zeros)
        if address_bytes == b"\x00" * 20:
            return ""

        return "0x" + address_bytes.hex()

    def reset(self) -> None:
        """No-op — AssetGuard is stateless."""
        pass
