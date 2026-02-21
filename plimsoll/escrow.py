"""
EscrowQueue — Human-in-the-Loop approval for high-value transactions.

When a transaction is blocked by any Plimsoll engine but the spend amount
exceeds ``auto_escalate_above``, it is held in escrow for human review
instead of being hard-blocked.  An operator can then approve or reject
the transaction via ``approve(tx_id)`` / ``reject(tx_id)``.

This closes the false-positive gap: legitimate large transactions are
queued for review rather than silently dropped.

Each escrowed transaction has a TTL; expired entries are automatically
pruned and treated as rejected.

Patch 3 — Risk-Off Fast Lanes:
    Prevents the "Escrow Death Trap" where safety-critical risk-reducing
    actions (loan repayment, position closing) get trapped in the queue
    while MEV bots liquidate the position. A semantic intent classifier
    identifies provably risk-reducing transactions and bypasses the delay.
"""

from __future__ import annotations

import enum
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger("plimsoll")


class EscrowStatus(enum.Enum):
    """Status of an escrowed transaction."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    FAST_LANE = "FAST_LANE"   # Patch 3: bypassed escrow via risk-off classification


@dataclass(frozen=True)
class EscrowedTransaction:
    """Immutable record of a held transaction."""

    tx_id: str
    payload: dict[str, Any]
    spend_amount: float
    block_reason: str
    block_engine: str
    status: EscrowStatus
    created_at: float
    expires_at: float


@dataclass
class EscrowConfig:
    """Configuration for the escrow queue."""

    enable_escrow: bool = False
    approval_callback: Optional[Callable[[EscrowedTransaction], None]] = None
    escrow_ttl_seconds: float = 3600.0        # 1 hour default
    auto_escalate_above: float = float("inf")  # Threshold to escalate to escrow

    # ── Patch 3: Risk-Off Fast Lanes ──────────────────────────────
    # Prevents the "Escrow Death Trap" — where safety-critical risk-reducing
    # actions (loan repayment, position closing, emergency swaps to stables)
    # get trapped in the escrow queue while MEV bots liquidate the position.
    enable_fast_lanes: bool = True
    fast_lane_selectors: Optional[list[str]] = None
    fast_lane_protocols: Optional[list[str]] = None

    def __post_init__(self) -> None:
        if self.fast_lane_selectors is None:
            self.fast_lane_selectors = [
                "repay",              # Aave/Compound repayment
                "repayBorrow",        # Compound v2
                "repayWithATokens",   # Aave v3
                "closePosition",      # GMX / perpetuals
                "decreasePosition",   # GMX
                "liquidationCall",    # Self-liquidation (better than external)
                "withdraw",           # Withdraw from lending (de-risk)
                "exit",               # Balancer / pool exit
                "removeLiquidity",    # Uniswap v2
                "decreaseLiquidity",  # Uniswap v3
            ]
        if self.fast_lane_protocols is None:
            self.fast_lane_protocols = []


# ── Patch 3: Semantic Intent Classifier ───────────────────────────


class IntentClassifier:
    """Classifies transaction intent as risk-reducing or risk-increasing.

    Risk-reducing actions ("Safe Harbor") bypass the escrow delay because
    blocking a loan repayment during a flash crash is worse than allowing it.

    Architecture:
        1. Check function selector against known risk-reducing selectors
        2. Check target against whitelisted risk-off protocols
        3. Check for swap-to-stablecoin pattern (risk-off intent)
        4. If any match -> classify as RISK_OFF -> bypass escrow

    This is a CONSERVATIVE classifier: it only fast-lanes actions that are
    provably risk-reducing. Unknown actions always go through escrow.
    """

    # Stablecoin identifiers (symbol-level, case-insensitive)
    STABLECOIN_SYMBOLS: set[str] = {
        "usdc", "usdt", "dai", "frax", "lusd", "gusd",
        "busd", "tusd", "usdp", "susd", "eurs", "usdd",
    }

    @staticmethod
    def is_risk_off(
        payload: dict[str, Any],
        config: EscrowConfig,
    ) -> tuple[bool, str]:
        """Determine if a transaction is risk-reducing (safe harbor).

        Returns ``(is_risk_off, reason)`` tuple.
        """
        if not config.enable_fast_lanes:
            return False, ""

        selectors = config.fast_lane_selectors or []
        protocols = config.fast_lane_protocols or []

        # Check 1: Function name / selector matches
        function = str(payload.get("function", "")).lower()
        action = str(payload.get("action", "")).lower()

        for selector in selectors:
            sel_lower = selector.lower()
            if sel_lower in function or sel_lower in action:
                return True, f"FAST_LANE: risk-off function '{selector}' detected"

        # Check 2: Target is a whitelisted risk-off protocol
        target = str(payload.get("target", payload.get("to", ""))).lower()
        for protocol in protocols:
            if protocol.lower() == target:
                return True, f"FAST_LANE: whitelisted risk-off protocol {protocol[:10]}..."

        # Check 3: Swap destination is a stablecoin (de-risk pattern)
        token_out = str(payload.get("token_out", payload.get("tokenOut", ""))).lower()
        swap_to = str(payload.get("swap_to", "")).lower()
        for symbol in IntentClassifier.STABLECOIN_SYMBOLS:
            if symbol in token_out or symbol in swap_to:
                return True, f"FAST_LANE: swap to stablecoin '{symbol}' detected"

        # Check 4: Explicit risk-off intent flag (agent self-declares)
        if payload.get("plimsoll_intent") == "risk_off":
            return True, "FAST_LANE: agent declared risk_off intent"

        return False, ""


@dataclass
class EscrowQueue:
    """Thread-safe escrow queue for human-in-the-loop approval.

    Usage::

        queue = EscrowQueue(config=EscrowConfig(
            enable_escrow=True,
            auto_escalate_above=500.0,
        ))
        tx = queue.enqueue(
            payload={"target": "0xDEAD...", "amount": 1000},
            spend_amount=1000.0,
            block_reason="VELOCITY BREACH",
            block_engine="CapitalVelocity",
        )
        # ... operator reviews ...
        queue.approve(tx.tx_id)
    """

    config: EscrowConfig = field(default_factory=EscrowConfig)
    _pending: dict[str, EscrowedTransaction] = field(
        default_factory=dict, init=False, repr=False
    )
    _resolved: dict[str, EscrowedTransaction] = field(
        default_factory=dict, init=False, repr=False
    )
    _fast_lane_count: int = field(default=0, init=False, repr=False)

    def should_fast_lane(self, payload: dict[str, Any]) -> tuple[bool, str]:
        """Check if a payload qualifies for the risk-off fast lane.

        Call this BEFORE enqueue() to determine if the transaction
        should bypass the escrow delay entirely.
        """
        return IntentClassifier.is_risk_off(payload, self.config)

    def enqueue(
        self,
        payload: dict[str, Any],
        spend_amount: float,
        block_reason: str,
        block_engine: str,
    ) -> EscrowedTransaction:
        """Add a transaction to the escrow queue for human review.

        Patch 3: If the transaction is classified as risk-reducing,
        it is auto-approved immediately (fast lane) instead of being
        held for human review.
        """
        now = time.time()
        tx_id = uuid.uuid4().hex[:12]

        # ── Patch 3: Fast lane check ─────────────────────────────
        is_fast, fast_reason = self.should_fast_lane(payload)
        if is_fast:
            fast_tx = EscrowedTransaction(
                tx_id=tx_id,
                payload=payload,
                spend_amount=spend_amount,
                block_reason=block_reason,
                block_engine=block_engine,
                status=EscrowStatus.FAST_LANE,
                created_at=now,
                expires_at=now,  # Immediate — no TTL
            )
            self._resolved[tx_id] = fast_tx
            self._fast_lane_count += 1
            logger.info(
                "ESCROW FAST LANE: Transaction %s auto-approved — %s",
                tx_id, fast_reason,
            )
            return fast_tx

        # ── Normal escrow path ───────────────────────────────────
        tx = EscrowedTransaction(
            tx_id=tx_id,
            payload=payload,
            spend_amount=spend_amount,
            block_reason=block_reason,
            block_engine=block_engine,
            status=EscrowStatus.PENDING,
            created_at=now,
            expires_at=now + self.config.escrow_ttl_seconds,
        )

        self._pending[tx_id] = tx
        logger.info("ESCROW: Transaction %s queued for human review", tx_id)

        # Fire notification callback (exception-safe)
        if self.config.approval_callback is not None:
            try:
                self.config.approval_callback(tx)
            except Exception as exc:
                logger.warning(
                    "ESCROW: Callback failed for tx %s: %s", tx_id, exc
                )

        return tx

    def approve(self, tx_id: str) -> Optional[EscrowedTransaction]:
        """Approve a pending escrowed transaction.

        Returns the approved transaction or None if not found / already resolved.
        """
        self._prune_expired()
        tx = self._pending.pop(tx_id, None)
        if tx is None:
            return None

        # Create a new frozen instance with APPROVED status
        approved = EscrowedTransaction(
            tx_id=tx.tx_id,
            payload=tx.payload,
            spend_amount=tx.spend_amount,
            block_reason=tx.block_reason,
            block_engine=tx.block_engine,
            status=EscrowStatus.APPROVED,
            created_at=tx.created_at,
            expires_at=tx.expires_at,
        )
        self._resolved[tx_id] = approved
        logger.info("ESCROW: Transaction %s APPROVED", tx_id)
        return approved

    def reject(self, tx_id: str) -> Optional[EscrowedTransaction]:
        """Reject a pending escrowed transaction.

        Returns the rejected transaction or None if not found / already resolved.
        """
        self._prune_expired()
        tx = self._pending.pop(tx_id, None)
        if tx is None:
            return None

        rejected = EscrowedTransaction(
            tx_id=tx.tx_id,
            payload=tx.payload,
            spend_amount=tx.spend_amount,
            block_reason=tx.block_reason,
            block_engine=tx.block_engine,
            status=EscrowStatus.REJECTED,
            created_at=tx.created_at,
            expires_at=tx.expires_at,
        )
        self._resolved[tx_id] = rejected
        logger.info("ESCROW: Transaction %s REJECTED", tx_id)
        return rejected

    def list_pending(self) -> list[EscrowedTransaction]:
        """Return all non-expired pending transactions."""
        self._prune_expired()
        return list(self._pending.values())

    def get(self, tx_id: str) -> Optional[EscrowedTransaction]:
        """Look up a transaction by ID (pending or resolved)."""
        self._prune_expired()
        return self._pending.get(tx_id) or self._resolved.get(tx_id)

    def _prune_expired(self) -> None:
        """Move expired pending transactions to resolved as EXPIRED."""
        now = time.time()
        expired_ids = [
            tx_id
            for tx_id, tx in self._pending.items()
            if now >= tx.expires_at
        ]
        for tx_id in expired_ids:
            tx = self._pending.pop(tx_id)
            expired = EscrowedTransaction(
                tx_id=tx.tx_id,
                payload=tx.payload,
                spend_amount=tx.spend_amount,
                block_reason=tx.block_reason,
                block_engine=tx.block_engine,
                status=EscrowStatus.EXPIRED,
                created_at=tx.created_at,
                expires_at=tx.expires_at,
            )
            self._resolved[tx_id] = expired
            logger.info("ESCROW: Transaction %s EXPIRED", tx_id)

    def reset(self) -> None:
        """Clear all escrow state."""
        self._pending.clear()
        self._resolved.clear()
        self._fast_lane_count = 0
