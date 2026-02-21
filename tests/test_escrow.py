"""Tests for EscrowQueue and firewall escrow integration."""

from __future__ import annotations

import time

from aegis.escrow import (
    EscrowQueue,
    EscrowConfig,
    EscrowedTransaction,
    EscrowStatus,
)
from aegis.firewall import AegisFirewall, AegisConfig
from aegis.engines.capital_velocity import CapitalVelocityConfig
from aegis.verdict import VerdictCode


# ── Standalone EscrowQueue tests ─────────────────────────────────


def test_enqueue_creates_pending():
    """Enqueuing a transaction should create a PENDING entry."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={"target": "0xDEAD", "amount": 1000},
        spend_amount=1000.0,
        block_reason="VELOCITY BREACH",
        block_engine="CapitalVelocity",
    )
    assert tx.status == EscrowStatus.PENDING
    assert tx.spend_amount == 1000.0
    assert len(tx.tx_id) == 12
    assert tx.payload["target"] == "0xDEAD"


def test_approve_changes_status():
    """Approving a pending transaction should return an APPROVED copy."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={"target": "0xDEAD"},
        spend_amount=500.0,
        block_reason="TEST",
        block_engine="TestEngine",
    )
    approved = queue.approve(tx.tx_id)
    assert approved is not None
    assert approved.status == EscrowStatus.APPROVED
    assert approved.tx_id == tx.tx_id


def test_reject_changes_status():
    """Rejecting a pending transaction should return a REJECTED copy."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={"target": "0xDEAD"},
        spend_amount=500.0,
        block_reason="TEST",
        block_engine="TestEngine",
    )
    rejected = queue.reject(tx.tx_id)
    assert rejected is not None
    assert rejected.status == EscrowStatus.REJECTED


def test_approve_nonexistent_returns_none():
    """Approving a non-existent tx_id should return None."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    result = queue.approve("nonexistent_id")
    assert result is None


def test_approve_already_approved_returns_none():
    """Approving an already-approved tx should return None (idempotent)."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    queue.approve(tx.tx_id)
    result = queue.approve(tx.tx_id)  # Second time
    assert result is None


def test_reject_removes_from_pending():
    """After rejection, tx should not appear in pending list."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    queue.reject(tx.tx_id)
    pending = queue.list_pending()
    assert len(pending) == 0


def test_list_pending():
    """list_pending should return all non-expired pending transactions."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx1 = queue.enqueue(
        payload={"id": 1}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    tx2 = queue.enqueue(
        payload={"id": 2}, spend_amount=200.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    pending = queue.list_pending()
    assert len(pending) == 2
    ids = {t.tx_id for t in pending}
    assert tx1.tx_id in ids
    assert tx2.tx_id in ids


def test_ttl_expiry():
    """Expired transactions should be pruned and not appear in pending."""
    queue = EscrowQueue(
        config=EscrowConfig(
            enable_escrow=True,
            escrow_ttl_seconds=0.1,  # 100ms TTL
        )
    )
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    time.sleep(0.15)  # Wait for expiry
    pending = queue.list_pending()
    assert len(pending) == 0

    # Expired tx should be in resolved
    resolved = queue.get(tx.tx_id)
    assert resolved is not None
    assert resolved.status == EscrowStatus.EXPIRED


def test_callback_invoked():
    """approval_callback should be called when a transaction is enqueued."""
    callback_log = []

    def on_enqueue(tx: EscrowedTransaction) -> None:
        callback_log.append(tx.tx_id)

    queue = EscrowQueue(
        config=EscrowConfig(
            enable_escrow=True,
            approval_callback=on_enqueue,
        )
    )
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    assert len(callback_log) == 1
    assert callback_log[0] == tx.tx_id


def test_callback_failure_safe():
    """A failing callback should not crash the enqueue."""
    def broken_callback(tx: EscrowedTransaction) -> None:
        raise RuntimeError("Webhook down!")

    queue = EscrowQueue(
        config=EscrowConfig(
            enable_escrow=True,
            approval_callback=broken_callback,
        )
    )
    # Should not raise
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    assert tx.status == EscrowStatus.PENDING


def test_get_pending():
    """get() should return a pending transaction."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    result = queue.get(tx.tx_id)
    assert result is not None
    assert result.status == EscrowStatus.PENDING


def test_get_resolved():
    """get() should return an approved/rejected transaction."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    queue.approve(tx.tx_id)
    result = queue.get(tx.tx_id)
    assert result is not None
    assert result.status == EscrowStatus.APPROVED


def test_reset_clears_all():
    """reset() should clear both pending and resolved."""
    queue = EscrowQueue(config=EscrowConfig(enable_escrow=True))
    tx = queue.enqueue(
        payload={}, spend_amount=100.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    queue.approve(tx.tx_id)
    queue.enqueue(
        payload={}, spend_amount=200.0,
        block_reason="TEST", block_engine="TestEngine",
    )
    queue.reset()
    assert len(queue.list_pending()) == 0
    assert queue.get(tx.tx_id) is None


# ── Firewall integration tests ──────────────────────────────────


def test_firewall_escrow_disabled_by_default():
    """With default config, escrow should be disabled and blocked txns stay blocked."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            )
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # First sample
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # Should block
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_VELOCITY_BREACH


def test_firewall_escrow_intercepts_blocked_txn():
    """When escrow is enabled and spend >= threshold, blocked txn should be escrowed."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,  # Escalate anything >= 50
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # First sample
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # Would block

    # Should be escrowed, not hard-blocked
    assert v.code == VerdictCode.PENDING_HUMAN_APPROVAL
    assert "tx_id" in v.metadata
    assert v.metadata["original_code"] == "BLOCK_VELOCITY_BREACH"

    # Should appear in escrowed list
    escrowed = fw.list_escrowed()
    assert len(escrowed) == 1
    assert escrowed[0].tx_id == v.metadata["tx_id"]


def test_firewall_escrow_below_threshold_hard_blocks():
    """Blocked txns below auto_escalate_above should still hard-block."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=500.0,  # High threshold
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # First sample
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # Below 500

    # Should be hard-blocked, not escrowed
    assert v.blocked
    assert v.code == VerdictCode.BLOCK_VELOCITY_BREACH


def test_firewall_approve_escrowed_txn():
    """Approving an escrowed txn should update its status."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    tx_id = v.metadata["tx_id"]

    approved = fw.approve(tx_id)
    assert approved is not None
    assert approved.status == EscrowStatus.APPROVED


def test_firewall_reject_escrowed_txn():
    """Rejecting an escrowed txn should remove it from pending."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    tx_id = v.metadata["tx_id"]

    rejected = fw.reject(tx_id)
    assert rejected is not None
    assert rejected.status == EscrowStatus.REJECTED
    assert len(fw.list_escrowed()) == 0


def test_pending_human_approval_feedback_prompt():
    """PENDING_HUMAN_APPROVAL verdict should produce a 'HELD FOR HUMAN REVIEW' prompt."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    v = fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    assert v.code == VerdictCode.PENDING_HUMAN_APPROVAL

    feedback = v.feedback_prompt()
    assert "HELD FOR HUMAN REVIEW" in feedback
    assert "TX_ID" in feedback
    assert "AWAIT OPERATOR APPROVAL" in feedback


def test_firewall_stats_include_escrowed():
    """Firewall stats should track escrowed count separately."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # Allowed (first sample)
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)  # Escrowed

    stats = fw.stats
    assert stats["allowed"] == 1
    assert stats["escrowed"] == 1
    assert stats["blocked"] == 0
    assert stats["total"] == 2


def test_firewall_reset_clears_escrow():
    """Firewall reset() should also clear escrow queue."""
    fw = AegisFirewall(
        config=AegisConfig(
            velocity=CapitalVelocityConfig(
                v_max=1.0,
                pid_threshold=1.0,
                k_p=1.0, k_i=0.0, k_d=0.0,
            ),
            escrow=EscrowConfig(
                enable_escrow=True,
                auto_escalate_above=50.0,
            ),
        )
    )
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)
    fw.evaluate({"target": "0xDEAD"}, spend_amount=100.0)

    fw.reset()
    assert len(fw.list_escrowed()) == 0
    assert fw.stats["escrowed"] == 0
