"""Tests for the @with_plimsoll_firewall decorator."""

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.trajectory_hash import TrajectoryHashConfig
from plimsoll.decorator import with_plimsoll_firewall


def test_decorator_allows_clean_call():
    fw = PlimsollFirewall()

    @with_plimsoll_firewall(fw)
    def send_tx(payload):
        return {"status": "sent", "payload": payload}

    result = send_tx({"target": "0xA", "amount": 10, "function": "transfer"})
    assert result["status"] == "sent"


def test_decorator_blocks_loop():
    fw = PlimsollFirewall(
        config=PlimsollConfig(
            trajectory=TrajectoryHashConfig(max_duplicates=1, window_seconds=60)
        )
    )

    @with_plimsoll_firewall(fw)
    def send_tx(payload):
        return {"status": "sent"}

    payload = {"target": "0xA", "amount": 10, "function": "transfer"}
    r1 = send_tx(payload)
    assert r1["status"] == "sent"

    r2 = send_tx(payload)
    assert r2.get("plimsoll_blocked") is True
    assert "feedback" in r2


def test_decorator_custom_on_block():
    fw = PlimsollFirewall(
        config=PlimsollConfig(
            trajectory=TrajectoryHashConfig(max_duplicates=1, window_seconds=60)
        )
    )

    @with_plimsoll_firewall(fw, on_block=lambda v: {"custom": "blocked", "reason": v.reason})
    def send_tx(payload):
        return {"status": "sent"}

    payload = {"target": "0xB", "amount": 5, "function": "swap"}
    send_tx(payload)
    r = send_tx(payload)
    assert r["custom"] == "blocked"


def test_decorator_exposes_firewall():
    fw = PlimsollFirewall()

    @with_plimsoll_firewall(fw)
    def action(payload):
        return True

    assert action.plimsoll_firewall is fw
