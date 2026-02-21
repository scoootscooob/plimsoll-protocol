"""
Engine 6: EVM Simulator — Pre-Execution Outcome Validation.

Defends against advanced DeFi sabotage where a transaction's *input*
looks safe (e.g., a stablecoin swap) but the *outcome* is catastrophic
(e.g., a malicious contract drains all token approvals via a nested
delegatecall).

Defence:
    Before signing any transaction, Plimsoll sends the payload to an EVM
    simulation backend (Tenderly, local Foundry fork, Alchemy simulate,
    etc.), fast-forwards the block, and checks the agent's wallet state
    after execution.

    If the simulation shows:
        - Net worth dropping by more than ``max_loss_pct``
        - Unexpected token approvals being set
        - Calls to known-malicious contracts
    → Plimsoll blocks the transaction.

The simulation backend is a **pluggable callable**, so Plimsoll itself
never imports any specific EVM library. The user provides a function
that takes a tx dict and returns a SimulationResult.

Time complexity: O(1) + simulation latency.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from plimsoll.verdict import Verdict, VerdictCode

_ENGINE_NAME = "EVMSimulator"
logger = logging.getLogger("plimsoll")


@dataclass(frozen=True)
class SimulationResult:
    """Result from an EVM simulation backend.

    Attributes:
        success: Whether the simulated transaction reverted or succeeded.
        gas_used: Gas consumed by the simulated tx.
        balance_before: Agent's native token balance before tx (wei or ETH).
        balance_after: Agent's native token balance after tx.
        net_worth_before_usd: Total portfolio value before (USD).
        net_worth_after_usd: Total portfolio value after (USD).
        approvals_changed: List of token addresses whose approvals changed.
        calls_trace: List of contract addresses called during execution.
        error: Error message if simulation failed.
    """

    success: bool = True
    gas_used: int = 0
    balance_before: float = 0.0
    balance_after: float = 0.0
    net_worth_before_usd: float = 0.0
    net_worth_after_usd: float = 0.0
    approvals_changed: list[str] = field(default_factory=list)
    calls_trace: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class EVMSimulatorConfig:
    """Configuration for the EVM pre-execution simulator."""

    enabled: bool = False
    simulator: Optional[Callable[[dict[str, Any]], SimulationResult]] = None
    max_loss_pct: float = 20.0        # Block if net worth drops > 20%
    block_on_approval_change: bool = True   # Block if token approvals change
    blocked_contracts: list[str] = field(default_factory=list)
    fail_closed: bool = True          # Block on simulation failure


@dataclass
class EVMSimulatorEngine:
    """Pre-execution EVM simulation engine.

    Evaluates transaction payloads by simulating them against a fork of
    the current chain state. Blocks transactions whose simulated outcomes
    are economically harmful.

    The simulator is pluggable — the user provides a callable that takes
    a transaction dict and returns a ``SimulationResult``. This allows
    integration with:

        - **Tenderly** — ``tenderly.simulate(tx)``
        - **Foundry/Anvil** — local fork simulation
        - **Alchemy** — ``alchemy_simulateExecution``
        - **Custom** — any function matching the signature

    Payloads that don't look like EVM transactions (no ``to`` or ``data``
    fields) pass through automatically.
    """

    config: EVMSimulatorConfig = field(default_factory=EVMSimulatorConfig)

    def evaluate(self, payload: dict[str, Any]) -> Verdict:
        """Evaluate a payload by simulating its execution."""

        if not self.config.enabled:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="EVM simulator disabled — passthrough",
                engine=_ENGINE_NAME,
            )

        # Only simulate payloads that look like EVM transactions
        has_to = "to" in payload or "target" in payload
        has_data = "data" in payload or "input" in payload
        if not has_to:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No EVM transaction fields — passthrough",
                engine=_ENGINE_NAME,
            )

        if self.config.simulator is None:
            if self.config.fail_closed:
                return Verdict(
                    code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                    reason="NO SIMULATOR CONFIGURED — fail closed",
                    engine=_ENGINE_NAME,
                    metadata={"error": "simulator is None"},
                )
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No simulator configured — passthrough (fail open)",
                engine=_ENGINE_NAME,
            )

        # Run simulation
        try:
            result = self.config.simulator(payload)
        except Exception as exc:
            logger.warning(
                "EVMSimulator: simulation failed for payload: %s", exc
            )
            if self.config.fail_closed:
                return Verdict(
                    code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                    reason=(
                        f"SIMULATION FAILURE: {exc} — fail closed"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={"error": str(exc)},
                )
            return Verdict(
                code=VerdictCode.ALLOW,
                reason=f"Simulation failed ({exc}) — fail open",
                engine=_ENGINE_NAME,
                metadata={"error": str(exc)},
            )

        # Check 1: Did the simulated tx revert?
        if not result.success:
            return Verdict(
                code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                reason=(
                    f"SIMULATION REVERTED: Transaction would fail on-chain. "
                    f"Error: {result.error or 'unknown revert'}"
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "success": False,
                    "error": result.error,
                    "gas_used": result.gas_used,
                },
            )

        # Check 2: Net worth loss check
        if result.net_worth_before_usd > 0:
            loss_pct = (
                (result.net_worth_before_usd - result.net_worth_after_usd)
                / result.net_worth_before_usd
            ) * 100.0

            if loss_pct > self.config.max_loss_pct:
                return Verdict(
                    code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                    reason=(
                        f"EXCESSIVE LOSS: Simulation shows {loss_pct:.1f}% "
                        f"net worth drop (max {self.config.max_loss_pct}%). "
                        f"${result.net_worth_before_usd:,.0f} → "
                        f"${result.net_worth_after_usd:,.0f}"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "loss_pct": round(loss_pct, 2),
                        "max_loss_pct": self.config.max_loss_pct,
                        "net_worth_before_usd": result.net_worth_before_usd,
                        "net_worth_after_usd": result.net_worth_after_usd,
                        "balance_before": result.balance_before,
                        "balance_after": result.balance_after,
                    },
                )

        # Check 3: Unexpected approval changes
        if self.config.block_on_approval_change and result.approvals_changed:
            return Verdict(
                code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                reason=(
                    f"APPROVAL MANIPULATION: Simulation detected "
                    f"{len(result.approvals_changed)} token approval "
                    f"change(s): {', '.join(result.approvals_changed[:5])}"
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "approvals_changed": result.approvals_changed,
                },
            )

        # Check 4: Calls to blocked contracts
        if self.config.blocked_contracts:
            blocked_lower = [c.lower() for c in self.config.blocked_contracts]
            calls_lower = [c.lower() for c in result.calls_trace]
            hit = [c for c in calls_lower if c in blocked_lower]
            if hit:
                return Verdict(
                    code=VerdictCode.BLOCK_SIMULATION_REJECTED,
                    reason=(
                        f"BLOCKED CONTRACT: Simulation shows interaction "
                        f"with blocked contract(s): {', '.join(hit[:5])}"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "blocked_contracts_hit": hit,
                        "calls_trace": result.calls_trace,
                    },
                )

        # All simulation checks passed
        return Verdict(
            code=VerdictCode.ALLOW,
            reason="Simulation passed all checks",
            engine=_ENGINE_NAME,
            metadata={
                "gas_used": result.gas_used,
                "net_worth_before_usd": result.net_worth_before_usd,
                "net_worth_after_usd": result.net_worth_after_usd,
                "balance_before": result.balance_before,
                "balance_after": result.balance_after,
            },
        )

    def reset(self) -> None:
        """No-op — EVMSimulator is stateless."""
        pass
