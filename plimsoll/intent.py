"""
plimsoll.intent — Universal Intent Standard.

Before a payload hits the Plimsoll Firewall, it can be translated into a
dimensionless ``NormalizedIntent`` object.  This abstraction allows the
same PID controller, entropy guard, and trajectory hash to govern
EVM transactions, Solana instructions, Bitcoin PSBTs, and HTTP/REST API
charges identically.

::

    from plimsoll.intent import intent_from_evm_tx, intent_from_http_request

    intent = intent_from_evm_tx(tx_dict, price_usd=3000.0)
    verdict = firewall.evaluate_intent(intent)

    intent = intent_from_http_request("POST", "https://api.stripe.com/v1/charges",
                                       body={"amount": 5000}, amount_usd=50.0)
    verdict = firewall.evaluate_intent(intent)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


# ── Protocol & Action enums ───────────────────────────────────────


class IntentProtocol(enum.Enum):
    """Supported protocol families."""

    EVM = "EVM"
    SVM = "SVM"       # Solana Virtual Machine
    UTXO = "UTXO"     # Bitcoin / Litecoin
    HTTP = "HTTP"      # Web2 APIs (Stripe, OpenAI, Brex …)


class IntentAction(enum.Enum):
    """Universal action categories — chain-agnostic."""

    TRANSFER = "TRANSFER"
    SWAP = "SWAP"
    APPROVAL = "APPROVAL"
    API_CHARGE = "API_CHARGE"
    STAKE = "STAKE"
    BRIDGE = "BRIDGE"
    UNKNOWN = "UNKNOWN"


# ── NormalizedIntent ──────────────────────────────────────────────


@dataclass(frozen=True)
class NormalizedIntent:
    """Universal intent object consumed by the Plimsoll firewall engines.

    All payloads — regardless of origin chain or protocol — are
    translated into this common format.  The seven engines evaluate
    the ``to_plimsoll_payload()`` dict exactly like a raw EVM dict.

    Attributes
    ----------
    protocol : IntentProtocol
    action : IntentAction
    capital_at_risk_usd : float
        The maximum USD-denominated capital that could be lost.
    """

    protocol: IntentProtocol
    action: IntentAction
    capital_at_risk_usd: float

    # Standard fields translated from protocol-specific formats
    target: str = ""                 # Destination address / URL
    source: str = ""                 # Sender address
    amount_raw: float = 0.0          # Amount in native units (Wei, Lamports, Sats)
    amount_usd: float = 0.0          # USD-normalised amount
    function: str = ""               # Selector / API endpoint
    data: str = ""                   # Calldata hash / request body hash
    chain_id: int = 0                # Chain ID (0 → non-blockchain)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_plimsoll_payload(self) -> dict[str, Any]:
        """Convert to the dict format that ``PlimsollFirewall.evaluate()`` expects."""
        payload: dict[str, Any] = {
            "target": self.target,
            "amount": self.amount_usd or self.capital_at_risk_usd,
            "function": self.function,
            "protocol": self.protocol.value,
            "action": self.action.value,
        }
        if self.data:
            payload["data"] = self.data
        if self.chain_id:
            payload["chain_id"] = self.chain_id
        payload.update(self.metadata)
        return payload


# ── Protocol-Specific Translators ─────────────────────────────────

# Well-known EVM function selectors
_APPROVAL_SELECTORS = frozenset({
    "0x095ea7b3",   # approve(address,uint256)
})
_SWAP_SELECTORS = frozenset({
    "0x38ed1739",   # swapExactTokensForTokens
    "0x8803dbee",   # swapTokensForExactTokens
    "0x7ff36ab5",   # swapExactETHForTokens
    "0x18cbafe5",   # swapExactTokensForETH
    "0x5c11d795",   # swapExactTokensForTokensSupportingFeeOnTransferTokens
    "0x414bf389",   # Uniswap V3 exactInputSingle
    "0xc04b8d59",   # Uniswap V3 exactInput
    "0xdb3e2198",   # Uniswap V3 exactOutputSingle
})


def intent_from_evm_tx(
    tx_dict: dict[str, Any],
    price_usd: float = 0.0,
) -> NormalizedIntent:
    """Translate an Ethereum transaction dict to :class:`NormalizedIntent`.

    Parameters
    ----------
    tx_dict : dict
        Standard Ethereum tx dict (``to``, ``value``, ``data``, …).
    price_usd : float
        ETH→USD price.  ``0`` means keep raw Wei values.
    """
    value_wei = float(tx_dict.get("value", 0))
    gas = float(tx_dict.get("gas", 21_000))
    max_fee = float(tx_dict.get("maxFeePerGas", 0) or tx_dict.get("gasPrice", 0))
    pvg = float(tx_dict.get("preVerificationGas", 0))

    tvar_wei = value_wei + (gas * max_fee) + (pvg * max_fee)

    # Determine action from function selector
    raw_data = str(tx_dict.get("data", tx_dict.get("input", "")))
    selector = raw_data[:10].lower() if raw_data and len(raw_data) >= 10 else ""

    if selector in _APPROVAL_SELECTORS:
        action = IntentAction.APPROVAL
    elif selector in _SWAP_SELECTORS:
        action = IntentAction.SWAP
    elif value_wei > 0:
        action = IntentAction.TRANSFER
    else:
        action = IntentAction.UNKNOWN

    # USD conversion
    if price_usd > 0:
        value_eth = value_wei / 1e18
        tvar_eth = tvar_wei / 1e18
        capital_usd = tvar_eth * price_usd
        amount_usd = value_eth * price_usd
    else:
        capital_usd = tvar_wei
        amount_usd = value_wei

    return NormalizedIntent(
        protocol=IntentProtocol.EVM,
        action=action,
        capital_at_risk_usd=capital_usd,
        target=str(tx_dict.get("to", "")),
        source=str(tx_dict.get("from", "")),
        amount_raw=value_wei,
        amount_usd=amount_usd,
        function=selector,
        data=raw_data,
        chain_id=int(tx_dict.get("chainId", 0)),
    )


def intent_from_solana_tx(
    instruction: dict[str, Any],
    price_usd: float = 0.0,
) -> NormalizedIntent:
    """Translate a Solana instruction dict to :class:`NormalizedIntent`."""
    lamports = float(instruction.get("lamports", 0))
    sol_amount = lamports / 1e9

    if price_usd > 0:
        capital_usd = sol_amount * price_usd
        amount_usd = capital_usd
    else:
        capital_usd = sol_amount
        amount_usd = sol_amount

    return NormalizedIntent(
        protocol=IntentProtocol.SVM,
        action=IntentAction.TRANSFER,
        capital_at_risk_usd=capital_usd,
        target=str(instruction.get("to", instruction.get("destination", ""))),
        source=str(instruction.get("from", instruction.get("source", ""))),
        amount_raw=lamports,
        amount_usd=amount_usd,
        function=str(instruction.get("program_id", "")),
    )


def intent_from_bitcoin_psbt(
    psbt_data: dict[str, Any],
    price_usd: float = 0.0,
) -> NormalizedIntent:
    """Translate a Bitcoin PSBT summary to :class:`NormalizedIntent`.

    Parameters
    ----------
    psbt_data : dict
        Must include ``total_input_sats`` and ``total_output_sats``.
    """
    total_input = float(psbt_data.get("total_input_sats", 0))
    total_output = float(psbt_data.get("total_output_sats", 0))
    fee_sats = total_input - total_output
    btc_amount = total_output / 1e8

    if price_usd > 0:
        capital_usd = btc_amount * price_usd
    else:
        capital_usd = total_output

    return NormalizedIntent(
        protocol=IntentProtocol.UTXO,
        action=IntentAction.TRANSFER,
        capital_at_risk_usd=capital_usd,
        target=str(psbt_data.get("primary_recipient", "")),
        amount_raw=total_output,
        amount_usd=capital_usd,
        metadata={"fee_sats": fee_sats, "fee_btc": fee_sats / 1e8},
    )


def intent_from_http_request(
    method: str,
    url: str,
    body: Optional[dict[str, Any]] = None,
    amount_usd: float = 0.0,
) -> NormalizedIntent:
    """Translate an HTTP API request to :class:`NormalizedIntent`."""
    return NormalizedIntent(
        protocol=IntentProtocol.HTTP,
        action=IntentAction.API_CHARGE,
        capital_at_risk_usd=amount_usd,
        target=url,
        amount_usd=amount_usd,
        function=f"{method.upper()} {url}",
        data=str(body) if body else "",
    )
