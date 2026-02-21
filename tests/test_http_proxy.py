"""Tests for the Python HTTP proxy cost extraction and enforcement."""

from __future__ import annotations

import pytest

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.engines.capital_velocity import CapitalVelocityConfig
from plimsoll.proxy.http_proxy import extract_api_cost, evaluate_http_request


class TestExtractApiCost:
    def test_stripe_charge(self) -> None:
        cost = extract_api_cost(
            "api.stripe.com", "/v1/charges",
            body={"amount": 5000, "currency": "usd"},
        )
        assert cost == 50.0

    def test_stripe_payment_intent(self) -> None:
        cost = extract_api_cost(
            "api.stripe.com", "/v1/payment_intents",
            body={"amount": 10000},
        )
        assert cost == 100.0

    def test_openai_fixed_cost(self) -> None:
        cost = extract_api_cost(
            "api.openai.com", "/v1/chat/completions",
            body={"model": "gpt-4"},
        )
        assert cost == 0.03

    def test_ungoverned_domain(self) -> None:
        cost = extract_api_cost(
            "api.example.com", "/v1/data",
            body={"amount": 999},
        )
        assert cost is None

    def test_custom_cost_map(self) -> None:
        custom = {
            "api.brex.com": {
                "/v1/transactions": {"field": "amount", "divisor": 1.0},
            },
        }
        cost = extract_api_cost(
            "api.brex.com", "/v1/transactions",
            body={"amount": 500.0},
            cost_map=custom,
        )
        assert cost == 500.0


class TestEvaluateHttpRequest:
    def test_allowed_small_charge(self) -> None:
        fw = PlimsollFirewall(config=PlimsollConfig())
        allowed, reason, cost = evaluate_http_request(
            fw, "POST", "https://api.stripe.com/v1/charges",
            body={"amount": 100},
        )
        assert allowed
        assert cost == 1.0  # 100 cents = $1

    def test_blocked_by_velocity(self) -> None:
        fw = PlimsollFirewall(config=PlimsollConfig(
            velocity=CapitalVelocityConfig(v_max=0.001, max_single_amount=5.0),
        ))
        allowed, reason, cost = evaluate_http_request(
            fw, "POST", "https://api.stripe.com/v1/charges",
            body={"amount": 100000},  # $1000
        )
        assert not allowed
        assert cost == 1000.0

    def test_ungoverned_passthrough(self) -> None:
        fw = PlimsollFirewall(config=PlimsollConfig())
        allowed, reason, cost = evaluate_http_request(
            fw, "GET", "https://api.example.com/data",
        )
        assert allowed
        assert cost == 0.0
