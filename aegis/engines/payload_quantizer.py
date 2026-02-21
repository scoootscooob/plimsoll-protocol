"""
Engine 5: Payload Quantizer — Steganographic Channel Destruction.

Defends against covert exfiltration where an attacker encodes secret
data (e.g., private key bytes) into the least-significant digits of
transaction amounts.

Example attack:
    The AI sends $1.097, $1.108, $1.101 — the trailing digits 97, 108,
    101 encode ASCII 'a', 'l', 'e'. Over many micro-transactions the
    entire private key is leaked, and EntropyGuard sees nothing abnormal
    because each amount has perfectly normal entropy.

Defence:
    Force all outgoing numeric values to snap to a configurable tick grid.
    $1.097 → $1.10 (nearest 0.10 tick). The LSB channel capacity drops
    to zero. The steganography is destroyed because the attacker can no
    longer control the low-order bits.

Quantization modes:
    - ``amount``: quantize the ``amount`` field in the payload.
    - ``all_numeric``: quantize every numeric value in the payload.

The engine can either:
    1. **Block** payloads that would be modified (strict mode), or
    2. **Rewrite** the payload in-place, snapping values to grid (permissive mode).

Time complexity: O(n) where n = number of fields in payload.
"""

from __future__ import annotations

import math
import logging
from dataclasses import dataclass, field
from typing import Any

from aegis.verdict import Verdict, VerdictCode

_ENGINE_NAME = "PayloadQuantizer"
logger = logging.getLogger("aegis")


@dataclass
class PayloadQuantizerConfig:
    """Tunable parameters for the payload quantizer."""

    enabled: bool = False
    tick_size: float = 0.01           # Snap all amounts to this grid
    quantize_fields: list[str] = field(
        default_factory=lambda: ["amount"]
    )                                  # Which payload fields to quantize
    quantize_all_numeric: bool = False  # If True, quantize ALL numeric values
    strict_mode: bool = True           # True = block if modified; False = rewrite
    tolerance: float = 0.0            # Allow deviation up to this before blocking/rewriting
    min_value: float = 0.0            # Ignore values below this (dust threshold)


@dataclass
class PayloadQuantizerEngine:
    """Steganographic channel destruction via amount quantization.

    Evaluates outgoing payloads and either blocks or rewrites any
    numeric fields whose values do not align to the tick grid.
    """

    config: PayloadQuantizerConfig = field(
        default_factory=PayloadQuantizerConfig
    )

    def _quantize(self, value: float) -> float:
        """Snap a value to the nearest tick."""
        if self.config.tick_size <= 0:
            return value
        return round(round(value / self.config.tick_size) * self.config.tick_size, 10)

    def _deviation(self, original: float, quantized: float) -> float:
        """Absolute deviation between original and quantized value."""
        return abs(original - quantized)

    def _collect_numeric_fields(
        self, payload: dict[str, Any]
    ) -> list[tuple[str, float]]:
        """Collect all numeric fields from the payload that need quantization."""
        fields = []
        if self.config.quantize_all_numeric:
            self._collect_recursive(payload, "", fields)
        else:
            for field_name in self.config.quantize_fields:
                if field_name in payload:
                    val = payload[field_name]
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        fields.append((field_name, float(val)))
        return fields

    def _collect_recursive(
        self,
        obj: Any,
        prefix: str,
        out: list[tuple[str, float]],
    ) -> None:
        """Recursively collect all numeric values from nested dicts/lists."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                path = f"{prefix}.{k}" if prefix else k
                self._collect_recursive(v, path, out)
        elif isinstance(obj, (list, tuple)):
            for i, v in enumerate(obj):
                path = f"{prefix}[{i}]"
                self._collect_recursive(v, path, out)
        elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
            out.append((prefix, float(obj)))

    def evaluate(self, payload: dict[str, Any]) -> Verdict:
        """Evaluate a payload for steganographic anomalies.

        Returns ALLOW if quantization is disabled or no fields deviate.
        Returns BLOCK_QUANTIZATION_REJECTED in strict mode if any field
        would be modified beyond tolerance.

        In permissive mode, returns ALLOW and attaches the quantized
        values in metadata (caller is responsible for applying them).
        """
        if not self.config.enabled:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="Payload quantizer disabled — passthrough",
                engine=_ENGINE_NAME,
            )

        fields = self._collect_numeric_fields(payload)
        if not fields:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="No numeric fields to quantize",
                engine=_ENGINE_NAME,
            )

        deviations = []
        quantized_map = {}

        for field_name, original in fields:
            # Skip dust-level values
            if abs(original) < self.config.min_value:
                continue

            quantized = self._quantize(original)
            dev = self._deviation(original, quantized)

            if dev > self.config.tolerance:
                deviations.append({
                    "field": field_name,
                    "original": original,
                    "quantized": quantized,
                    "deviation": round(dev, 10),
                })
                quantized_map[field_name] = quantized

        if not deviations:
            return Verdict(
                code=VerdictCode.ALLOW,
                reason="All numeric fields align to tick grid",
                engine=_ENGINE_NAME,
                metadata={"tick_size": self.config.tick_size},
            )

        # Fields deviate from grid
        if self.config.strict_mode:
            # Block — payload contains off-grid values
            field_summary = ", ".join(
                f"{d['field']}: {d['original']}→{d['quantized']}"
                for d in deviations[:3]  # Show first 3
            )
            return Verdict(
                code=VerdictCode.BLOCK_QUANTIZATION_REJECTED,
                reason=(
                    f"STEGANOGRAPHY RISK: {len(deviations)} field(s) "
                    f"deviate from tick grid (tick={self.config.tick_size}). "
                    f"{field_summary}"
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "deviations": deviations,
                    "quantized_values": quantized_map,
                    "tick_size": self.config.tick_size,
                },
            )
        else:
            # Permissive mode — allow but provide quantized values
            return Verdict(
                code=VerdictCode.ALLOW,
                reason=(
                    f"Quantized {len(deviations)} field(s) to tick grid "
                    f"(tick={self.config.tick_size})"
                ),
                engine=_ENGINE_NAME,
                metadata={
                    "quantized_values": quantized_map,
                    "deviations": deviations,
                    "tick_size": self.config.tick_size,
                    "rewritten": True,
                },
            )

    def quantize_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a new payload with all target fields snapped to the tick grid.

        This is the 'rewrite' helper — call it after evaluate() in permissive mode.
        Does NOT modify the original payload (returns a shallow copy).
        """
        if not self.config.enabled:
            return payload

        result = dict(payload)
        fields = self._collect_numeric_fields(payload)

        for field_name, original in fields:
            if abs(original) < self.config.min_value:
                continue
            quantized = self._quantize(original)
            # Only rewrite top-level fields for safety
            if field_name in result:
                result[field_name] = quantized

        return result

    def reset(self) -> None:
        """No-op — PayloadQuantizer is stateless."""
        pass
