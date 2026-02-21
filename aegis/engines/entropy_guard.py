"""
Engine 3: Shannon Entropy Guard — Data Exfiltration Prevention.

Malicious skills can trick an agent into transmitting private keys, seed
phrases, or environment variables to a hacker's server by embedding them
in outgoing API payloads. Standard API calls have a predictable, low-entropy
distribution of byte values. A base64-encoded private key or encrypted blob
causes a massive entropy spike.

Algorithm:
    1. Serialize outgoing payload values to bytes.
    2. Compute Shannon entropy: H(X) = -Σ P(x) log₂ P(x) over byte dist.
    3. If H(X) exceeds threshold (typically ~4.5 bits for structured JSON,
       vs ~5.8+ for encrypted/encoded secrets), flag and sever the connection.

Additionally performs pattern matching for known secret formats (hex keys,
base64 blobs, seed phrases).

Time complexity: O(n) where n = payload byte length.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from aegis.verdict import Verdict, VerdictCode

_ENGINE_NAME = "EntropyGuard"

# Patterns that are almost certainly secrets
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ethereum_private_key", re.compile(r"0x[0-9a-fA-F]{64}")),
    ("hex_key_256bit", re.compile(r"[0-9a-fA-F]{64}")),
    ("base64_blob_long", re.compile(r"[A-Za-z0-9+/=]{60,}")),
    ("solana_private_key", re.compile(r"[1-9A-HJ-NP-Za-km-z]{87,88}")),
    ("mnemonic_phrase", re.compile(
        r"\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|"
        r"abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|"
        r"across|act|action|actor|actress|actual|adapt|add|addict|address|"
        r"adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|"
        r"again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|"
        r"alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|"
        r"also|alter|always|amateur|amazing|among|amount|amused|analyst|"
        r"anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|"
        r"another|answer|antenna|antique|anxiety|any|apart|apology|appear|"
        r"apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|"
        r"army|around|arrange|arrest|arrive|arrow|art|artefact|artist|"
        r"artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|"
        r"atom|attack|attend|attitude|attract|auction|audit|august|aunt|"
        r"author|auto|autumn|average|avocado|avoid|awake|aware|awesome|"
        r"awful|awkward|axis)\b"
        r"(?:\s+\b(?:abandon|ability|able|about|above|absent|absorb|abstract|"
        r"absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|"
        r"acquire|across|act|action|actor|actress|actual|adapt|add|addict|"
        r"address|adjust|admit|adult|advance|advice|aerobic|affair|afford|"
        r"afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|"
        r"album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|"
        r"already|also|alter|always|amateur|amazing|among|amount|amused|"
        r"analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|"
        r"annual|another|answer|antenna|antique|anxiety|any|apart|apology|"
        r"appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|"
        r"armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|"
        r"artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|"
        r"attack|attend|attitude|attract|auction|audit|august|aunt|author|"
        r"auto|autumn|average|avocado|avoid|awake|aware|awesome|awful|"
        r"awkward|axis)\b){11,}"
    )),
]


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits over the byte distribution."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _flatten_values(obj: object) -> list[str]:
    """Recursively extract all string values from a nested structure."""
    values: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            values.extend(_flatten_values(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            values.extend(_flatten_values(item))
    elif isinstance(obj, str):
        values.append(obj)
    elif obj is not None:
        values.append(str(obj))
    return values


@dataclass
class EntropyGuardConfig:
    """Tunable parameters for the entropy guard engine."""

    entropy_threshold: float = 5.0
    min_value_length: int = 32
    enable_pattern_matching: bool = True


@dataclass
class EntropyGuardEngine:
    """Detects high-entropy secrets in outgoing payloads."""

    config: EntropyGuardConfig = field(default_factory=EntropyGuardConfig)

    def _check_patterns(self, text: str) -> str | None:
        """Return the name of the first secret pattern matched, or None."""
        if not self.config.enable_pattern_matching:
            return None
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(text):
                return name
        return None

    def evaluate(self, payload: dict) -> Verdict:
        """Evaluate an outgoing payload for entropy anomalies."""
        values = _flatten_values(payload)

        for val in values:
            # Pattern matching — fast path
            pattern_hit = self._check_patterns(val)
            if pattern_hit:
                return Verdict(
                    code=VerdictCode.BLOCK_ENTROPY_ANOMALY,
                    reason=(
                        f"SECRET PATTERN DETECTED: '{pattern_hit}' found in "
                        f"outgoing payload value (length {len(val)})"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "pattern": pattern_hit,
                        "value_prefix": val[:16] + "…",
                        "value_length": len(val),
                    },
                )

            # Entropy check — for sufficiently long values
            if len(val) >= self.config.min_value_length:
                entropy = _shannon_entropy(val.encode())
                if entropy > self.config.entropy_threshold:
                    return Verdict(
                        code=VerdictCode.BLOCK_ENTROPY_ANOMALY,
                        reason=(
                            f"ENTROPY ANOMALY: Value has {entropy:.2f} bits "
                            f"entropy (threshold: {self.config.entropy_threshold}). "
                            f"Possible secret/key exfiltration"
                        ),
                        engine=_ENGINE_NAME,
                        metadata={
                            "entropy": round(entropy, 4),
                            "threshold": self.config.entropy_threshold,
                            "value_prefix": val[:16] + "…",
                            "value_length": len(val),
                        },
                    )

        # Whole-payload entropy as a final check
        serialized = json.dumps(payload, sort_keys=True).encode()
        if len(serialized) >= self.config.min_value_length:
            total_entropy = _shannon_entropy(serialized)
            if total_entropy > self.config.entropy_threshold + 0.5:
                return Verdict(
                    code=VerdictCode.BLOCK_ENTROPY_ANOMALY,
                    reason=(
                        f"PAYLOAD ENTROPY ANOMALY: Whole payload has "
                        f"{total_entropy:.2f} bits (threshold: "
                        f"{self.config.entropy_threshold + 0.5})"
                    ),
                    engine=_ENGINE_NAME,
                    metadata={
                        "payload_entropy": round(total_entropy, 4),
                        "payload_bytes": len(serialized),
                    },
                )

        return Verdict(
            code=VerdictCode.ALLOW,
            reason="Entropy within normal bounds",
            engine=_ENGINE_NAME,
        )
