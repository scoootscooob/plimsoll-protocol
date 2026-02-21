"""
Plimsoll Protocol — Deterministic Circuit Breaker for Autonomous AI Agents.

The financial seatbelt for the machine economy.
"""

from plimsoll.firewall import PlimsollFirewall, PlimsollConfig
from plimsoll.decorator import with_plimsoll_firewall
from plimsoll.verdict import Verdict, VerdictCode
from plimsoll.engines.threat_feed import ThreatFeedEngine, ThreatFeedConfig
from plimsoll.enclave.vault import KeyVault, PlimsollEnforcementError
from plimsoll.escrow import EscrowQueue, EscrowConfig, EscrowedTransaction, EscrowStatus, IntentClassifier
from plimsoll.enclave.tee import TEEEnclave, TEEConfig, TEEBackend, SoftwareBackend, AttestationReport
from plimsoll.intent import NormalizedIntent, IntentProtocol, IntentAction

__all__ = [
    "PlimsollFirewall",
    "PlimsollConfig",
    "with_plimsoll_firewall",
    "Verdict",
    "VerdictCode",
    "ThreatFeedEngine",
    "ThreatFeedConfig",
    "KeyVault",
    "PlimsollEnforcementError",
    "EscrowQueue",
    "EscrowConfig",
    "EscrowedTransaction",
    "EscrowStatus",
    "IntentClassifier",
    "TEEEnclave",
    "TEEConfig",
    "TEEBackend",
    "SoftwareBackend",
    "AttestationReport",
    "NormalizedIntent",
    "IntentProtocol",
    "IntentAction",
]

__version__ = "2.0.0"
