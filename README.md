<div align="center">

# Plimsoll

**The deterministic execution substrate for autonomous capital.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/Tests-836_passing-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/Rust-Blazing_Fast-orange.svg)]()
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)]()
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636.svg)]()
[![Integration](https://img.shields.io/badge/Integrates_with-OpenClaw_%7C_Automaton_%7C_Eliza_%7C_LangChain-success.svg)]()

> **"Brains are probabilistic. Capital is deterministic. Plimsoll is the physical boundary between the two."**

</div>

---

## The "Feral AI" Bottleneck

Right now, developers are building brilliant trading agents using OpenClaw, Automaton, Eliza, and LangChain. But there is a multi-billion dollar bottleneck: **LLMs hallucinate by design.**

Give a probabilistic AI the private keys to a $50,000 treasury and you will eventually get drained. Prompt injection. MEV sandwich. Hallucinated retry loop. It's not a question of *if*. It's a question of *which block number*.

Because of this fear, enterprises force a **"Human-in-the-Loop"** to manually click "Approve" on every trade.

**Human-in-the-loop is a financial death sentence.** If a human has to approve your arbitrage trade, MEV bots front-run you by 12 seconds. Your agent is a Ferrari with a parking brake welded shut.

---

## What is Plimsoll?

We don't try to fix the LLM. We assume the brain *will* be compromised.

**Plimsoll is the deterministic spinal cord between the AI's brain and its hands.** We intercept every transaction off-chain, simulate EVM/SVM/UTXO state in sub-milliseconds, and run the payload through 7 mathematical physics engines before the private key is ever touched.

If an agent attempts to violate your velocity, entropy, or slippage limits, we physically drop the transaction and return a **Semantic Revert** directly into the LLM context window. The agent doesn't crash. It adapts. It executes safely on the next tick.

**We are the ceramic brakes that finally allow autonomous capital to drive at 200 MPH.**

```
┌──────────────┐     ┌────────────────────────────────────────┐     ┌──────────┐
│              │     │           PLIMSOLL FIREWALL             │     │          │
│   LLM Agent  │────▶│                                        │────▶│  Chain / │
│   (Reason)   │     │  Threat Feed ─▶ Trajectory Hash        │     │   API    │
│              │◀────│  ─▶ Capital Velocity ─▶ Entropy Guard   │     │  (Act)   │
│  ◀─feedback  │     │  ─▶ Asset Guard ─▶ Payload Quantizer   │     │          │
│              │     │  ─▶ EVM Simulator                      │     │          │
└──────────────┘     └────────────────────────────────────────┘     └──────────┘
                            ▲                        │
                            │     Context-Window     │
                            │       Airgap           │
                            │                        ▼
                      ┌─────────────┐        ┌──────────────┐
                      │  Key Vault  │        │  On-Chain     │
                      │  (Enclave)  │        │  Vault + PoBR │
                      └─────────────┘        └──────────────┘
```

The private key **never touches the LLM context window.** The vault enforces firewall approval *before* decrypting. The agent can think about whatever it wants. It can only *do* what physics allows.

---

## Zero-Friction Integration

Security tools fail when they require you to rewrite your codebase. Plimsoll wraps natively around the world's best AI agent frameworks in **one line of code**.

### Option A: Framework Native

```python
# OpenClaw
from plimsoll.integrations.openclaw import PlimsollDeFiTools

tools = PlimsollDeFiTools(firewall=firewall)
tools.register("swap", swap_fn, spend_key="amount")
agent.run("Find yield on Arbitrum and deploy our treasury.")

# Automaton (Conway)
from plimsoll.integrations.automaton import PlimsollAutomatonWallet
wallet = PlimsollAutomatonWallet(firewall=firewall, inner_wallet=raw_wallet)

# Eliza
from plimsoll.integrations.eliza import PlimsollElizaAction
protected = PlimsollElizaAction(firewall=firewall, inner_action=my_action)

# LangChain
from plimsoll.integrations.langchain import plimsoll_tool

@plimsoll_tool(firewall)
@tool
def swap_tokens(token_in: str, token_out: str, amount: float):
    ...
```

### Option B: The "Zero-Code" RPC Override

Don't want to touch your Python? Just point your agent's RPC URL at Plimsoll. The LLM doesn't even know it's wearing a mathematical straightjacket.

```env
# Before: Feral, naked, and vulnerable
RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY

# After: Blanketed by 7 deterministic physics engines
RPC_URL=http://localhost:8545
```

```bash
docker compose -f plimsoll-rpc/docker-compose.yml up
```

### Option C: Drop-In Decorator

```python
from plimsoll import PlimsollFirewall, with_plimsoll_firewall

@with_plimsoll_firewall(PlimsollFirewall())
def send_payment(target: str, amount: float):
    return wallet.transfer(target, amount)

# Blocked calls return cognitive feedback, not exceptions
send_payment(target="0xHACKER", amount=99999)
```

---

## Semantic Feedback Loops (We Teach, We Don't Crash)

When Plimsoll blocks a catastrophic trade, it doesn't just drop the TCP connection. It intercepts the payload and returns a synthetic, LLM-formatted prompt directly into the agent's observation loop:

```json
{
  "status": "PLIMSOLL_INTERVENTION",
  "code": "BLOCK_VELOCITY_BREACH",
  "reason": "Spend velocity 847.3 $/min exceeds PID governor threshold. Daily budget 73% consumed in 4 minutes.",
  "instruction": "Reduce position size or wait 6m 12s for velocity window to decay. Current safe maximum: $23.40."
}
```

Your agent doesn't die. It learns, adapts, and executes safely on the next tick. The LLM reads the feedback, reduces its position size, and retries. No human needed. No crash. No drain.

---

## The 7-Cylinder Engine

Every outbound payload passes through all seven engines in series. First block wins. Sub-millisecond total.

| # | Engine | What It Kills | How It Works |
|---|--------|--------------|--------------|
| 0 | **Threat Feed** | Known exploiters, malicious selectors, poisoned calldata | Bloom filter blacklist with Sybil-resistant crowd-sourced IOCs. If an agent in Tokyo gets hit with a zero-day, your agent in New York is immunized in 12ms. |
| 1 | **Trajectory Hash** | Hallucination retry loops, stuck agents | SHA-256 of canonical params in a sliding window. 3 identical calls in 60s = block + cognitive sever. |
| 2 | **Capital Velocity** | Wallet drain, rapid spend-down, slow bleed | PID controller (P + I + D) with HMAC-derived jitter. The threshold is *mathematically unpredictable* — attackers can't probe it. |
| 3 | **Entropy Guard** | Private key exfiltration, seed phrase leakage | Shannon entropy + regex for ETH keys, Solana keys, BIP-39 mnemonics, base64 blobs. If the LLM tries to POST your private key anywhere, it's dead on arrival. |
| 4 | **Asset Guard** | Rug pull swaps, stale intents, bridge hijacks | Token allow-list, oracle liquidity check, slippage cap, 24s intent TTL, bridge destination pinning. |
| 5 | **Payload Quantizer** | Steganographic data exfiltration | Snaps numeric values to tick grid, destroying covert channels hidden in amount fields. |
| 6 | **EVM Simulator** | Revert traps, approval exploits, net-worth attacks | Pre-execution simulation via revm shadow-fork. If the simulation shows your vault loses money, the real transaction never fires. |

---

## 38 Threat Vectors. 8 Patch Generations. Zero Bypasses.

<details>
<summary><strong>Core Defenses (v1.0)</strong></summary>

| Code | Attack |
|------|--------|
| `BLOCK_LOOP_DETECTED` | Hallucination retry spiral |
| `BLOCK_VELOCITY_BREACH` | Spend rate exceeds PID governor |
| `BLOCK_VELOCITY_JITTER` | Attacker probing threshold boundary |
| `BLOCK_ENTROPY_ANOMALY` | Secret / private key in payload |
| `BLOCK_ASSET_REJECTED` | Bad swap, oracle liquidity fail, stale intent |
| `BLOCK_GLOBAL_BLACKLIST` | Known malicious address or selector |
| `BLOCK_QUANTIZATION_REJECTED` | Steganographic numeric channel |
| `BLOCK_SIMULATION_REJECTED` | Simulation revert, net worth loss, approval exploit |
| `BLOCK_EIP712_PERMIT` | EIP-712 "Silent Dagger" — malicious typed data signing |
| `BLOCK_REALITY_DESYNC` | Stale simulation block vs. chain head |
| `BLOCK_GAS_VALUE_RATIO` | Paymaster parasite — gas cost exceeds tx value |

</details>

<details>
<summary><strong>Zero-Day Kill Shots (v1.0.1 — v1.0.4)</strong></summary>

| Code | Attack |
|------|--------|
| `BLOCK_METAMORPHIC_CODE` | EXTCODEHASH mismatch — contract mutated post-simulation |
| `BLOCK_COGNITIVE_STARVATION` | Rapid-fire revert loop severing agent cognition |
| `BLOCK_TROJAN_RECEIPT` | Prompt injection via `eth_getTransactionReceipt` response |
| `BLOCK_NON_DETERMINISTIC` | State inspector — re-simulate diverges from original |
| `BLOCK_CROSS_CHAIN_REPLAY` | Permit signature replayed across L1/L2 chains |
| `BLOCK_PAYMASTER_SEVERED` | Paymaster slashing — too many reverts, auto-revoke |
| `BLOCK_JSON_POLLUTION` | Duplicate JSON keys with conflicting values |
| `BLOCK_PROXY_UPGRADE` | Unauthorized EIP-1967 implementation slot change |
| `BLOCK_L1_DATA_FEE_ANOMALY` | L1 blob fee spike on rollups |
| `BLOCK_GAS_ANOMALY` | Gas black hole — actual gas 10x simulated gas |
| `BLOCK_BUNDLER_ORIGIN_MISMATCH` | ERC-4337 bundler illusion attack |
| `BLOCK_PVG_CEILING_EXCEEDED` | Pre-verification gas heist |
| `BLOCK_BRIDGE_REFUND_HIJACK` | Bridge refund redirected to attacker address |
| `BLOCK_PERMIT_EXPIRY_TOO_LONG` | Permit2 time-bomb (immortal signature) |

</details>

<details>
<summary><strong>Multi-Chain Defenses (v2.0)</strong></summary>

| Code | Attack |
|------|--------|
| `BLOCK_SVM_UNAUTHORIZED_WRITABLE` | Solana: unauthorized writable account injection |
| `BLOCK_UTXO_FEE_EXCESSIVE` | Bitcoin: fee exceeds conservation-of-mass limit |
| `BLOCK_HTTP_BUDGET_EXCEEDED` | Web2 API: spend exceeds budget |
| `BLOCK_INTENT_REJECTED` | Universal intent failed cross-chain validation |

</details>

---

## Multi-Chain. Not Multi-Compromise.

| Chain | On-Chain Vault | Off-Chain Proxy | What It Enforces |
|-------|---------------|----------------|-----------------|
| **Ethereum + 9 L2s** | `PlimsollVault.sol` (ERC-4337) | Rust `plimsoll-rpc` with revm | Session keys, velocity limits, drawdown guard, target whitelist, PoBR attestation |
| **Solana** | Anchor PDA vault + cosigner | SVM writable-account guard | Cosigner-enforced CPI, daily budget, single-tx cap, emergency lock |
| **Bitcoin** | Taproot 2-of-2 (P2TR) | UTXO conservation-of-mass | CHECKSIGVERIFY script-path, CSV recovery (144 blocks), fee guard |
| **Web2 APIs** | — | HTTP cost extraction | Per-API budget caps for Stripe, AWS, external services |

**Supported L2s:** Optimism, Base, Arbitrum One, Arbitrum Nova, zkSync Era, Polygon zkEVM, Scroll, Linea, Zora — with L1 data fee awareness.

---

## On-Chain Physics

### PlimsollVault (Ethereum)

ERC-4337 smart account. Not a multisig. Not a timelock. A **physics engine on-chain**.

Three pluggable modules enforce the laws of capital:
- **VelocityLimitModule** — Hourly spend cap + single-tx cap with sliding window
- **DrawdownGuardModule** — Max drawdown from initial deposit (basis points)
- **TargetWhitelistModule** — Only approved contract addresses can receive funds

Session keys scope AI agents to time-limited, budget-capped execution. The agent gets a leash. The leash has math.

### Proof of Bounded Risk (PoBR)

`PlimsollAttestation.sol` mints on-chain attestations: *"This vault's max daily drawdown is 5%."*

DeFi protocols query PoBR to grant **under-collateralized leverage** to provably-bounded agents. Your agent gets better rates than a human because it can *prove* its risk envelope. Bridges to Ethereum Attestation Service (EAS) via `PlimsollEASAdapter.sol`.

### Solana Vault

Anchor program. PDA vault (`seeds = ["plimsoll-vault", owner]`). Every CPI execution requires BOTH the agent signer AND the Plimsoll cosigner. Daily budget. Single-tx cap. Emergency lock/unlock. On-chain velocity.

### Bitcoin Vault

P2TR (Taproot) 2-of-2 with `CHECKSIGVERIFY` + `CHECKSIG` script-path spending. NUMS internal key forces all spends through the script path — no key-path bypass. `OP_CHECKSEQUENCEVERIFY` owner recovery after 144 blocks (~24h). PSBT validation with conservation-of-mass fee guard blocks zero-output attacks and fee extraction.

---

## The Vault Architecture (Context-Window Airgap)

Most agent frameworks store the private key in a Python variable. The LLM can see it. Exfiltrate it. Leak it in a debug log.

Plimsoll's `KeyVault` stores the key in an encrypted enclave. The LLM never sees the key. The key only decrypts after the firewall returns `ALLOW`.

```python
from plimsoll import PlimsollFirewall, KeyVault

vault = KeyVault()
vault.store("treasury", my_private_key)
vault.bind_firewall(PlimsollFirewall())

# The firewall evaluates BEFORE the key is ever decrypted
signed_tx = vault.sign_eth_transaction(
    key_id="treasury",
    tx_dict={"to": recipient, "value": amount, "gas": 21000},
    spend_amount=1.5
)
```

**Production deployment:** AWS Nitro Enclave with no network, no disk, no debug access. KMS delivers the data key only after PCR0 attestation (SHA-384 hash of the enclave image). Even AWS admins cannot decrypt without the matching enclave binary.

```bash
cd deploy/nitro
terraform init && terraform apply
nitro-cli build-enclave --docker-uri plimsoll-enclave --output-file plimsoll.eif
nitro-cli run-enclave --eif-path plimsoll.eif --memory 512 --cpu-count 2
```

---

## The Rust Proxy (For the "I Don't Want to Write Python" Crowd)

`plimsoll-rpc` is a standalone Rust binary. Point any agent's RPC URL at it. Zero code changes.

```
Agent ──▶ plimsoll-rpc (localhost:8545)
              │
              ├── Intercept eth_sendTransaction / eth_sendRawTransaction
              ├── Fork mainnet state, simulate in local revm
              ├── Run 7 physics engines against state deltas
              ├── Sanitize ALL RPC responses (anti-prompt-injection)
              ├── Route approved txs through Flashbots Protect (MEV shield)
              ├── Index events to PostgreSQL (fleet dashboard)
              └── Collect 1-2 bps protocol fee
```

15 Rust modules. 77 tests. Handles EVM, SVM, and UTXO chains.

---

## See It Break (Then See It Save)

### The Scare Campaign (no keys, no setup)

```bash
pip install plimsoll-protocol
python3 demo/scare_campaign.py
```

Watch three attacks hit an unprotected agent, then watch Plimsoll catch every single one:

1. **Rapid Wallet Drain** — 4 transfers to a hacker ($400, $300, $200, $100). Velocity engine blocks at $700.
2. **Private Key Exfiltration** — Agent POSTs its 256-bit hex key to an evil server. Entropy guard: dead on arrival.
3. **Hallucination Retry Loop** — 5 identical swap attempts. Trajectory hash blocks after the 3rd in 60s.

### Live Agent Demo (GPT-4o-mini + Sepolia)

```bash
export OPENAI_API_KEY=sk-...
python3 demo/live_agent.py             # dry-run (default)
python3 demo/live_agent.py --live      # real Sepolia transactions
```

A real GPT-4o-mini agent manages funds on Ethereum Sepolia. Phase 1: legitimate operations pass through cleanly. Phase 2: prompt injection attack — Plimsoll intercepts, blocks, and feeds cognitive correction back to the LLM in real-time. The agent recovers. The vault survives.

---

## 836 Tests. 5 Languages. Zero Failures.

| Suite | Lang | Tests | What It Proves |
|-------|------|------:|----------------|
| Core SDK + Engines + KMS | Python | 540 | 7 engines, vault security, escrow, intents, CLI, 4 framework integrations, 16 zero-day patches |
| RPC Proxy + Simulator + MEV | Rust | 77 | EVM simulation, Flashbots bundling, response sanitizer, threat feed, SVM simulator, UTXO guard |
| Bitcoin Taproot | Rust | 14 | Script construction, PSBT validation, conservation-of-mass, CSV recovery encoding |
| Fleet Indexer | Rust | 35 | EVM/Solana event parsing, dedup, USD enrichment, PostgreSQL schema |
| Smart Contracts | Solidity | 170 | Vault, session keys, 3 modules, attestation, EAS adapter, fuzz tests |

```bash
python3 -m pytest tests/ -v              # 540
cd plimsoll-rpc && cargo test            # 77
cd contracts/bitcoin && cargo test       # 14
cd indexer && cargo test                 # 35
cd contracts && forge test               # 170
```

---

## Install

```bash
pip install plimsoll-protocol
```

```bash
# With framework support
pip install "plimsoll-protocol[langchain]"
pip install "plimsoll-protocol[automaton]"
pip install "plimsoll-protocol[eliza]"

# Everything (dev + all integrations)
pip install "plimsoll-protocol[dev]"
```

```bash
# From source
git clone https://github.com/scoootscooob/plimsoll-protocol.git
cd plimsoll-protocol && pip install -e ".[dev]"
```

---

## Configure

```python
from plimsoll import PlimsollFirewall, PlimsollConfig

firewall = PlimsollFirewall(config=PlimsollConfig(
    # Capital Velocity (PID governor)
    v_max=100.0,                  # Max $/window
    window_seconds=300.0,          # 5-minute sliding window
    k_p=1.0, k_i=0.3, k_d=0.5,   # PID gains
    pid_threshold=2.0,             # Block when PID signal > threshold

    # Trajectory Hash (loop detection)
    trajectory_window_seconds=60.0,
    trajectory_max_duplicates=3,

    # Entropy Guard (secret detection)
    entropy_threshold=5.0,

    # Cognitive Starvation Defense
    strike_max=5,                  # Blocks in window before full sever
    strike_window_secs=60,
    sever_duration_secs=900,       # 15-min cooldown after sever

    # ERC-4337 Defenses
    max_pre_verification_gas=0,    # 0 = disabled
    max_permit_duration_secs=0,    # 0 = disabled

    # Chain awareness
    chain_id=1,                    # Mainnet
))
```

---

## Architecture

```
plimsoll-protocol/
├── plimsoll/                    # Python SDK (pip install plimsoll-protocol)
│   ├── firewall.py              #   Orchestrator — chains 7 engines, first block wins
│   ├── decorator.py             #   @with_plimsoll_firewall drop-in wrapper
│   ├── verdict.py               #   38 verdict codes + cognitive feedback prompts
│   ├── intent.py                #   NormalizedIntent (EVM/SVM/UTXO/HTTP → dimensionless)
│   ├── escrow.py                #   Human-in-the-loop approval queue (when you want it)
│   ├── engines/                 #   7 deterministic math engines
│   ├── enclave/                 #   KeyVault + TEE abstraction (Nitro/SGX/TZ)
│   ├── proxy/                   #   ASGI interceptor (JSON-RPC + REST)
│   ├── vault/                   #   On-chain vault SDK (ERC-4337 + PoBR)
│   ├── integrations/            #   LangChain, Eliza, Automaton, OpenClaw
│   ├── oracles/                 #   Price feed (Pyth, Chainlink, CoinGecko fallback)
│   └── cli/                     #   plimsoll init | up | status
│
├── plimsoll-rpc/                # Rust RPC proxy (axum + revm + Flashbots Protect)
│   └── src/                     #   15 modules: simulator, inspector, sanitizer,
│                                #   threat_feed, flashbots, svm_simulator,
│                                #   utxo_guard, telemetry, fee, http_proxy...
│
├── contracts/
│   ├── src/
│   │   ├── PlimsollVault.sol        # ERC-4337 smart account + on-chain physics
│   │   ├── PlimsollAttestation.sol  # Proof of Bounded Risk (PoBR) registry
│   │   └── PlimsollEASAdapter.sol   # Ethereum Attestation Service bridge
│   ├── solana/                      # Anchor program — PDA vault + cosigner
│   └── bitcoin/                     # Taproot 2-of-2 (P2TR + CSV recovery)
│
├── indexer/                     # Rust multi-chain event indexer (Tokio async)
│   └── src/                     #   EVM + Solana listeners, dedup, USD enrichment,
│                                #   PostgreSQL with PARTITION BY LIST(chain_id)
│
├── dapp/                        # React + Next.js + wagmi dashboard
├── deploy/nitro/                # AWS Nitro Enclave (Terraform + KMS/PCR0 bootstrap)
├── demo/                        # scare_campaign.py + live GPT-4o agent demo
└── tests/                       # 836 tests across Python, Rust, Solidity
```

---

## Roadmap

- [x] 7 deterministic math engines
- [x] Context-window airgap (KeyVault)
- [x] 16 zero-day / kill-shot security patches
- [x] ERC-4337 smart account with on-chain physics modules
- [x] Proof of Bounded Risk (PoBR) attestation + EAS bridge
- [x] Multi-chain (Ethereum + 9 L2s, Solana, Bitcoin, Web2)
- [x] Rust RPC proxy with revm simulation + Flashbots Protect
- [x] AWS Nitro Enclave with KMS/PCR0 bootstrap + HKDF derivation
- [x] Multi-chain fleet indexer (PostgreSQL + materialized views)
- [x] 4 framework integrations (LangChain, Eliza, Automaton, OpenClaw)
- [ ] MPC signing (Turnkey distributed key shares)
- [ ] Formal verification of engine invariants (Coq/Lean proofs)
- [ ] Cross-agent reputation graph
- [ ] Autonomous rebalancing within PoBR bounds
- [ ] Live mainnet bounty vaults

---

## Security

Plimsoll is security infrastructure. Every design decision assumes the worst case.

- **Fail closed** — if any engine errors, the transaction is blocked. Not logged. Blocked.
- **Deterministic** — no randomness in block decisions. Jitter is HMAC-derived, not `random()`.
- **Defense in depth** — 7 engines, each catching a different attack class. Redundancy is the point.
- **Zero trust** — the LLM is treated as an untrusted, adversarial input source. Always.

Found a vulnerability? **Do not open a public issue.** Email security@plimsollprotocol.com. We acknowledge within 24 hours.

---

## Contributing

We welcome contributors. The codebase is 836 tests deep — it's hard to break.

1. Fork the repository
2. Create a feature branch
3. Ensure all 836 tests pass across all 5 suites
4. Submit a pull request

---

## License

[MIT](LICENSE) — Use it, fork it, protect your agents.

---

<p align="center">
  <strong>Stop babysitting your agents. Let them drive.</strong>
</p>
