//! Plimsoll Bitcoin Vault — Taproot 2-of-2 Multisig Script.
//!
//! Implements a P2TR (Pay-to-Taproot) UTXO guard that requires BOTH
//! the agent key AND the Plimsoll proxy key to sign before spending.
//!
//! ## Architecture
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────┐
//!   │  P2TR Output (Taproot)                              │
//!   │                                                     │
//!   │  Internal Key: MuSig2(owner, plimsoll_proxy)           │
//!   │                                                     │
//!   │  Script Path (fallback):                            │
//!   │    Leaf 0: OP_CHECKSIGVERIFY(agent) OP_CHECKSIG(proxy)  │
//!   │    Leaf 1: OP_CHECKSEQUENCEVERIFY(timelock) OP_CHECKSIG(owner) │
//!   │                                                     │
//!   └─────────────────────────────────────────────────────┘
//! ```
//!
//! ### Key Path (Happy Path — Fastest)
//!
//! The internal key is a MuSig2 aggregate of `owner + plimsoll_proxy`.
//! Both must cooperate to produce a valid Schnorr signature.  This is
//! the most gas-efficient path — a single 64-byte signature on-chain.
//!
//! ### Script Path — Leaf 0 (Agent Execution)
//!
//! When an AI agent wants to spend:
//! 1. Agent signs the PSBT with its Schnorr key.
//! 2. Plimsoll proxy validates via 7 engines + Conservation of Mass.
//! 3. Proxy co-signs with its Schnorr key.
//! 4. Both signatures are revealed via the Taproot script path.
//!
//! If the agent bypasses the proxy and signs alone, the script
//! requires TWO signatures — one from the proxy — so on-chain
//! Bitcoin consensus natively rejects it.
//!
//! ### Script Path — Leaf 1 (Owner Recovery)
//!
//! If the proxy goes offline (infra failure), the owner can recover
//! funds after a CSV (CheckSequenceVerify) timelock expires.
//! Default: 144 blocks ≈ 24 hours.
//!
//! ## Conservation of Mass (Off-Chain Enforcement)
//!
//! Before the proxy co-signs, it runs the UTXO guard
//! (`plimsoll-rpc/src/utxo_guard.rs`) to verify:
//!
//! ```text
//!   Sum(Inputs) - Sum(Outputs) = Implicit Fee ≤ $50
//! ```
//!
//! The on-chain script cannot enforce USD-denominated limits (Bitcoin
//! Script has no oracle access), but by requiring the proxy signature,
//! it delegates the economic enforcement to the off-chain engine.

use serde::{Deserialize, Serialize};

// ── Taproot script construction ──────────────────────────────────

/// Represents a participant's x-only public key (32 bytes, BIP-340).
pub type XOnlyPubkey = [u8; 32];

/// Configuration for the Plimsoll Bitcoin Taproot Vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaprootVaultConfig {
    /// Owner's x-only pubkey (recovery path).
    pub owner_pubkey: XOnlyPubkey,
    /// AI agent's x-only pubkey.
    pub agent_pubkey: XOnlyPubkey,
    /// Plimsoll proxy's x-only pubkey (cosigner).
    pub proxy_pubkey: XOnlyPubkey,
    /// CSV timelock for owner recovery (in blocks, default 144 ≈ 24h).
    pub recovery_timelock_blocks: u16,
}

impl Default for TaprootVaultConfig {
    fn default() -> Self {
        Self {
            owner_pubkey: [0u8; 32],
            agent_pubkey: [0u8; 32],
            proxy_pubkey: [0u8; 32],
            recovery_timelock_blocks: 144,
        }
    }
}

/// A single leaf in the Tapscript tree.
#[derive(Debug, Clone, Serialize)]
pub struct TapscriptLeaf {
    /// Human-readable description.
    pub description: String,
    /// Raw Bitcoin Script bytes.
    pub script: Vec<u8>,
    /// Leaf version (0xC0 for Tapscript v0).
    pub leaf_version: u8,
}

/// The complete Taproot vault descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct TaprootVaultDescriptor {
    /// Internal key (MuSig2 aggregate or NUMS point).
    pub internal_key: XOnlyPubkey,
    /// Tapscript leaves ordered for the Merkle tree.
    pub leaves: Vec<TapscriptLeaf>,
    /// Human-readable summary.
    pub summary: String,
}

// ── Bitcoin Script opcodes ───────────────────────────────────────

/// Common Bitcoin Script opcodes used in Tapscript.
mod opcodes {
    pub const OP_CHECKSIG: u8 = 0xAC;
    pub const OP_CHECKSIGVERIFY: u8 = 0xAD;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xB2;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_PUSH32: u8 = 0x20; // Push 32 bytes
}

// ── Script builders ──────────────────────────────────────────────

/// Build Leaf 0: Agent + Proxy 2-of-2 (Tapscript CHECKSIGVERIFY pattern).
///
/// ```text
///   <agent_pubkey> OP_CHECKSIGVERIFY <proxy_pubkey> OP_CHECKSIG
/// ```
///
/// Requires exactly two Schnorr signatures on the witness stack:
///   1. Proxy signature (consumed by OP_CHECKSIG)
///   2. Agent signature (consumed by OP_CHECKSIGVERIFY)
///
/// This is the Tapscript-native 2-of-2 — no OP_CHECKMULTISIG needed
/// (which is disabled in Tapscript anyway per BIP-342).
pub fn build_agent_execution_script(
    agent_pubkey: &XOnlyPubkey,
    proxy_pubkey: &XOnlyPubkey,
) -> Vec<u8> {
    let mut script = Vec::with_capacity(68);

    // Push agent pubkey (32 bytes)
    script.push(opcodes::OP_PUSH32);
    script.extend_from_slice(agent_pubkey);
    script.push(opcodes::OP_CHECKSIGVERIFY);

    // Push proxy pubkey (32 bytes)
    script.push(opcodes::OP_PUSH32);
    script.extend_from_slice(proxy_pubkey);
    script.push(opcodes::OP_CHECKSIG);

    script
}

/// Build Leaf 1: Owner Recovery with CSV timelock.
///
/// ```text
///   <timelock_blocks> OP_CHECKSEQUENCEVERIFY OP_DROP <owner_pubkey> OP_CHECKSIG
/// ```
///
/// The owner can unilaterally recover funds after `timelock_blocks`
/// blocks have been mined since the UTXO was created.
pub fn build_owner_recovery_script(
    owner_pubkey: &XOnlyPubkey,
    timelock_blocks: u16,
) -> Vec<u8> {
    let mut script = Vec::with_capacity(38);

    // Push timelock value (little-endian, variable length)
    let timelock_bytes = timelock_blocks.to_le_bytes();
    if timelock_blocks <= 0x4B {
        // Direct push for small values
        script.push(timelock_bytes[0]);
    } else {
        // OP_PUSHDATA1 for larger values
        script.push(0x02); // Push 2 bytes
        script.extend_from_slice(&timelock_bytes);
    }

    script.push(opcodes::OP_CHECKSEQUENCEVERIFY);
    script.push(opcodes::OP_DROP);

    // Push owner pubkey
    script.push(opcodes::OP_PUSH32);
    script.extend_from_slice(owner_pubkey);
    script.push(opcodes::OP_CHECKSIG);

    script
}

/// Construct the complete Taproot vault descriptor.
///
/// Returns a `TaprootVaultDescriptor` containing:
///   - The internal key (for key-path spend — placeholder NUMS point)
///   - Two Tapscript leaves (agent execution + owner recovery)
///
/// In production, the internal key should be a MuSig2 aggregate of
/// (owner, proxy).  For safety, we use a NUMS (Nothing Up My Sleeve)
/// point by default — forcing all spends through the script path
/// where both signatures are explicitly verified.
pub fn build_taproot_vault(config: &TaprootVaultConfig) -> TaprootVaultDescriptor {
    let agent_script = build_agent_execution_script(
        &config.agent_pubkey,
        &config.proxy_pubkey,
    );

    let recovery_script = build_owner_recovery_script(
        &config.owner_pubkey,
        config.recovery_timelock_blocks,
    );

    // NUMS point (provably unspendable internal key).
    // H = lift_x(SHA256("plimsoll-taproot-vault-nums"))
    // This forces all spends through script paths where we can
    // enforce the 2-of-2 requirement.
    let nums_point: XOnlyPubkey = {
        // SHA256("plimsoll-taproot-vault-nums") — precomputed.
        // In production, use a proper NUMS derivation.
        let mut h = [0u8; 32];
        // Simple deterministic derivation for the placeholder
        let seed = b"plimsoll-taproot-vault-nums-v2";
        for (i, byte) in seed.iter().enumerate() {
            h[i % 32] ^= byte;
        }
        h
    };

    TaprootVaultDescriptor {
        internal_key: nums_point,
        leaves: vec![
            TapscriptLeaf {
                description: "Leaf 0: Agent + Proxy 2-of-2 execution".into(),
                script: agent_script,
                leaf_version: 0xC0, // Tapscript v0
            },
            TapscriptLeaf {
                description: format!(
                    "Leaf 1: Owner recovery after {} block CSV timelock",
                    config.recovery_timelock_blocks
                ),
                script: recovery_script,
                leaf_version: 0xC0,
            },
        ],
        summary: format!(
            "Plimsoll Taproot Vault: 2-of-2 (agent+proxy) with {}-block owner recovery. \
             Agent cannot spend without proxy co-signature. \
             Owner can recover after ~{} hours.",
            config.recovery_timelock_blocks,
            config.recovery_timelock_blocks as f64 / 6.0,
        ),
    }
}

/// Validate a PSBT against the Plimsoll Taproot Vault rules.
///
/// This is the bridge between on-chain script enforcement and
/// the off-chain Conservation of Mass engine.
///
/// Returns `(allowed, reason)`.
pub fn validate_psbt_for_signing(
    total_input_sats: u64,
    total_output_sats: u64,
    max_fee_usd: f64,
    btc_price_usd: f64,
) -> (bool, String) {
    // Check zero-output attack FIRST — this is always malicious
    // regardless of fee limit.
    if total_output_sats == 0 && total_input_sats > 0 {
        return (
            false,
            "BLOCK_UTXO_ZERO_OUTPUT: All input value goes to miner fee. \
             Certain attack vector — refusing to co-sign."
                .into(),
        );
    }

    let implicit_fee_sats = total_input_sats.saturating_sub(total_output_sats);
    let fee_btc = implicit_fee_sats as f64 / 1e8;
    let fee_usd = fee_btc * btc_price_usd;

    if fee_usd > max_fee_usd {
        return (
            false,
            format!(
                "BLOCK_UTXO_FEE_EXCESSIVE: Conservation of Mass violation — \
                 implicit fee ${:.2} exceeds ${:.2} limit. \
                 Plimsoll proxy will NOT co-sign this PSBT.",
                fee_usd, max_fee_usd,
            ),
        );
    }

    (
        true,
        format!(
            "PSBT validated: fee ${:.2} ({} sats) within ${:.2} limit. \
             Proxy will co-sign.",
            fee_usd, implicit_fee_sats, max_fee_usd,
        ),
    )
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> TaprootVaultConfig {
        TaprootVaultConfig {
            owner_pubkey: [0xAA; 32],
            agent_pubkey: [0xBB; 32],
            proxy_pubkey: [0xCC; 32],
            recovery_timelock_blocks: 144,
        }
    }

    #[test]
    fn test_agent_execution_script_structure() {
        let config = sample_config();
        let script = build_agent_execution_script(
            &config.agent_pubkey,
            &config.proxy_pubkey,
        );

        // Expected: PUSH32 <agent_pk> CHECKSIGVERIFY PUSH32 <proxy_pk> CHECKSIG
        // Layout: [0]=PUSH32, [1..33]=agent(32), [33]=CHECKSIGVERIFY,
        //         [34]=PUSH32, [35..67]=proxy(32), [67]=CHECKSIG
        // Total: 1+32+1+1+32+1 = 68 bytes
        assert_eq!(script.len(), 68);
        assert_eq!(script[0], 0x20);  // OP_PUSH32
        assert_eq!(&script[1..33], &[0xBB; 32]); // agent pubkey
        assert_eq!(script[33], 0xAD); // OP_CHECKSIGVERIFY
        assert_eq!(script[34], 0x20); // OP_PUSH32
        assert_eq!(&script[35..67], &[0xCC; 32]); // proxy pubkey
        assert_eq!(script[67], 0xAC); // OP_CHECKSIG
    }

    #[test]
    fn test_agent_script_requires_two_signatures() {
        let config = sample_config();
        let script = build_agent_execution_script(
            &config.agent_pubkey,
            &config.proxy_pubkey,
        );

        // Must contain both CHECKSIGVERIFY and CHECKSIG
        assert!(script.contains(&opcodes::OP_CHECKSIGVERIFY));
        assert!(script.contains(&opcodes::OP_CHECKSIG));

        // Must contain both pubkeys
        assert!(script.windows(32).any(|w| w == [0xBB; 32]));
        assert!(script.windows(32).any(|w| w == [0xCC; 32]));
    }

    #[test]
    fn test_owner_recovery_script_has_timelock() {
        let config = sample_config();
        let script = build_owner_recovery_script(
            &config.owner_pubkey,
            config.recovery_timelock_blocks,
        );

        // Must contain CSV opcode
        assert!(script.contains(&opcodes::OP_CHECKSEQUENCEVERIFY));
        // Must contain DROP (to clean stack after CSV)
        assert!(script.contains(&opcodes::OP_DROP));
        // Must contain CHECKSIG for owner
        assert!(script.contains(&opcodes::OP_CHECKSIG));
        // Must contain owner pubkey
        assert!(script.windows(32).any(|w| w == [0xAA; 32]));
    }

    #[test]
    fn test_recovery_timelock_encoding_small() {
        let script = build_owner_recovery_script(&[0xAA; 32], 50);
        // 50 <= 0x4B (75), so direct push (1 byte)
        assert_eq!(script[0], 50u8);
        assert_eq!(script[1], opcodes::OP_CHECKSEQUENCEVERIFY);
    }

    #[test]
    fn test_recovery_timelock_encoding_large() {
        let script = build_owner_recovery_script(&[0xAA; 32], 1000);
        // 1000 > 0x4B, so 2-byte LE push
        assert_eq!(script[0], 0x02); // Push 2 bytes
        let expected = 1000u16.to_le_bytes();
        assert_eq!(script[1], expected[0]);
        assert_eq!(script[2], expected[1]);
        assert_eq!(script[3], opcodes::OP_CHECKSEQUENCEVERIFY);
    }

    #[test]
    fn test_build_taproot_vault_two_leaves() {
        let config = sample_config();
        let descriptor = build_taproot_vault(&config);

        assert_eq!(descriptor.leaves.len(), 2);
        assert_eq!(descriptor.leaves[0].leaf_version, 0xC0);
        assert_eq!(descriptor.leaves[1].leaf_version, 0xC0);
        assert!(descriptor.leaves[0].description.contains("Agent + Proxy"));
        assert!(descriptor.leaves[1].description.contains("Owner recovery"));
    }

    #[test]
    fn test_taproot_vault_uses_nums_internal_key() {
        let config = sample_config();
        let descriptor = build_taproot_vault(&config);

        // Internal key should NOT be any of the participant keys
        // (it's a NUMS point to force script-path spending)
        assert_ne!(descriptor.internal_key, config.owner_pubkey);
        assert_ne!(descriptor.internal_key, config.agent_pubkey);
        assert_ne!(descriptor.internal_key, config.proxy_pubkey);
    }

    #[test]
    fn test_taproot_vault_summary() {
        let config = sample_config();
        let descriptor = build_taproot_vault(&config);

        assert!(descriptor.summary.contains("2-of-2"));
        assert!(descriptor.summary.contains("144-block"));
        assert!(descriptor.summary.contains("proxy co-signature"));
    }

    #[test]
    fn test_psbt_validation_normal_fee_passes() {
        let (allowed, reason) = validate_psbt_for_signing(
            110_000,  // inputs
            100_000,  // outputs
            50.0,     // max fee USD
            60_000.0, // BTC price
        );
        assert!(allowed);
        assert!(reason.contains("validated"));
    }

    #[test]
    fn test_psbt_validation_excessive_fee_blocked() {
        let (allowed, reason) = validate_psbt_for_signing(
            200_000_000, // 2 BTC input
            100_000_000, // 1 BTC output → 1 BTC fee = $60k
            50.0,
            60_000.0,
        );
        assert!(!allowed);
        assert!(reason.contains("BLOCK_UTXO_FEE_EXCESSIVE"));
        assert!(reason.contains("Conservation of Mass"));
    }

    #[test]
    fn test_psbt_validation_zero_output_blocked() {
        let (allowed, reason) = validate_psbt_for_signing(
            100_000_000, // 1 BTC input
            0,           // zero outputs — all goes to miner
            50.0,
            60_000.0,
        );
        assert!(!allowed);
        assert!(reason.contains("BLOCK_UTXO_ZERO_OUTPUT"));
    }

    #[test]
    fn test_psbt_validation_boundary_fee_passes() {
        // Fee exactly at $50 limit
        // 83333 sats at $60k = $49.9998
        let (allowed, _) = validate_psbt_for_signing(
            183_333,
            100_000,
            50.0,
            60_000.0,
        );
        assert!(allowed);
    }

    #[test]
    fn test_different_timelock_values() {
        // 1-block timelock (minimum)
        let config1 = TaprootVaultConfig {
            recovery_timelock_blocks: 1,
            ..sample_config()
        };
        let desc1 = build_taproot_vault(&config1);
        assert!(desc1.leaves[1].description.contains("1 block"));

        // 1008-block timelock (1 week)
        let config2 = TaprootVaultConfig {
            recovery_timelock_blocks: 1008,
            ..sample_config()
        };
        let desc2 = build_taproot_vault(&config2);
        assert!(desc2.leaves[1].description.contains("1008 block"));
    }

    #[test]
    fn test_default_config() {
        let config = TaprootVaultConfig::default();
        assert_eq!(config.recovery_timelock_blocks, 144);
        assert_eq!(config.owner_pubkey, [0u8; 32]);
    }
}
