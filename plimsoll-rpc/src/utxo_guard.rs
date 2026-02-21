//! plimsoll-rpc/src/utxo_guard.rs — Bitcoin PSBT Guard.
//!
//! Intercepts agent PSBTs (Partially Signed Bitcoin Transactions).
//! Implements the **Conservation of Mass** algorithm:
//!
//! ```text
//!   Sum(Inputs) - Sum(Outputs) = Implicit Miner Fee
//! ```
//!
//! If the implicit miner fee delta exceeds `max_fee_usd`, the hardware
//! enclave violently refuses to sign — preventing the PSBT fee-drain
//! attack where a malicious PSBT sends most of the input value to the
//! miner as fee.
//!
//! Phase 3.2 of the v2.0 roadmap.

use serde::{Deserialize, Serialize};

// ── Analysis result ──────────────────────────────────────────────

/// Result of PSBT Conservation-of-Mass analysis.
#[derive(Debug, Clone, Serialize)]
pub struct UtxoAnalysisResult {
    pub allowed: bool,
    pub reason: String,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub implicit_fee_sats: u64,
    pub fee_usd: f64,
}

// ── PSBT summary (pre-parsed by the caller) ──────────────────────

/// Pre-parsed PSBT summary for analysis.
///
/// The actual BIP-174 binary parsing is handled upstream (by the agent
/// framework or a dedicated Bitcoin library).  This struct captures
/// the economics that Plimsoll needs to enforce.
#[derive(Debug, Clone, Deserialize)]
pub struct PsbtSummary {
    /// Sum of all input UTXO values in satoshis.
    pub total_input_sats: u64,
    /// Sum of all output values in satoshis.
    pub total_output_sats: u64,
    /// Number of inputs.
    #[serde(default)]
    pub num_inputs: usize,
    /// Number of outputs.
    #[serde(default)]
    pub num_outputs: usize,
    /// Primary recipient address (for logging).
    #[serde(default)]
    pub primary_recipient: String,
}

// ── Core analysis ────────────────────────────────────────────────

/// Check Conservation of Mass on a PSBT.
///
/// `Sum(Inputs) - Sum(Outputs) = Implicit Miner Fee`
///
/// If the fee exceeds `max_fee_usd`, the PSBT is rejected.
///
/// # Arguments
/// * `summary`      — Pre-parsed PSBT economic summary.
/// * `btc_price_usd` — Current BTC/USD price for fee conversion.
/// * `max_fee_usd`  — Maximum acceptable implicit fee in USD.
pub fn analyze_psbt(
    summary: &PsbtSummary,
    btc_price_usd: f64,
    max_fee_usd: f64,
) -> UtxoAnalysisResult {
    let implicit_fee_sats = summary.total_input_sats.saturating_sub(summary.total_output_sats);
    let fee_btc = implicit_fee_sats as f64 / 1e8;
    let fee_usd = fee_btc * btc_price_usd;

    if fee_usd > max_fee_usd {
        return UtxoAnalysisResult {
            allowed: false,
            reason: format!(
                "BLOCK_UTXO_FEE_EXCESSIVE: Conservation of Mass violation — \
                 implicit miner fee ${:.2} ({} sats / {:.8} BTC) exceeds \
                 maximum ${:.2}. Inputs={} sats, Outputs={} sats. \
                 Potential PSBT fee-drain attack.",
                fee_usd,
                implicit_fee_sats,
                fee_btc,
                max_fee_usd,
                summary.total_input_sats,
                summary.total_output_sats,
            ),
            total_input_sats: summary.total_input_sats,
            total_output_sats: summary.total_output_sats,
            implicit_fee_sats,
            fee_usd,
        };
    }

    UtxoAnalysisResult {
        allowed: true,
        reason: format!(
            "PSBT fee ${:.2} ({} sats) within ${:.2} limit",
            fee_usd, implicit_fee_sats, max_fee_usd,
        ),
        total_input_sats: summary.total_input_sats,
        total_output_sats: summary.total_output_sats,
        implicit_fee_sats,
        fee_usd,
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_summary(input: u64, output: u64) -> PsbtSummary {
        PsbtSummary {
            total_input_sats: input,
            total_output_sats: output,
            num_inputs: 1,
            num_outputs: 1,
            primary_recipient: "bc1qtest...".into(),
        }
    }

    #[test]
    fn test_normal_fee_allowed() {
        // 10,000 sat fee at $60k BTC = $6.00
        let s = make_summary(110_000, 100_000);
        let r = analyze_psbt(&s, 60_000.0, 50.0);
        assert!(r.allowed);
        assert_eq!(r.implicit_fee_sats, 10_000);
        assert!((r.fee_usd - 6.0).abs() < 0.01);
    }

    #[test]
    fn test_excessive_fee_blocked() {
        // 1 BTC fee at $60k = $60,000 — way over $50 limit
        let s = make_summary(200_000_000, 100_000_000); // 1 BTC fee
        let r = analyze_psbt(&s, 60_000.0, 50.0);
        assert!(!r.allowed);
        assert!(r.reason.contains("BLOCK_UTXO_FEE_EXCESSIVE"));
        assert!(r.reason.contains("Conservation of Mass"));
    }

    #[test]
    fn test_zero_fee_allowed() {
        let s = make_summary(100_000, 100_000);
        let r = analyze_psbt(&s, 60_000.0, 50.0);
        assert!(r.allowed);
        assert_eq!(r.implicit_fee_sats, 0);
        assert_eq!(r.fee_usd, 0.0);
    }

    #[test]
    fn test_conservation_of_mass_math() {
        // Inputs: 5 BTC, Outputs: 0.01 BTC → 4.99 BTC implicit fee
        // At $60k that's $299,400 — clearly an attack
        let s = make_summary(500_000_000, 1_000_000);
        let r = analyze_psbt(&s, 60_000.0, 50.0);
        assert!(!r.allowed);
        assert_eq!(r.implicit_fee_sats, 499_000_000);
    }

    #[test]
    fn test_boundary_fee_exactly_at_limit() {
        // Fee exactly at $50.00 → should be allowed (not strictly greater)
        // Need: fee_sats * (btc_price / 1e8) = 50.0
        // At $60k: fee_sats = 50 * 1e8 / 60000 = 83333
        let s = make_summary(183_333, 100_000);
        let r = analyze_psbt(&s, 60_000.0, 50.0);
        // 83333 sats at $60k = $49.9998 < $50 → allowed
        assert!(r.allowed);
    }
}
