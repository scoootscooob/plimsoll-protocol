//! Fee collection logic for the Aegis RPC Proxy.
//!
//! Every successful transaction routed through Aegis is charged
//! a 1-2 basis point fee. This is the revenue model for the protocol.

use tracing::info;

/// Calculate the fee amount for a given transaction value.
/// Fee is in basis points (1 bps = 0.01%).
pub fn calculate_fee(value_wei: u128, fee_bps: u16) -> u128 {
    if value_wei == 0 || fee_bps == 0 {
        return 0;
    }
    // fee = value * bps / 10000
    value_wei * (fee_bps as u128) / 10000
}

/// Build a fee transfer transaction to be bundled with the user's tx.
///
/// In production, this creates an additional tx in the Flashbots bundle
/// that sends the fee from the user's tx output to the fee collector.
///
/// # TODO (Production)
/// Integrate with Flashbots bundle builder to atomically collect fees.
pub fn build_fee_tx(
    fee_collector: &str,
    fee_amount: u128,
    _chain_id: u64,
) -> Option<serde_json::Value> {
    if fee_amount == 0 {
        return None;
    }

    info!(
        fee_collector = fee_collector,
        fee_amount = fee_amount,
        "Building fee collection tx"
    );

    // Stub: return the fee tx parameters
    Some(serde_json::json!({
        "to": fee_collector,
        "value": format!("0x{:x}", fee_amount),
        "gas": "0x5208",  // 21000
        "type": "fee_collection"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_calculation() {
        // 1 ETH at 2 bps = 0.0002 ETH
        let fee = calculate_fee(1_000_000_000_000_000_000, 2);
        assert_eq!(fee, 200_000_000_000_000); // 0.0002 ETH

        // 10 ETH at 1 bps
        let fee = calculate_fee(10_000_000_000_000_000_000, 1);
        assert_eq!(fee, 1_000_000_000_000_000); // 0.001 ETH
    }

    #[test]
    fn test_zero_fee() {
        assert_eq!(calculate_fee(0, 2), 0);
        assert_eq!(calculate_fee(1_000_000, 0), 0);
    }

    #[test]
    fn test_build_fee_tx() {
        let tx = build_fee_tx("0xFEE", 1000, 1);
        assert!(tx.is_some());

        let tx = build_fee_tx("0xFEE", 0, 1);
        assert!(tx.is_none());
    }
}
