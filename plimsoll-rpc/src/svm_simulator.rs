//! plimsoll-rpc/src/svm_simulator.rs — Solana Transaction Guard.
//!
//! Intercepts Solana `sendTransaction` (base64-encoded) JSON-RPC calls.
//! Decodes the payload, unrolls the AccountMeta array, and asserts that
//! **no un-whitelisted account has `is_writable: true`** — preventing
//! drain attacks where a malicious program writes to the agent's token
//! accounts.
//!
//! Phase 3.1 of the v2.0 roadmap.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ── Analysis result ──────────────────────────────────────────────

/// Result of analysing a Solana transaction against the whitelist.
#[derive(Debug, Clone, Serialize)]
pub struct SvmAnalysisResult {
    pub allowed: bool,
    pub reason: String,
    pub program_ids: Vec<String>,
    pub writable_accounts: Vec<String>,
    pub unauthorized_writable: Vec<String>,
}

// ── Lightweight Solana message structures ─────────────────────────
//
// We avoid pulling in the full `solana-sdk` (huge dep tree) by doing
// a minimal JSON-level parse.  The RPC `sendTransaction` payload is
// base64, but many agent frameworks also send the human-readable JSON
// representation.  We support both paths.

/// Compact instruction representation extracted from the message.
#[derive(Debug, Deserialize)]
pub struct ParsedInstruction {
    /// Index into `account_keys` for the program.
    pub program_id_index: usize,
    /// Indices into `account_keys` for the accounts.
    pub accounts: Vec<usize>,
}

/// Minimal Solana message (header + account keys + instructions).
#[derive(Debug, Deserialize)]
pub struct ParsedMessage {
    /// Number of required signatures (header byte 0).
    pub num_required_signatures: u8,
    /// Number of read-only signed accounts (header byte 1).
    pub num_readonly_signed_accounts: u8,
    /// Number of read-only unsigned accounts (header byte 2).
    pub num_readonly_unsigned_accounts: u8,
    /// Base-58 encoded account public keys.
    pub account_keys: Vec<String>,
    /// Instructions referencing account_keys by index.
    pub instructions: Vec<ParsedInstruction>,
}

impl ParsedMessage {
    /// Determine whether account at `index` is writable.
    ///
    /// In the Solana message format the first
    /// `num_required_signatures - num_readonly_signed_accounts` accounts
    /// are writable signers.  Then come read-only signers.  After all
    /// signers, the next block up to
    /// `total - num_readonly_unsigned_accounts` are writable non-signers.
    pub fn is_writable(&self, index: usize) -> bool {
        let total = self.account_keys.len();
        let num_sigs = self.num_required_signatures as usize;
        let num_ro_signed = self.num_readonly_signed_accounts as usize;
        let num_ro_unsigned = self.num_readonly_unsigned_accounts as usize;

        if index < num_sigs {
            // Signer — writable unless in the read-only-signed range.
            index < num_sigs.saturating_sub(num_ro_signed)
        } else {
            // Non-signer — writable unless in the trailing read-only block.
            index < total.saturating_sub(num_ro_unsigned)
        }
    }
}

// ── Core analysis ────────────────────────────────────────────────

/// Analyse a Solana transaction against the account whitelist.
///
/// # Arguments
/// * `message` — A parsed Solana message (JSON or deserialized).
/// * `whitelist` — Set of allowed writable account pubkeys.
///                  If empty, all accounts are allowed.
pub fn analyze_solana_message(
    message: &ParsedMessage,
    whitelist: &HashSet<String>,
) -> SvmAnalysisResult {
    let mut writable_accounts = Vec::new();
    let mut program_ids = Vec::new();
    let mut unauthorized = Vec::new();

    for instruction in &message.instructions {
        if instruction.program_id_index < message.account_keys.len() {
            let pid = &message.account_keys[instruction.program_id_index];
            if !program_ids.contains(pid) {
                program_ids.push(pid.clone());
            }
        }

        for &acct_idx in &instruction.accounts {
            if acct_idx >= message.account_keys.len() {
                continue;
            }
            let account = &message.account_keys[acct_idx];

            if message.is_writable(acct_idx) {
                if !writable_accounts.contains(account) {
                    writable_accounts.push(account.clone());
                }

                if !whitelist.is_empty() && !whitelist.contains(account) {
                    if !unauthorized.contains(account) {
                        unauthorized.push(account.clone());
                    }
                }
            }
        }
    }

    if !unauthorized.is_empty() {
        return SvmAnalysisResult {
            allowed: false,
            reason: format!(
                "BLOCK_SVM_UNAUTHORIZED_WRITABLE: {} account(s) have is_writable=true \
                 but are not whitelisted: [{}]",
                unauthorized.len(),
                unauthorized.join(", "),
            ),
            program_ids,
            writable_accounts,
            unauthorized_writable: unauthorized,
        };
    }

    SvmAnalysisResult {
        allowed: true,
        reason: "Solana transaction passed all checks".into(),
        program_ids,
        writable_accounts,
        unauthorized_writable: vec![],
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_message(keys: Vec<&str>, num_sigs: u8, ro_signed: u8, ro_unsigned: u8) -> ParsedMessage {
        let num_keys = keys.len();
        ParsedMessage {
            num_required_signatures: num_sigs,
            num_readonly_signed_accounts: ro_signed,
            num_readonly_unsigned_accounts: ro_unsigned,
            account_keys: keys.into_iter().map(String::from).collect(),
            instructions: vec![ParsedInstruction {
                program_id_index: num_keys - 1,
                accounts: (0..num_keys - 1).collect(),
            }],
        }
    }

    #[test]
    fn test_allow_whitelisted_writable() {
        // Keys: [signer(writable), account1(writable), program(readonly)]
        let msg = make_message(vec!["Signer1", "Account1", "Program1"], 1, 0, 1);

        let mut whitelist = HashSet::new();
        whitelist.insert("Signer1".to_string());
        whitelist.insert("Account1".to_string());

        let result = analyze_solana_message(&msg, &whitelist);
        assert!(result.allowed);
        assert!(result.unauthorized_writable.is_empty());
    }

    #[test]
    fn test_block_unauthorized_writable() {
        let msg = make_message(vec!["Signer1", "Attacker", "Program1"], 1, 0, 1);

        let mut whitelist = HashSet::new();
        whitelist.insert("Signer1".to_string());
        // "Attacker" is NOT in whitelist but is writable

        let result = analyze_solana_message(&msg, &whitelist);
        assert!(!result.allowed);
        assert!(result.unauthorized_writable.contains(&"Attacker".to_string()));
        assert!(result.reason.contains("BLOCK_SVM_UNAUTHORIZED_WRITABLE"));
    }

    #[test]
    fn test_empty_whitelist_allows_all() {
        let msg = make_message(vec!["Signer1", "AnyAccount", "Program1"], 1, 0, 1);

        let whitelist = HashSet::new(); // empty = allow all

        let result = analyze_solana_message(&msg, &whitelist);
        assert!(result.allowed);
    }

    #[test]
    fn test_writable_detection() {
        // 3 keys: [signer_rw, nonsigner_rw, nonsigner_ro]
        // num_sigs=1, ro_signed=0, ro_unsigned=1
        let msg = ParsedMessage {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 1,
            account_keys: vec![
                "WritableSigner".to_string(),
                "WritableNonSigner".to_string(),
                "ReadOnlyNonSigner".to_string(),
            ],
            instructions: vec![],
        };

        assert!(msg.is_writable(0));  // writable signer
        assert!(msg.is_writable(1));  // writable non-signer
        assert!(!msg.is_writable(2)); // read-only non-signer
    }

    #[test]
    fn test_program_ids_extracted() {
        let msg = ParsedMessage {
            num_required_signatures: 1,
            num_readonly_signed_accounts: 0,
            num_readonly_unsigned_accounts: 0,
            account_keys: vec![
                "Signer".to_string(),
                "SystemProgram".to_string(),
                "TokenProgram".to_string(),
            ],
            instructions: vec![
                ParsedInstruction { program_id_index: 1, accounts: vec![0] },
                ParsedInstruction { program_id_index: 2, accounts: vec![0] },
            ],
        };

        let result = analyze_solana_message(&msg, &HashSet::new());
        assert_eq!(result.program_ids.len(), 2);
        assert!(result.program_ids.contains(&"SystemProgram".to_string()));
        assert!(result.program_ids.contains(&"TokenProgram".to_string()));
    }
}
