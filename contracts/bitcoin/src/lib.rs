//! Plimsoll Bitcoin Contracts — Taproot Vault and PSBT enforcement.
//!
//! This crate provides:
//! - `taproot_vault`: P2TR 2-of-2 multisig with CSV owner recovery
//! - PSBT validation bridge to the Conservation of Mass engine

pub mod taproot_vault;
