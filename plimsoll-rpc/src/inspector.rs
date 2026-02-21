//! Patch 2 (v1.0.2): Schrödinger's State — Opcode-Level Non-Determinism Detector.
//!
//! Contracts that use environmental opcodes (BLOCKHASH, COINBASE, TIMESTAMP,
//! NUMBER, PREVRANDAO, GASLIMIT, BASEFEE, GAS) in conditional branches (JUMPI)
//! produce different execution paths at simulation time vs on-chain execution.
//!
//! This inspector implements a taint-tracking system that mirrors the EVM stack:
//! 1. When an ENV opcode pushes a value onto the stack, mark it as "tainted"
//! 2. When DUP/SWAP operations move values, propagate taint accordingly
//! 3. When arithmetic ops combine values, taint the result if any input is tainted
//! 4. When JUMPI reads its condition (stack[1]), check if it's tainted
//!    → if so, flag `non_deterministic_jumpi = true`
//!
//! This is designed for revm v17's Inspector trait using the builder pattern:
//! `Evm::builder().with_external_context(&mut inspector)
//!     .append_handler_register(inspector_handle_register)`

use tracing::warn;

/// Environmental opcodes that produce values dependent on execution context.
/// These values differ between simulation time and on-chain execution.
const ENV_OPCODES: &[u8] = &[
    0x40, // BLOCKHASH
    0x41, // COINBASE
    0x42, // TIMESTAMP
    0x43, // NUMBER
    0x44, // PREVRANDAO (was DIFFICULTY pre-merge)
    0x45, // GASLIMIT
    0x48, // BASEFEE
    0x5a, // GAS
];

/// Arithmetic/logic opcodes that propagate taint (if any input is tainted,
/// the output is tainted).
const TAINT_PROPAGATION_OPCODES: &[u8] = &[
    0x01, // ADD
    0x02, // MUL
    0x03, // SUB
    0x04, // DIV
    0x05, // SDIV
    0x06, // MOD
    0x07, // SMOD
    0x08, // ADDMOD
    0x09, // MULMOD
    0x0a, // EXP
    0x0b, // SIGNEXTEND
    0x10, // LT
    0x11, // GT
    0x12, // SLT
    0x13, // SGT
    0x14, // EQ
    0x15, // ISZERO
    0x16, // AND
    0x17, // OR
    0x18, // XOR
    0x19, // NOT
    0x1a, // BYTE
    0x1b, // SHL
    0x1c, // SHR
    0x1d, // SAR
];

/// Inspector state for tracking non-deterministic execution paths.
#[derive(Debug, Default)]
pub struct NonDeterminismInspector {
    /// Taint stack mirroring the EVM stack. `true` = value came from ENV opcode.
    taint_stack: Vec<bool>,

    /// Whether a non-deterministic JUMPI was detected.
    pub non_deterministic_jumpi: bool,

    /// Details about detected non-determinism for logging.
    pub detection_details: Vec<String>,

    /// Program counter of the offending JUMPI.
    pub jumpi_pc: Option<usize>,
}

impl NonDeterminismInspector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the inspector for a new transaction.
    pub fn reset(&mut self) {
        self.taint_stack.clear();
        self.non_deterministic_jumpi = false;
        self.detection_details.clear();
        self.jumpi_pc = None;
    }

    /// Process a single opcode step. Called by the revm Inspector trait.
    ///
    /// In production, this hooks into `Inspector::step()` which receives
    /// the current opcode and stack state from the EVM interpreter.
    pub fn process_opcode(&mut self, opcode: u8, stack_len: usize) {
        // Sync taint stack size with actual EVM stack
        while self.taint_stack.len() < stack_len {
            self.taint_stack.push(false);
        }
        while self.taint_stack.len() > stack_len {
            self.taint_stack.pop();
        }

        // ── ENV opcodes: mark TOS as tainted ─────────────────────
        if ENV_OPCODES.contains(&opcode) {
            // ENV opcodes push one value onto the stack
            self.taint_stack.push(true);
            let opname = opcode_name(opcode);
            self.detection_details.push(format!(
                "ENV opcode {} (0x{:02x}) pushed tainted value",
                opname, opcode
            ));
            return;
        }

        // ── JUMPI (0x57): check if condition is tainted ──────────
        if opcode == 0x57 {
            // JUMPI pops 2: stack[-2] = dest, stack[-1] = condition
            // The condition (stack[-1] = top of stack) determines the branch
            if self.taint_stack.len() >= 2 {
                let condition_tainted = self.taint_stack[self.taint_stack.len() - 1];
                if condition_tainted {
                    self.non_deterministic_jumpi = true;
                    self.jumpi_pc = Some(stack_len); // approximate PC
                    warn!(
                        "PATCH 2 (SCHRÖDINGER'S STATE): Non-deterministic JUMPI detected — \
                         branch condition depends on environmental opcode"
                    );
                }
            }
            // JUMPI pops 2 values
            if self.taint_stack.len() >= 2 {
                self.taint_stack.pop();
                self.taint_stack.pop();
            }
            return;
        }

        // ── DUP1-DUP16 (0x80-0x8f): duplicate and propagate taint ─
        if opcode >= 0x80 && opcode <= 0x8f {
            let n = (opcode - 0x80 + 1) as usize;
            if self.taint_stack.len() >= n {
                let taint = self.taint_stack[self.taint_stack.len() - n];
                self.taint_stack.push(taint);
            } else {
                self.taint_stack.push(false);
            }
            return;
        }

        // ── SWAP1-SWAP16 (0x90-0x9f): swap and propagate taint ──
        if opcode >= 0x90 && opcode <= 0x9f {
            let n = (opcode - 0x90 + 1) as usize;
            let len = self.taint_stack.len();
            if len > n {
                self.taint_stack.swap(len - 1, len - 1 - n);
            }
            return;
        }

        // ── Arithmetic/logic: taint output if any input tainted ──
        if TAINT_PROPAGATION_OPCODES.contains(&opcode) {
            let (inputs, outputs) = opcode_io(opcode);
            let mut any_tainted = false;

            // Check if any input is tainted
            for i in 0..inputs.min(self.taint_stack.len()) {
                if self.taint_stack[self.taint_stack.len() - 1 - i] {
                    any_tainted = true;
                    break;
                }
            }

            // Pop inputs
            for _ in 0..inputs.min(self.taint_stack.len()) {
                self.taint_stack.pop();
            }

            // Push outputs (tainted if any input was tainted)
            for _ in 0..outputs {
                self.taint_stack.push(any_tainted);
            }
            return;
        }

        // ── POP (0x50): remove top of stack ──────────────────────
        if opcode == 0x50 {
            self.taint_stack.pop();
            return;
        }

        // ── PUSH1-PUSH32 (0x60-0x7f): push clean value ──────────
        if opcode >= 0x60 && opcode <= 0x7f {
            self.taint_stack.push(false);
            return;
        }

        // ── JUMP (0x56): pop destination ─────────────────────────
        if opcode == 0x56 {
            self.taint_stack.pop();
            return;
        }

        // ── Memory/storage reads push clean values ───────────────
        // MLOAD(0x51), SLOAD(0x54), CALLDATALOAD(0x35)
        if opcode == 0x51 || opcode == 0x54 || opcode == 0x35 {
            // These pop 1 (address/offset) and push 1 (value)
            self.taint_stack.pop();
            self.taint_stack.push(false);
            return;
        }

        // ── Default: for unhandled opcodes, be conservative ──────
        // Most other opcodes either don't affect the stack or
        // have specific stack effects we handle above.
    }

    /// Check if the inspector detected any non-determinism.
    pub fn is_non_deterministic(&self) -> bool {
        self.non_deterministic_jumpi
    }
}

/// Get a human-readable name for an opcode.
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x48 => "BASEFEE",
        0x5a => "GAS",
        _ => "UNKNOWN",
    }
}

/// Get the number of (inputs, outputs) for an opcode.
fn opcode_io(opcode: u8) -> (usize, usize) {
    match opcode {
        // Unary: 1 in, 1 out
        0x15 | 0x19 => (1, 1), // ISZERO, NOT
        // Binary: 2 in, 1 out
        0x01..=0x07 | 0x0a | 0x0b | 0x10..=0x14 | 0x16..=0x18 | 0x1a..=0x1d => (2, 1),
        // Ternary: 3 in, 1 out
        0x08 | 0x09 => (3, 1), // ADDMOD, MULMOD
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_opcodes_list() {
        assert!(ENV_OPCODES.contains(&0x42)); // TIMESTAMP
        assert!(ENV_OPCODES.contains(&0x43)); // NUMBER
        assert!(ENV_OPCODES.contains(&0x44)); // PREVRANDAO
        assert!(ENV_OPCODES.contains(&0x5a)); // GAS
        assert!(!ENV_OPCODES.contains(&0x01)); // ADD is not ENV
    }

    #[test]
    fn test_clean_jumpi_no_flag() {
        let mut inspector = NonDeterminismInspector::new();
        // PUSH1 (clean value)
        inspector.process_opcode(0x60, 0);
        // PUSH1 (clean value)
        inspector.process_opcode(0x60, 1);
        // JUMPI — both values clean
        inspector.process_opcode(0x57, 2);
        assert!(!inspector.is_non_deterministic());
    }

    #[test]
    fn test_tainted_jumpi_flags() {
        let mut inspector = NonDeterminismInspector::new();
        // PUSH1 (clean destination)
        inspector.process_opcode(0x60, 0);
        // TIMESTAMP (tainted condition)
        inspector.process_opcode(0x42, 1);
        // JUMPI — condition is tainted!
        inspector.process_opcode(0x57, 2);
        assert!(inspector.is_non_deterministic());
    }

    #[test]
    fn test_taint_propagation_through_arithmetic() {
        let mut inspector = NonDeterminismInspector::new();
        // PUSH1 (clean)
        inspector.process_opcode(0x60, 0);
        // NUMBER (tainted)
        inspector.process_opcode(0x43, 1);
        // ADD: clean + tainted = tainted
        inspector.process_opcode(0x01, 2);
        // PUSH1 (clean destination)
        inspector.process_opcode(0x60, 1);
        // SWAP1 — swap dest and tainted result
        inspector.process_opcode(0x90, 2);
        // JUMPI — condition is the tainted ADD result
        inspector.process_opcode(0x57, 2);
        assert!(inspector.is_non_deterministic());
    }

    #[test]
    fn test_dup_propagates_taint() {
        let mut inspector = NonDeterminismInspector::new();
        // TIMESTAMP (tainted)
        inspector.process_opcode(0x42, 0);
        // DUP1
        inspector.process_opcode(0x80, 1);
        // Both values should be tainted
        assert_eq!(inspector.taint_stack.len(), 2);
        assert!(inspector.taint_stack[0]);
        assert!(inspector.taint_stack[1]);
    }

    #[test]
    fn test_reset_clears_state() {
        let mut inspector = NonDeterminismInspector::new();
        inspector.process_opcode(0x60, 0); // PUSH (clean destination)
        inspector.process_opcode(0x42, 1); // TIMESTAMP (tainted condition)
        inspector.process_opcode(0x57, 2); // JUMPI — condition is tainted!
        assert!(inspector.is_non_deterministic());

        inspector.reset();
        assert!(!inspector.is_non_deterministic());
        assert!(inspector.taint_stack.is_empty());
        assert!(inspector.detection_details.is_empty());
    }

    #[test]
    fn test_opcode_name() {
        assert_eq!(opcode_name(0x42), "TIMESTAMP");
        assert_eq!(opcode_name(0x43), "NUMBER");
        assert_eq!(opcode_name(0x44), "PREVRANDAO");
        assert_eq!(opcode_name(0x5a), "GAS");
    }
}
