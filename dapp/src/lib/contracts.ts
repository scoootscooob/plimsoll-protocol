/**
 * Aegis V5 Contract ABIs & Addresses
 *
 * These ABIs are generated from the Solidity contracts.
 * Update addresses after deployment.
 */

// ── AegisVault ABI ───────────────────────────────────────────

export const AEGIS_VAULT_ABI = [
  // Owner functions
  {
    name: "deposit",
    type: "function",
    inputs: [],
    outputs: [],
    stateMutability: "payable",
  },
  {
    name: "withdraw",
    type: "function",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "issueSessionKey",
    type: "function",
    inputs: [
      { name: "agent", type: "address" },
      { name: "durationSeconds", type: "uint256" },
      { name: "maxSingleAmount_", type: "uint256" },
      { name: "dailyBudget_", type: "uint256" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "revokeSessionKey",
    type: "function",
    inputs: [{ name: "agent", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "setModules",
    type: "function",
    inputs: [
      { name: "velocity_", type: "address" },
      { name: "whitelist_", type: "address" },
      { name: "drawdown_", type: "address" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "emergencyLockVault",
    type: "function",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "emergencyUnlock",
    type: "function",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "transferOwnership",
    type: "function",
    inputs: [{ name: "newOwner", type: "address" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    name: "acceptOwnership",
    type: "function",
    inputs: [],
    outputs: [],
    stateMutability: "nonpayable",
  },
  // Agent execution
  {
    name: "execute",
    type: "function",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes" }],
    stateMutability: "nonpayable",
  },
  // View functions
  {
    name: "owner",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    name: "vaultBalance",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    name: "initialBalance",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    name: "emergencyLocked",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    name: "isSessionActive",
    type: "function",
    inputs: [{ name: "agent", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    name: "getSessionKey",
    type: "function",
    inputs: [{ name: "agent", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "active", type: "bool" },
          { name: "expiresAt", type: "uint256" },
          { name: "maxSingleAmount", type: "uint256" },
          { name: "dailyBudget", type: "uint256" },
          { name: "spentToday", type: "uint256" },
          { name: "dayStart", type: "uint256" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    name: "velocityModule",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    name: "whitelistModule",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  {
    name: "drawdownModule",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
    stateMutability: "view",
  },
  // Events
  {
    name: "Deposited",
    type: "event",
    inputs: [
      { name: "from", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "Withdrawn",
    type: "event",
    inputs: [
      { name: "to", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    name: "SessionKeyIssued",
    type: "event",
    inputs: [
      { name: "agent", type: "address", indexed: true },
      { name: "expiresAt", type: "uint256", indexed: false },
      { name: "dailyBudget", type: "uint256", indexed: false },
    ],
  },
  {
    name: "SessionKeyRevoked",
    type: "event",
    inputs: [
      { name: "agent", type: "address", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "ExecutionApproved",
    type: "event",
    inputs: [
      { name: "agent", type: "address", indexed: true },
      { name: "target", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    name: "ExecutionBlocked",
    type: "event",
    inputs: [
      { name: "agent", type: "address", indexed: true },
      { name: "target", type: "address", indexed: true },
      { name: "reason", type: "string", indexed: false },
    ],
  },
  {
    name: "EmergencyLock",
    type: "event",
    inputs: [
      { name: "triggeredBy", type: "address", indexed: true },
    ],
  },
] as const;

// ── AegisAttestation ABI ─────────────────────────────────────

export const AEGIS_ATTESTATION_ABI = [
  {
    name: "isAttested",
    type: "function",
    inputs: [{ name: "vault", type: "address" }],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "view",
  },
  {
    name: "getMaxDrawdown",
    type: "function",
    inputs: [{ name: "vault", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    name: "getAttestation",
    type: "function",
    inputs: [{ name: "vault", type: "address" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "vault", type: "address" },
          { name: "owner", type: "address" },
          { name: "maxDrawdownBps", type: "uint256" },
          { name: "maxDailySpendWei", type: "uint256" },
          { name: "whitelistedTargets", type: "uint256" },
          { name: "velocityModuleActive", type: "bool" },
          { name: "drawdownModuleActive", type: "bool" },
          { name: "whitelistModuleActive", type: "bool" },
          { name: "createdAt", type: "uint256" },
          { name: "updatedAt", type: "uint256" },
          { name: "valid", type: "bool" },
        ],
      },
    ],
    stateMutability: "view",
  },
  {
    name: "attestedCount",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
] as const;

// ── Contract Addresses (update after deployment) ─────────────

export const CONTRACTS = {
  sepolia: {
    vault: "0x0000000000000000000000000000000000000000" as `0x${string}`,
    velocityModule: "0x0000000000000000000000000000000000000000" as `0x${string}`,
    whitelistModule: "0x0000000000000000000000000000000000000000" as `0x${string}`,
    drawdownModule: "0x0000000000000000000000000000000000000000" as `0x${string}`,
    attestation: "0x0000000000000000000000000000000000000000" as `0x${string}`,
  },
} as const;
