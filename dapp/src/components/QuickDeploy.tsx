"use client";

import { useState, useEffect } from "react";
import { type Address } from "viem";
import { useCreateVault, useAcceptOwnership, useFactoryAddress } from "@/hooks/useFactory";

// ── Risk Presets ────────────────────────────────────────────

const PRESETS = {
  conservative: {
    label: "Conservative",
    description: "Low limits, tight controls. Best for testing or small budgets.",
    maxPerHourEth: "1",
    maxSingleTxEth: "0.5",
    maxDrawdownBps: 300,
    specs: ["1 ETH/hr velocity", "0.5 ETH max per tx", "3% drawdown floor"],
  },
  balanced: {
    label: "Balanced",
    description: "Moderate limits for production agents with reasonable budgets.",
    maxPerHourEth: "5",
    maxSingleTxEth: "2",
    maxDrawdownBps: 500,
    specs: ["5 ETH/hr velocity", "2 ETH max per tx", "5% drawdown floor"],
  },
  aggressive: {
    label: "Aggressive",
    description: "Higher limits for high-frequency trading agents.",
    maxPerHourEth: "20",
    maxSingleTxEth: "10",
    maxDrawdownBps: 1000,
    specs: ["20 ETH/hr velocity", "10 ETH max per tx", "10% drawdown floor"],
  },
} as const;

type PresetKey = keyof typeof PRESETS;

interface Props {
  onComplete: (vaultAddress: Address) => void;
}

export function QuickDeploy({ onComplete }: Props) {
  const [preset, setPreset] = useState<PresetKey>("balanced");
  const [depositAmount, setDepositAmount] = useState("");
  const [copied, setCopied] = useState(false);

  const { chainKey } = useFactoryAddress();
  const createVault = useCreateVault();
  const acceptOwnership = useAcceptOwnership();

  const deployedVault = createVault.vaultAddress;
  const chainLabel = chainKey === "base" ? "Base" : chainKey === "sepolia" ? "Sepolia" : chainKey;

  // Build the RPC URL for the deployed vault
  const rpcUrl = deployedVault
    ? `https://rpc.plimsoll.network/v1/${deployedVault}`
    : null;

  // Auto-complete after ownership accepted
  useEffect(() => {
    if (acceptOwnership.isSuccess && deployedVault) {
      // Small delay so user sees the success state
      const timer = setTimeout(() => {}, 500);
      return () => clearTimeout(timer);
    }
  }, [acceptOwnership.isSuccess, deployedVault]);

  const handleDeploy = () => {
    const p = PRESETS[preset];
    createVault.createVault(
      p.maxPerHourEth,
      p.maxSingleTxEth,
      p.maxDrawdownBps,
      depositAmount || undefined
    );
  };

  const handleAccept = () => {
    if (deployedVault) {
      acceptOwnership.accept(deployedVault);
    }
  };

  const handleCopyRpc = () => {
    if (rpcUrl) {
      navigator.clipboard.writeText(rpcUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // ── Step 3: Vault Live — Show RPC URL ─────────────────────
  if (acceptOwnership.isSuccess && deployedVault) {
    return (
      <div className="max-w-2xl mx-auto space-y-8">
        <div className="text-center">
          <h2 className="font-serif text-4xl mb-3 text-ink">
            Your vault is live.
          </h2>
          <p className="font-mono text-sm text-ink/60 max-w-lg mx-auto leading-relaxed">
            Replace your agent&apos;s RPC URL with the one below. Every transaction
            will pass through Plimsoll&apos;s 7-engine firewall. That&apos;s it.
          </p>
        </div>

        {/* Vault Address */}
        <div className="card">
          <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase block mb-2">
            [ Vault_Address ]
          </span>
          <span className="font-mono text-sm text-ink break-all select-all block">
            {deployedVault}
          </span>
        </div>

        {/* RPC URL — the main payoff */}
        <div className="border-2 border-ink p-6 bg-paper">
          <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase block mb-3">
            [ Protected_RPC ]
          </span>
          <div className="bg-surface border border-ink/20 p-4 mb-4">
            <code className="font-mono text-sm text-ink break-all select-all block">
              {rpcUrl}
            </code>
          </div>
          <button
            className="btn-primary w-full"
            onClick={handleCopyRpc}
          >
            {copied ? "Copied" : "Copy RPC URL"}
          </button>
          <p className="font-mono text-[10px] text-ink/40 mt-3 leading-relaxed">
            Point your agent&apos;s RPC endpoint here instead of Alchemy/Infura.
            All eth_sendTransaction calls are intercepted, simulated, and evaluated
            by 7 deterministic engines before reaching the chain.
          </p>
        </div>

        {/* Go to Dashboard */}
        <button
          className="btn-secondary w-full"
          onClick={() => onComplete(deployedVault)}
        >
          Open Vault Dashboard
        </button>
      </div>
    );
  }

  // ── Step 2: Accept Ownership ──────────────────────────────
  if (createVault.isSuccess && deployedVault) {
    return (
      <div className="max-w-2xl mx-auto space-y-6">
        <div className="text-center">
          <h2 className="font-serif text-3xl mb-3 text-ink">
            Vault Deployed
          </h2>
          <p className="font-mono text-sm text-ink/60 max-w-md mx-auto leading-relaxed">
            Accept ownership to finalize. This is a security step that ensures
            only you control the vault.
          </p>
        </div>

        <div className="card">
          <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase block mb-2">
            [ Vault_Address ]
          </span>
          <span className="font-mono text-sm text-ink break-all select-all block">
            {deployedVault}
          </span>
        </div>

        <button
          className="btn-primary w-full text-lg py-3"
          disabled={acceptOwnership.isPending || acceptOwnership.isConfirming}
          onClick={handleAccept}
        >
          {acceptOwnership.isPending
            ? "Signing..."
            : acceptOwnership.isConfirming
              ? "Confirming..."
              : "Accept Ownership"}
        </button>

        {acceptOwnership.error && (
          <div className="border border-terracotta/30 bg-terracotta/5 p-4">
            <p className="font-mono text-sm text-terracotta">
              {(acceptOwnership.error as Error).message?.includes("User rejected")
                ? "Transaction was rejected in your wallet."
                : (acceptOwnership.error as Error).message?.slice(0, 200)}
            </p>
          </div>
        )}
      </div>
    );
  }

  // ── Step 1: Configure + Deploy ────────────────────────────
  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div className="text-center">
        <h2 className="font-serif text-4xl mb-3 text-ink">
          Protect Your Wallet
        </h2>
        <p className="font-mono text-sm text-ink/60 max-w-lg mx-auto leading-relaxed">
          Create a Plimsoll vault on {chainLabel}. Your agent uses a protected RPC
          endpoint. Every transaction passes through 7 deterministic engines.
          No code changes required.
        </p>
      </div>

      {/* Preset Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-0 border-t border-l border-ink/20">
        {(Object.entries(PRESETS) as [PresetKey, typeof PRESETS[PresetKey]][]).map(
          ([key, p], i) => (
            <button
              key={key}
              className={`border-r border-b border-ink/20 p-6 text-left transition-colors duration-150 ${
                preset === key
                  ? "bg-ink text-paper"
                  : "bg-paper text-ink hover:bg-surface"
              }`}
              onClick={() => setPreset(key)}
            >
              <span
                className={`font-mono text-[10px] tracking-widest uppercase block mb-3 ${
                  preset === key ? "text-terracotta" : "text-terracotta"
                }`}
              >
                [ Preset_{String(i + 1).padStart(2, "0")} ]
              </span>
              <h3
                className={`font-serif text-lg mb-2 ${
                  preset === key ? "text-paper" : "text-ink"
                }`}
              >
                {p.label}
              </h3>
              <p
                className={`font-mono text-xs mb-3 leading-relaxed ${
                  preset === key ? "text-paper/70" : "text-ink/60"
                }`}
              >
                {p.description}
              </p>
              <ul className="space-y-1">
                {p.specs.map((spec) => (
                  <li
                    key={spec}
                    className={`font-mono text-[10px] tracking-wide ${
                      preset === key ? "text-paper/50" : "text-ink/40"
                    }`}
                  >
                    {spec}
                  </li>
                ))}
              </ul>
            </button>
          )
        )}
      </div>

      {/* Optional Deposit */}
      <div className="card">
        <label className="label-text">Initial Deposit (ETH, Optional)</label>
        <input
          className="input-field text-sm"
          type="number"
          value={depositAmount}
          onChange={(e) => setDepositAmount(e.target.value)}
          placeholder="0.0"
          step="0.01"
          min="0"
        />
        <span className="font-mono text-[10px] text-ink/40 mt-2 block">
          You can deposit more later from the dashboard.
        </span>
      </div>

      {/* Deploy Button */}
      <button
        className="btn-primary w-full text-lg py-3"
        disabled={createVault.isPending || createVault.isConfirming}
        onClick={handleDeploy}
      >
        {createVault.isPending
          ? "Signing..."
          : createVault.isConfirming
            ? "Deploying Vault..."
            : "Create Vault"}
      </button>

      {createVault.error && (
        <div className="border border-terracotta/30 bg-terracotta/5 p-4 space-y-2">
          <p className="font-mono text-sm text-terracotta">
            {(createVault.error as Error).message?.includes("Signing request not found")
              ? "Wallet session expired. Please disconnect and reconnect your wallet, then try again."
              : (createVault.error as Error).message?.includes("User rejected")
                ? "Transaction was rejected in your wallet."
                : (createVault.error as Error).message?.slice(0, 200)}
          </p>
          <button
            className="font-mono text-xs text-terracotta underline"
            onClick={handleDeploy}
          >
            Retry
          </button>
        </div>
      )}
    </div>
  );
}
