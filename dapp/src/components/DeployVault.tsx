"use client";

import { useState, useEffect } from "react";
import { type Address } from "viem";
import { useCreateVault, useAcceptOwnership, useFactoryAddress } from "@/hooks/useFactory";

interface Props {
  onVaultCreated?: (vaultAddress: Address) => void;
}

export function DeployVault({ onVaultCreated }: Props) {
  const [maxPerHour, setMaxPerHour] = useState("10");
  const [maxSingleTx, setMaxSingleTx] = useState("5");
  const [maxDrawdownBps, setMaxDrawdownBps] = useState("500");
  const [initialDeposit, setInitialDeposit] = useState("");
  const [isExpanded, setIsExpanded] = useState(false);

  const { isFactoryDeployed, chainKey } = useFactoryAddress();
  const createVault = useCreateVault();
  const acceptOwnership = useAcceptOwnership();

  // Auto-set the deployed vault address from tx receipt
  const deployedVault = createVault.vaultAddress;

  // Once accept ownership succeeds, auto-load the vault
  useEffect(() => {
    if (acceptOwnership.isSuccess && deployedVault && onVaultCreated) {
      onVaultCreated(deployedVault);
    }
  }, [acceptOwnership.isSuccess, deployedVault, onVaultCreated]);

  const handleDeploy = () => {
    createVault.createVault(
      maxPerHour,
      maxSingleTx,
      parseInt(maxDrawdownBps),
      initialDeposit || undefined
    );
  };

  const handleAccept = () => {
    if (deployedVault) {
      acceptOwnership.accept(deployedVault);
    }
  };

  const chainLabel = chainKey === "base" ? "Base" : chainKey === "sepolia" ? "Sepolia" : chainKey;

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-mono text-xs text-ink/60 tracking-widest uppercase">
          Deploy New Vault
        </h3>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[10px] text-ink/40 tracking-widest uppercase">
            {chainLabel}
          </span>
          <button
            className="btn-secondary text-xs"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "Collapse" : "Expand"}
          </button>
        </div>
      </div>

      {isExpanded && !isFactoryDeployed && (
        <div className="border-t border-ink/20 pt-4">
          <p className="font-mono text-sm text-ink/60">
            Factory contract not yet deployed to {chainLabel}. Switch your wallet
            to a supported chain, or deploy via:
          </p>
          <pre className="font-mono text-xs text-ink/40 mt-2 p-3 bg-surface overflow-x-auto">
{`cd contracts
forge script script/DeployFactory.s.sol \\
  --rpc-url $${chainKey.toUpperCase()}_RPC --broadcast`}
          </pre>
          <p className="font-mono text-xs text-ink/40 mt-2">
            Then update the factory address in <code>contracts.ts</code>.
          </p>
        </div>
      )}

      {isExpanded && isFactoryDeployed && (
        <div className="space-y-4 border-t border-ink/20 pt-4">
          <h4 className="font-mono text-xs text-terracotta tracking-widest uppercase">
            [ Module_Params ]
          </h4>

          <div>
            <label className="label-text">Max Spend Per Hour (ETH)</label>
            <input
              className="input-field text-sm"
              type="number"
              value={maxPerHour}
              onChange={(e) => setMaxPerHour(e.target.value)}
              step="0.1"
              min="0"
            />
          </div>

          <div>
            <label className="label-text">Max Single Transaction (ETH)</label>
            <input
              className="input-field text-sm"
              type="number"
              value={maxSingleTx}
              onChange={(e) => setMaxSingleTx(e.target.value)}
              step="0.1"
              min="0"
            />
          </div>

          <div>
            <label className="label-text">Max Drawdown (Basis Points)</label>
            <input
              className="input-field text-sm"
              type="number"
              value={maxDrawdownBps}
              onChange={(e) => setMaxDrawdownBps(e.target.value)}
              min="0"
              max="10000"
            />
            <span className="font-mono text-[10px] text-ink/40 mt-1 block">
              500 = 5%, 1000 = 10%, 5000 = 50%
            </span>
          </div>

          <div>
            <label className="label-text">Initial Deposit (ETH, Optional)</label>
            <input
              className="input-field text-sm"
              type="number"
              value={initialDeposit}
              onChange={(e) => setInitialDeposit(e.target.value)}
              placeholder="0.0"
              step="0.01"
              min="0"
            />
          </div>

          <button
            className="btn-primary w-full"
            disabled={createVault.isPending || createVault.isConfirming}
            onClick={handleDeploy}
          >
            {createVault.isPending
              ? "Signing..."
              : createVault.isConfirming
                ? "Deploying..."
                : `Deploy Vault on ${chainLabel}`}
          </button>

          {/* Vault deployed — show address and accept ownership */}
          {createVault.isSuccess && deployedVault && !acceptOwnership.isSuccess && (
            <div className="border border-ink/20 p-4 space-y-3">
              <p className="font-mono text-sm text-ink/80">
                Vault deployed successfully!
              </p>
              <div className="bg-surface p-3 border border-ink/10">
                <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase block mb-1">
                  Vault Address
                </span>
                <span className="font-mono text-sm text-ink break-all select-all">
                  {deployedVault}
                </span>
              </div>
              <p className="font-mono text-xs text-ink/50">
                Accept ownership to finalize your vault. This is a security step
                that ensures only you control it.
              </p>
              <button
                className="btn-primary w-full"
                disabled={acceptOwnership.isPending || acceptOwnership.isConfirming}
                onClick={handleAccept}
              >
                {acceptOwnership.isPending
                  ? "Signing..."
                  : acceptOwnership.isConfirming
                    ? "Confirming..."
                    : "Accept Ownership"}
              </button>
            </div>
          )}

          {/* Fallback: tx succeeded but couldn't parse vault address */}
          {createVault.isSuccess && !deployedVault && !acceptOwnership.isSuccess && (
            <div className="border border-ink/20 p-4 space-y-3">
              <p className="font-mono text-sm text-ink/60">
                Vault deployed. Check the transaction on{" "}
                <a
                  href={
                    chainKey === "base"
                      ? `https://basescan.org/tx/${createVault.hash}`
                      : `https://sepolia.etherscan.io/tx/${createVault.hash}`
                  }
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-terracotta underline"
                >
                  {chainKey === "base" ? "Basescan" : "Etherscan"}
                </a>{" "}
                for your vault address.
              </p>
            </div>
          )}

          {/* Ownership accepted */}
          {acceptOwnership.isSuccess && deployedVault && (
            <div className="border border-ink/20 p-4">
              <p className="font-mono text-sm text-ink/80 mb-3">
                Vault is ready. You are the owner.
              </p>
              <div className="bg-surface p-3 border border-ink/10 mb-3">
                <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase block mb-1">
                  Your Vault
                </span>
                <span className="font-mono text-sm text-ink break-all select-all">
                  {deployedVault}
                </span>
              </div>
              <button
                className="btn-secondary w-full"
                onClick={() => {
                  if (deployedVault && onVaultCreated) {
                    onVaultCreated(deployedVault);
                  }
                }}
              >
                Load Vault Dashboard
              </button>
            </div>
          )}

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

          {acceptOwnership.error && (
            <div className="border border-terracotta/30 bg-terracotta/5 p-4 space-y-2">
              <p className="font-mono text-sm text-terracotta">
                {(acceptOwnership.error as Error).message?.includes("Signing request not found")
                  ? "Wallet session expired. Please disconnect and reconnect your wallet, then try again."
                  : (acceptOwnership.error as Error).message?.includes("User rejected")
                    ? "Transaction was rejected in your wallet."
                    : (acceptOwnership.error as Error).message?.slice(0, 200)}
              </p>
              <button
                className="font-mono text-xs text-terracotta underline"
                onClick={handleAccept}
              >
                Retry
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
