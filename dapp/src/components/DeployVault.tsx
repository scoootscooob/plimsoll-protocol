"use client";

import { useState } from "react";
import { type Address } from "viem";
import { useCreateVault, useAcceptOwnership, isFactoryDeployed } from "@/hooks/useFactory";

interface Props {
  onVaultCreated?: (vaultAddress: Address) => void;
}

export function DeployVault({ onVaultCreated }: Props) {
  const [maxPerHour, setMaxPerHour] = useState("10");
  const [maxSingleTx, setMaxSingleTx] = useState("5");
  const [maxDrawdownBps, setMaxDrawdownBps] = useState("500");
  const [initialDeposit, setInitialDeposit] = useState("");
  const [isExpanded, setIsExpanded] = useState(false);
  const [deployedVault, setDeployedVault] = useState<Address | null>(null);

  const createVault = useCreateVault();
  const acceptOwnership = useAcceptOwnership();

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

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-mono text-xs text-ink/60 tracking-widest uppercase">
          Deploy New Vault
        </h3>
        <button
          className="btn-secondary text-xs"
          onClick={() => setIsExpanded(!isExpanded)}
        >
          {isExpanded ? "Collapse" : "Expand"}
        </button>
      </div>

      {isExpanded && !isFactoryDeployed && (
        <div className="border-t border-ink/20 pt-4">
          <p className="font-mono text-sm text-ink/60">
            Factory contract not yet deployed to Sepolia. Deploy via:
          </p>
          <pre className="font-mono text-xs text-ink/40 mt-2 p-3 bg-surface overflow-x-auto">
{`cd contracts
forge script script/DeployFactory.s.sol \\
  --rpc-url $SEPOLIA_RPC --broadcast`}
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
                : "Deploy Vault"}
          </button>

          {createVault.isSuccess && !acceptOwnership.isSuccess && (
            <div className="border border-ink/20 p-4 space-y-3">
              <p className="font-mono text-sm text-ink/60">
                Vault deployed. Enter the vault address from the transaction
                receipt, then accept ownership to finalize.
              </p>
              <div>
                <label className="label-text">Vault Address</label>
                <input
                  className="input-field text-sm"
                  type="text"
                  placeholder="0x... (from transaction receipt)"
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val.startsWith("0x") && val.length === 42) {
                      setDeployedVault(val as Address);
                    }
                  }}
                />
              </div>
              <button
                className="btn-primary w-full"
                disabled={!deployedVault || acceptOwnership.isPending || acceptOwnership.isConfirming}
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

          {acceptOwnership.isSuccess && deployedVault && (
            <div className="border border-ink/20 p-4">
              <p className="font-mono text-sm text-ink/60 mb-2">
                Ownership accepted. Vault is ready.
              </p>
              <button
                className="btn-secondary w-full"
                onClick={() => {
                  if (deployedVault && onVaultCreated) {
                    onVaultCreated(deployedVault);
                  }
                }}
              >
                Load Vault
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
