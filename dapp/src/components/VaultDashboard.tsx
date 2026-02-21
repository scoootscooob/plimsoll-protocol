"use client";

import { useState } from "react";
import { useAccount } from "wagmi";
import { formatEther, type Address } from "viem";
import {
  useVaultBalance,
  useVaultOwner,
  useInitialBalance,
  useEmergencyLocked,
  useModuleAddresses,
} from "@/hooks/useVault";
import { SessionKeyManager } from "./SessionKeyManager";
import { DepositWithdraw } from "./DepositWithdraw";
import { EmergencyPanel } from "./EmergencyPanel";
import { ModuleStatus } from "./ModuleStatus";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

export function VaultDashboard() {
  const { address: userAddress, isConnected } = useAccount();
  const [vaultAddress, setVaultAddress] = useState<string>("");
  const [activeVault, setActiveVault] = useState<Address | null>(null);

  const balance = useVaultBalance(activeVault || ZERO_ADDRESS);
  const owner = useVaultOwner(activeVault || ZERO_ADDRESS);
  const initialBal = useInitialBalance(activeVault || ZERO_ADDRESS);
  const locked = useEmergencyLocked(activeVault || ZERO_ADDRESS);
  const modules = useModuleAddresses(activeVault || ZERO_ADDRESS);

  const isOwner =
    userAddress &&
    owner.data &&
    userAddress.toLowerCase() === (owner.data as string).toLowerCase();

  if (!isConnected) {
    return (
      <div className="text-center py-20">
        <h2 className="text-3xl font-bold mb-4 bg-gradient-to-r from-plimsoll-400 to-plimsoll-200 bg-clip-text text-transparent">
          Plimsoll Capital Delegation
        </h2>
        <p className="text-gray-400 text-lg mb-8 max-w-md mx-auto">
          Manage AI agent vaults with deterministic, on-chain physics
          enforcement. Connect your wallet to get started.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-3xl mx-auto mt-12">
          <div className="card text-center">
            <div className="text-3xl mb-3">🛡️</div>
            <h3 className="font-semibold mb-2">Physics Modules</h3>
            <p className="text-sm text-gray-400">
              Velocity limits, whitelist, and drawdown guards enforce math at
              the EVM level.
            </p>
          </div>
          <div className="card text-center">
            <div className="text-3xl mb-3">🔑</div>
            <h3 className="font-semibold mb-2">Session Keys</h3>
            <p className="text-sm text-gray-400">
              Grant AI agents scoped, time-limited access with per-tx and daily
              budget caps.
            </p>
          </div>
          <div className="card text-center">
            <div className="text-3xl mb-3">📊</div>
            <h3 className="font-semibold mb-2">PoBR Attestation</h3>
            <p className="text-sm text-gray-400">
              On-chain proof of bounded risk for DeFi protocol integration.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Vault Selector */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Vault Address</h2>
        <div className="flex gap-3">
          <input
            type="text"
            value={vaultAddress}
            onChange={(e) => setVaultAddress(e.target.value)}
            placeholder="0x... Enter your PlimsollVault contract address"
            className="input-field font-mono text-sm"
          />
          <button
            className="btn-primary whitespace-nowrap"
            onClick={() => {
              if (vaultAddress.startsWith("0x") && vaultAddress.length === 42) {
                setActiveVault(vaultAddress as Address);
              }
            }}
          >
            Load Vault
          </button>
        </div>
      </div>

      {activeVault && (
        <>
          {/* Stats Row */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card">
              <div className="stat-label">Vault Balance</div>
              <div className="stat-value">
                {balance.data
                  ? `${parseFloat(formatEther(balance.data as bigint)).toFixed(4)} ETH`
                  : "Loading..."}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Initial Deposit</div>
              <div className="stat-value">
                {initialBal.data
                  ? `${parseFloat(formatEther(initialBal.data as bigint)).toFixed(4)} ETH`
                  : "0 ETH"}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Status</div>
              <div className="mt-1">
                {locked.data ? (
                  <span className="badge-locked">EMERGENCY LOCKED</span>
                ) : (
                  <span className="badge-active">ACTIVE</span>
                )}
              </div>
            </div>
            <div className="card">
              <div className="stat-label">Your Role</div>
              <div className="mt-1">
                {isOwner ? (
                  <span className="badge-active">OWNER</span>
                ) : (
                  <span className="badge-inactive">VIEWER</span>
                )}
              </div>
            </div>
          </div>

          {/* Module Status */}
          <ModuleStatus
            velocityAddr={modules.velocity.data as Address | undefined}
            whitelistAddr={modules.whitelist.data as Address | undefined}
            drawdownAddr={modules.drawdown.data as Address | undefined}
          />

          {/* Owner Controls */}
          {isOwner && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <DepositWithdraw vaultAddress={activeVault} />
              <SessionKeyManager vaultAddress={activeVault} />
            </div>
          )}

          {/* Emergency Panel */}
          {isOwner && (
            <EmergencyPanel
              vaultAddress={activeVault}
              isLocked={!!locked.data}
            />
          )}
        </>
      )}
    </div>
  );
}
