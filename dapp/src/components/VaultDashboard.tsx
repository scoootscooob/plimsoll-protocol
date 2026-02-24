"use client";

import { useState, useEffect } from "react";
import { useAccount } from "wagmi";
import { formatEther, type Address } from "viem";
import {
  useVaultBalance,
  useVaultOwner,
  useInitialBalance,
  useEmergencyLocked,
  useModuleAddresses,
} from "@/hooks/useVault";
import { useOwnerVaults } from "@/hooks/useFactory";
import { SessionKeyManager } from "./SessionKeyManager";
import { DepositWithdraw } from "./DepositWithdraw";
import { EmergencyPanel } from "./EmergencyPanel";
import { ModuleStatus } from "./ModuleStatus";
import { DeployVault } from "./DeployVault";
import { QuickDeploy } from "./QuickDeploy";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

export function VaultDashboard() {
  const { address: userAddress, isConnected, isReconnecting } = useAccount();
  const [vaultAddress, setVaultAddress] = useState<string>("");
  const [activeVault, setActiveVault] = useState<Address | null>(null);
  // Prevent hydration flash: wait for client-side mount before deciding connected state
  const [hasMounted, setHasMounted] = useState(false);
  useEffect(() => { setHasMounted(true); }, []);

  const ownerVaults = useOwnerVaults(userAddress);

  const balance = useVaultBalance(activeVault || ZERO_ADDRESS);
  const owner = useVaultOwner(activeVault || ZERO_ADDRESS);
  const initialBal = useInitialBalance(activeVault || ZERO_ADDRESS);
  const locked = useEmergencyLocked(activeVault || ZERO_ADDRESS);
  const modules = useModuleAddresses(activeVault || ZERO_ADDRESS);

  const isOwner =
    userAddress &&
    owner.data &&
    userAddress.toLowerCase() === (owner.data as string).toLowerCase();

  // While wagmi is still rehydrating the connection, show a loading state
  // instead of flashing the disconnected view
  if (!hasMounted || isReconnecting) {
    return (
      <div className="text-center py-20">
        <div className="inline-block w-6 h-6 border-2 border-ink/20 border-t-terracotta rounded-full animate-spin" />
        <p className="font-mono text-xs text-ink/40 mt-4 uppercase tracking-widest">
          Reconnecting wallet...
        </p>
      </div>
    );
  }

  if (!isConnected) {
    return (
      <div className="text-center py-20">
        <h2 className="font-serif text-4xl mb-4 text-ink">
          Capital Delegation
        </h2>
        <p className="font-mono text-sm text-ink/60 mb-8 max-w-md mx-auto leading-relaxed">
          Manage AI agent vaults with deterministic, on-chain physics
          enforcement. Connect your wallet to get started.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-0 max-w-3xl mx-auto mt-12 border-t border-l border-ink/20">
          <div className="border-r border-b border-ink/20 p-8 text-center">
            <h3 className="font-mono text-xs text-terracotta mb-4 tracking-widest uppercase">[ Module_01 ]</h3>
            <h4 className="font-serif text-lg mb-2">Physics Modules</h4>
            <p className="font-mono text-xs text-ink/60 leading-relaxed">
              Velocity limits, whitelist, and drawdown guards enforce math at
              the EVM level.
            </p>
          </div>
          <div className="border-r border-b border-ink/20 p-8 text-center">
            <h3 className="font-mono text-xs text-terracotta mb-4 tracking-widest uppercase">[ Module_02 ]</h3>
            <h4 className="font-serif text-lg mb-2">Session Keys</h4>
            <p className="font-mono text-xs text-ink/60 leading-relaxed">
              Grant AI agents scoped, time-limited access with per-tx and daily
              budget caps.
            </p>
          </div>
          <div className="border-r border-b border-ink/20 p-8 text-center">
            <h3 className="font-mono text-xs text-terracotta mb-4 tracking-widest uppercase">[ Module_03 ]</h3>
            <h4 className="font-serif text-lg mb-2">PoBR Attestation</h4>
            <p className="font-mono text-xs text-ink/60 leading-relaxed">
              On-chain proof of bounded risk for DeFi protocol integration.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const vaultList = (ownerVaults.data as Address[] | undefined) || [];
  const isLoadingVaults = ownerVaults.isLoading;

  // ── First-time user: show QuickDeploy ───────────────────────
  if (!isLoadingVaults && vaultList.length === 0 && !activeVault) {
    return (
      <QuickDeploy
        onComplete={(addr) => {
          setActiveVault(addr);
          ownerVaults.refetch();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Deploy New Vault (advanced — for users who already have vaults) */}
      <DeployVault
        onVaultCreated={(addr) => {
          setActiveVault(addr);
          ownerVaults.refetch();
        }}
      />

      {/* Your Vaults (from factory registry) */}
      {vaultList.length > 0 && (
        <div className="card">
          <h3 className="font-mono text-xs text-ink/60 mb-4 tracking-widest uppercase">
            Your Vaults
          </h3>
          <div className="space-y-2">
            {vaultList.map((addr, i) => (
              <button
                key={addr}
                className={`w-full text-left p-3 border font-mono text-sm transition-colors duration-150 ${
                  activeVault === addr
                    ? "border-ink bg-surface"
                    : "border-ink/20 hover:border-ink/40"
                }`}
                onClick={() => setActiveVault(addr)}
              >
                <span className="font-mono text-[10px] text-terracotta tracking-widest uppercase">
                  [ Vault_{String(i).padStart(2, "0")} ]
                </span>
                <span className="block mt-1 truncate">{addr}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Manual Vault Address Input */}
      <div className="card">
        <h2 className="font-mono text-xs text-ink/60 mb-4 tracking-widest uppercase">
          {vaultList.length > 0 ? "Or Enter Address Manually" : "Vault Address"}
        </h2>
        <div className="flex gap-3">
          <input
            type="text"
            value={vaultAddress}
            onChange={(e) => setVaultAddress(e.target.value)}
            placeholder="0x... Enter your PlimsollVault contract address"
            className="input-field text-sm"
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
          <div className="grid grid-cols-1 md:grid-cols-4 gap-0 border-t border-l border-ink/20">
            <div className="border-r border-b border-ink/20 p-6">
              <div className="stat-label">Vault Balance</div>
              <div className="stat-value mt-2">
                {balance.data
                  ? `${parseFloat(formatEther(balance.data as bigint)).toFixed(4)} ETH`
                  : "Loading..."}
              </div>
            </div>
            <div className="border-r border-b border-ink/20 p-6">
              <div className="stat-label">Initial Deposit</div>
              <div className="stat-value mt-2">
                {initialBal.data
                  ? `${parseFloat(formatEther(initialBal.data as bigint)).toFixed(4)} ETH`
                  : "0 ETH"}
              </div>
            </div>
            <div className="border-r border-b border-ink/20 p-6">
              <div className="stat-label">Status</div>
              <div className="mt-2">
                {locked.data ? (
                  <span className="badge-locked">EMERGENCY LOCKED</span>
                ) : (
                  <span className="badge-active">ACTIVE</span>
                )}
              </div>
            </div>
            <div className="border-r border-b border-ink/20 p-6">
              <div className="stat-label">Your Role</div>
              <div className="mt-2">
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
