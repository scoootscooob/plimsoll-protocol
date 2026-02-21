"use client";

import { type Address } from "viem";
import { useEmergencyLock } from "@/hooks/useVault";

interface Props {
  vaultAddress: Address;
  isLocked: boolean;
}

export function EmergencyPanel({ vaultAddress, isLocked }: Props) {
  const { lock, unlock, isPending, isConfirming, isSuccess, error } =
    useEmergencyLock();

  return (
    <div
      className={`card border ${
        isLocked ? "border-red-500/50 bg-red-950/20" : "border-yellow-500/30"
      }`}
    >
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            {isLocked ? "🔴" : "⚠️"} Emergency Controls
          </h3>
          <p className="text-sm text-gray-400 mt-1">
            {isLocked
              ? "Vault is LOCKED. All session keys and executions are frozen."
              : "Lock the vault to immediately freeze all agent activity."}
          </p>
        </div>

        {isLocked ? (
          <button
            className="btn-primary"
            disabled={isPending || isConfirming}
            onClick={() => unlock(vaultAddress)}
          >
            {isPending ? "Signing..." : isConfirming ? "Confirming..." : "Unlock Vault"}
          </button>
        ) : (
          <button
            className="btn-danger"
            disabled={isPending || isConfirming}
            onClick={() => lock(vaultAddress)}
          >
            {isPending
              ? "Signing..."
              : isConfirming
                ? "Confirming..."
                : "EMERGENCY LOCK"}
          </button>
        )}
      </div>

      {isSuccess && (
        <p className="text-sm text-green-400 mt-2">
          {isLocked ? "Vault unlocked!" : "Vault locked!"}
        </p>
      )}
      {error && (
        <p className="text-sm text-red-400 mt-2">
          {(error as Error).message?.slice(0, 150)}
        </p>
      )}
    </div>
  );
}
