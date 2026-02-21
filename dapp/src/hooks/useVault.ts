"use client";

/**
 * Custom hooks for interacting with PlimsollVault contracts.
 */

import { useReadContract, useWriteContract, useWaitForTransactionReceipt } from "wagmi";
import { parseEther, formatEther, type Address } from "viem";
import { PLIMSOLL_VAULT_ABI, PLIMSOLL_ATTESTATION_ABI, CONTRACTS } from "@/lib/contracts";

// ── Read Hooks ───────────────────────────────────────────────

export function useVaultBalance(vaultAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "vaultBalance",
  });
}

export function useVaultOwner(vaultAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "owner",
  });
}

export function useInitialBalance(vaultAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "initialBalance",
  });
}

export function useEmergencyLocked(vaultAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "emergencyLocked",
  });
}

export function useSessionActive(vaultAddress: Address, agentAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "isSessionActive",
    args: [agentAddress],
  });
}

export function useSessionKey(vaultAddress: Address, agentAddress: Address) {
  return useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "getSessionKey",
    args: [agentAddress],
  });
}

export function useModuleAddresses(vaultAddress: Address) {
  const velocity = useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "velocityModule",
  });
  const whitelist = useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "whitelistModule",
  });
  const drawdown = useReadContract({
    address: vaultAddress,
    abi: PLIMSOLL_VAULT_ABI,
    functionName: "drawdownModule",
  });
  return { velocity, whitelist, drawdown };
}

// ── Write Hooks ──────────────────────────────────────────────

export function useDeposit() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const deposit = (vaultAddress: Address, amountEth: string) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "deposit",
      value: parseEther(amountEth),
    });
  };

  return { deposit, hash, isPending, isConfirming, isSuccess, error };
}

export function useWithdraw() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const withdraw = (vaultAddress: Address, to: Address, amountEth: string) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "withdraw",
      args: [to, parseEther(amountEth)],
    });
  };

  return { withdraw, hash, isPending, isConfirming, isSuccess, error };
}

export function useIssueSessionKey() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const issueKey = (
    vaultAddress: Address,
    agent: Address,
    durationHours: number,
    maxSingleEth: string,
    dailyBudgetEth: string
  ) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "issueSessionKey",
      args: [
        agent,
        BigInt(Math.floor(durationHours * 3600)),
        parseEther(maxSingleEth),
        parseEther(dailyBudgetEth),
      ],
    });
  };

  return { issueKey, hash, isPending, isConfirming, isSuccess, error };
}

export function useRevokeSessionKey() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const revokeKey = (vaultAddress: Address, agent: Address) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "revokeSessionKey",
      args: [agent],
    });
  };

  return { revokeKey, hash, isPending, isConfirming, isSuccess, error };
}

export function useEmergencyLock() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const lock = (vaultAddress: Address) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "emergencyLockVault",
    });
  };

  const unlock = (vaultAddress: Address) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "emergencyUnlock",
    });
  };

  return { lock, unlock, hash, isPending, isConfirming, isSuccess, error };
}

// ── Attestation Hooks ────────────────────────────────────────

export function useAttestation(attestationAddress: Address, vaultAddress: Address) {
  return useReadContract({
    address: attestationAddress,
    abi: PLIMSOLL_ATTESTATION_ABI,
    functionName: "getAttestation",
    args: [vaultAddress],
  });
}

export function useIsAttested(attestationAddress: Address, vaultAddress: Address) {
  return useReadContract({
    address: attestationAddress,
    abi: PLIMSOLL_ATTESTATION_ABI,
    functionName: "isAttested",
    args: [vaultAddress],
  });
}
