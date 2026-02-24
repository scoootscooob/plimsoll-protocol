"use client";

/**
 * Custom hooks for interacting with the PlimsollVaultFactory contract.
 *
 * Chain-aware: automatically uses the factory address matching
 * the user's connected wallet chain (Base, Sepolia, etc.).
 */

import {
  useReadContract,
  useWriteContract,
  useWaitForTransactionReceipt,
  useChainId,
} from "wagmi";
import { parseEther, decodeEventLog, type Address } from "viem";
import { base, sepolia } from "wagmi/chains";
import { PLIMSOLL_FACTORY_ABI, PLIMSOLL_VAULT_ABI, CONTRACTS } from "@/lib/contracts";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as Address;

// ── Chain-aware factory address resolver ────────────────────

type ChainKey = keyof typeof CONTRACTS;

function getChainKey(chainId: number): ChainKey {
  if (chainId === base.id) return "base";
  if (chainId === sepolia.id) return "sepolia";
  return "base"; // default to Base
}

export function getFactoryAddress(chainId: number): Address {
  const key = getChainKey(chainId);
  return CONTRACTS[key].factory as Address;
}

export function getContractsForChain(chainId: number) {
  const key = getChainKey(chainId);
  return CONTRACTS[key];
}

// ── Hook: get current chain's factory info ──────────────────

export function useFactoryAddress() {
  const chainId = useChainId();
  const factoryAddress = getFactoryAddress(chainId);
  const deployed = factoryAddress !== ZERO_ADDRESS;
  const chainKey = getChainKey(chainId);
  return { factoryAddress, isFactoryDeployed: deployed, chainId, chainKey };
}

// ── Write: createVault ──────────────────────────────────────

export function useCreateVault() {
  const { factoryAddress } = useFactoryAddress();
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const receipt = useWaitForTransactionReceipt({ hash });

  // Parse the VaultCreated event from the tx receipt to get the vault address
  let vaultAddress: Address | null = null;
  if (receipt.data?.logs) {
    for (const log of receipt.data.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PLIMSOLL_FACTORY_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "VaultCreated") {
          vaultAddress = (decoded.args as { vault: Address }).vault;
          break;
        }
      } catch {
        // Not a VaultCreated event, skip
      }
    }
  }

  const createVault = (
    maxPerHourEth: string,
    maxSingleTxEth: string,
    maxDrawdownBps: number,
    depositEth?: string
  ) => {
    writeContract({
      address: factoryAddress,
      abi: PLIMSOLL_FACTORY_ABI,
      functionName: "createVault",
      args: [
        parseEther(maxPerHourEth),
        parseEther(maxSingleTxEth),
        BigInt(maxDrawdownBps),
      ],
      value: depositEth ? parseEther(depositEth) : BigInt(0),
    });
  };

  return {
    createVault,
    hash,
    isPending,
    isConfirming: receipt.isLoading,
    isSuccess: receipt.isSuccess,
    vaultAddress,
    error,
  };
}

// ── Write: acceptOwnership (second step after factory deploy) ──

export function useAcceptOwnership() {
  const { writeContract, data: hash, isPending, error } = useWriteContract();
  const { isLoading: isConfirming, isSuccess } = useWaitForTransactionReceipt({ hash });

  const accept = (vaultAddress: Address) => {
    writeContract({
      address: vaultAddress,
      abi: PLIMSOLL_VAULT_ABI,
      functionName: "acceptOwnership",
    });
  };

  return { accept, hash, isPending, isConfirming, isSuccess, error };
}

// ── Read: getVaultsByOwner ──────────────────────────────────

export function useOwnerVaults(ownerAddress: Address | undefined) {
  const { factoryAddress, isFactoryDeployed } = useFactoryAddress();

  return useReadContract({
    address: factoryAddress,
    abi: PLIMSOLL_FACTORY_ABI,
    functionName: "getVaultsByOwner",
    args: ownerAddress ? [ownerAddress] : undefined,
    query: {
      enabled: !!ownerAddress && isFactoryDeployed,
    },
  });
}

// ── Read: getVaultCount ─────────────────────────────────────

export function useVaultCount() {
  const { factoryAddress, isFactoryDeployed } = useFactoryAddress();

  return useReadContract({
    address: factoryAddress,
    abi: PLIMSOLL_FACTORY_ABI,
    functionName: "getVaultCount",
    query: {
      enabled: isFactoryDeployed,
    },
  });
}
