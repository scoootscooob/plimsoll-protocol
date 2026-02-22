/**
 * Wagmi + ConnectKit configuration for Plimsoll dApp.
 *
 * Family wallet is disabled — its GraphQL signing backend consistently
 * returns "Signing request not found" errors when sending transactions.
 * This is a known issue with Family's infrastructure, not our contracts.
 * Users can connect via MetaMask, Coinbase Wallet, or WalletConnect.
 */

import { getDefaultConfig } from "connectkit";
import { createConfig, http } from "wagmi";
import { sepolia, mainnet } from "wagmi/chains";

export const config = createConfig(
  getDefaultConfig({
    chains: [sepolia, mainnet],
    transports: {
      [sepolia.id]: http(
        process.env.NEXT_PUBLIC_SEPOLIA_RPC_URL ||
          "https://rpc.sepolia.org"
      ),
      [mainnet.id]: http(
        process.env.NEXT_PUBLIC_MAINNET_RPC_URL ||
          "https://cloudflare-eth.com"
      ),
    },
    walletConnectProjectId:
      process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "",
    appName: "Plimsoll Capital Delegation",
    appDescription: "Manage AI agent vaults with on-chain physics enforcement",
    appUrl: "https://plimsoll.network",
    enableFamily: false,
  })
);
