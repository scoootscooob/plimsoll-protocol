/**
 * Wagmi + ConnectKit configuration for Plimsoll dApp.
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
  })
);
