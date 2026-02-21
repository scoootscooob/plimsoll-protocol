/**
 * Wagmi + ConnectKit configuration for Aegis dApp.
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
          "https://eth-sepolia.g.alchemy.com/v2/demo"
      ),
      [mainnet.id]: http(
        process.env.NEXT_PUBLIC_MAINNET_RPC_URL ||
          "https://eth-mainnet.g.alchemy.com/v2/demo"
      ),
    },
    walletConnectProjectId:
      process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "",
    appName: "Aegis Capital Delegation",
    appDescription: "Manage AI agent vaults with on-chain physics enforcement",
    appUrl: "https://aegis.network",
  })
);
