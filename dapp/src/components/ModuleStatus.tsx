"use client";

import { type Address } from "viem";

const ZERO = "0x0000000000000000000000000000000000000000";

interface Props {
  velocityAddr?: Address;
  whitelistAddr?: Address;
  drawdownAddr?: Address;
}

export function ModuleStatus({
  velocityAddr,
  whitelistAddr,
  drawdownAddr,
}: Props) {
  const modules = [
    {
      name: "Velocity Limit",
      description: "Enforces maximum spend rate per rolling hour",
      icon: "⚡",
      address: velocityAddr,
    },
    {
      name: "Target Whitelist",
      description: "Only allows pre-approved destination contracts",
      icon: "🎯",
      address: whitelistAddr,
    },
    {
      name: "Drawdown Guard",
      description: "Prevents portfolio drawdown beyond configured floor",
      icon: "🛡️",
      address: drawdownAddr,
    },
  ];

  return (
    <div className="card">
      <h3 className="text-lg font-semibold mb-4">Physics Modules</h3>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {modules.map((mod) => {
          const isActive = mod.address && mod.address !== ZERO;
          return (
            <div
              key={mod.name}
              className={`rounded-lg p-4 border ${
                isActive
                  ? "border-green-500/30 bg-green-950/10"
                  : "border-gray-700/50 bg-gray-800/30"
              }`}
            >
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xl">{mod.icon}</span>
                <span className="font-medium">{mod.name}</span>
                {isActive ? (
                  <span className="badge-active ml-auto">ON</span>
                ) : (
                  <span className="badge-inactive ml-auto">OFF</span>
                )}
              </div>
              <p className="text-xs text-gray-400">{mod.description}</p>
              {isActive && (
                <p className="text-xs font-mono text-gray-500 mt-2 truncate">
                  {mod.address}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
