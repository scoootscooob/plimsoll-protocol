"use client";

import { ConnectKitButton } from "connectkit";

export function Header() {
  return (
    <header className="border-b border-gray-800 bg-gray-950/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-plimsoll-600 rounded-lg flex items-center justify-center font-bold text-sm">
              A
            </div>
            <span className="text-xl font-bold bg-gradient-to-r from-plimsoll-400 to-plimsoll-200 bg-clip-text text-transparent">
              Plimsoll
            </span>
            <span className="text-sm text-gray-500 ml-2">
              Capital Delegation
            </span>
          </div>
          <ConnectKitButton />
        </div>
      </div>
    </header>
  );
}
