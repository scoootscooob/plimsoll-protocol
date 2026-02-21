import type { Config } from "tailwindcss";

/**
 * Plimsoll Design System — "Academic Brutalism"
 *
 * 1970s MIT Physics / classified DARPA document aesthetic.
 * No gradients. No drop shadows. No rounded corners.
 *
 * Palette:
 *   paper      #FAF9F6   Warm ivory/parchment (never pure white)
 *   ink        #1A1918   Deep espresso/charcoal (never pure black)
 *   surface    #EAE8E3   Slightly darker paper for code blocks/cards
 *   terracotta #C84B31   Muted rust/red for critical alerts & accents
 */

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        paper: "#FAF9F6",
        ink: "#1A1918",
        surface: "#EAE8E3",
        terracotta: "#C84B31",
      },
      fontFamily: {
        serif: ['"Newsreader"', '"EB Garamond"', '"Times New Roman"', "serif"],
        mono: [
          '"JetBrains Mono"',
          '"IBM Plex Mono"',
          '"Courier New"',
          "monospace",
        ],
        sans: ['"Inter"', "system-ui", "sans-serif"],
      },
      keyframes: {
        SubtlePulse: {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: ".5", transform: "scale(0.8)" },
        },
      },
      animation: {
        SubtlePulse: "SubtlePulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};
export default config;
